#include "daemon/notification.h"
#include "ipc/uds.h"
#include "config.h"
#include <stdexcept>
#include <syslog.h>
#include <pwd.h>
#include <utmp.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <set>
#include <string>
#include <vector>
#include <limits>


using namespace hotkey_manager;

static std::string get_process_env(pid_t pid, std::string env_var) {
    char path[256];
    std::string result;
    FILE* fp;
    
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    fp = fopen(path, "r");
    if (!fp) return "";
    char env_buffer[4096];
    size_t len = fread(env_buffer, 1, sizeof(env_buffer)-1, fp);
    fclose(fp);
    if (len == 0) return "";
    env_buffer[len] = '\0';
    char* start = env_buffer;
    while (*start) {
        if (strncmp(start, env_var.c_str(), env_var.length()) == 0 && start[env_var.length()] == '=') {
            result = std::string(start + env_var.length() + 1);
            break;
        }
        start += strlen(start) + 1;
    }
    
    return result;
}

void NotificationManager::closeNotification(DBusConnection* conn, dbus_uint32_t replaceId) {
    DBusMessage* msg = dbus_message_new_method_call(
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
        "CloseNotification"
    );
    if (!msg) {
        throw std::runtime_error("Failed to create D-Bus message to close notification");
    }
    dbus_message_append_args(msg, DBUS_TYPE_UINT32, &replaceId, DBUS_TYPE_INVALID);
    if (!dbus_connection_send(conn, msg, NULL)) {
        dbus_message_unref(msg);
        throw std::runtime_error("Failed to send D-Bus message to close notification");
    }
    dbus_connection_flush(conn);
    dbus_message_unref(msg);
}

NotificationManager::NotificationManager(const std::string& appName, const std::string& iconName)
: appName(nullptr)
, iconName(nullptr)
, notifications() {
    this->appName = strdup(appName.c_str());
    this->iconName = strdup(iconName.c_str());
    if (!this->appName || !this->iconName) {
        syslog(LOG_WARNING, "Failed to allocate memory for appName or iconName");
        throw std::runtime_error("Failed to allocate memory for appName or iconName");
    }

}

NotificationManager::~NotificationManager() {
    if (appName)
        free(appName);
    if (iconName)
        free(iconName);

}

int64_t NotificationManager::sendNotification(const std::string& summary, const std::string& body, int timeoutMs) {
    if (timeoutMs <= 0) {
        throw std::invalid_argument("timeoutMs must be greater than 0");
    }
    struct ChildInfo {
        pid_t pid;
        int readFd;
        std::pair<std::string, std::string> key;
        uid_t uid;
        gid_t gid;
    };
    struct utmp *ut;
    struct passwd *pw;
    std::set<std::pair<std::string, std::string>> processed; // pair of (username, dbusAddress)
    std::vector<ChildInfo> children;
    setutent();

    while ((ut = getutent()) != NULL) {
        if (ut->ut_type != USER_PROCESS || ut->ut_pid <= 0 || ut->ut_user[0] == '\0')
            continue;

        std::string dbusAddress = get_process_env(ut->ut_pid, "DBUS_SESSION_BUS_ADDRESS");
        if (dbusAddress.empty())
            continue;

        pw = getpwnam(ut->ut_user);
        if (!pw) {
            syslog(LOG_WARNING, "Failed to get passwd entry for user: %s", ut->ut_user);
            continue;
        }
        std::string runtimeDir;
        runtimeDir = std::string("/run/user/") + std::to_string(pw->pw_uid);
        if (processed.count({ut->ut_user, dbusAddress}) > 0)
            continue; // Skip if this user and DBUS address combination has already been processed

        dbus_uint32_t replaceId = 0;
        std::pair<std::string, std::string> key{ut->ut_user, dbusAddress};
        auto existing = notifications.find(key);
        if (existing != notifications.end()) {
            replaceId = existing->second.notificationId;
        }

        int pipeFds[2];
        if (pipe(pipeFds) == -1) {
            syslog(LOG_WARNING, "Failed to create pipe for notification: %s", std::strerror(errno));
            continue;
        }

        pid_t pid = fork();
        if (pid != 0) {
            // Parent process
            processed.emplace(ut->ut_user, dbusAddress);
            close(pipeFds[1]);
            if (pid < 0) {
                close(pipeFds[0]);
                syslog(LOG_WARNING, "Failed to fork notification process: %s", std::strerror(errno));
                continue;
            }
            children.push_back(ChildInfo{pid, pipeFds[0], key, pw->pw_uid, pw->pw_gid});
            continue;
        }

        // Child process
        close(pipeFds[0]);
        setenv("DBUS_SESSION_BUS_ADDRESS", dbusAddress.c_str(), 1);
        if (!runtimeDir.empty())
            setenv("XDG_RUNTIME_DIR", runtimeDir.c_str(), 1);
        if (setgid(pw->pw_gid) == -1) {
            syslog(LOG_WARNING, "Failed to setgid for user: %s", ut->ut_user);
            close(pipeFds[1]);
            _exit(1);
        }
        if (setuid(pw->pw_uid) == -1) {
            syslog(LOG_WARNING, "Failed to setuid for user: %s", ut->ut_user);
            close(pipeFds[1]);
            _exit(1);
        }

        // Reopen syslog for the child process with the new user identity
        openlog("hotkey-manager-notification", LOG_PID | LOG_CONS, LOG_DAEMON);

        DBusConnection *conn;
        DBusError err;

        dbus_error_init(&err);
        conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
        if (dbus_error_is_set(&err)) {
            std::string errorMsg = "Failed to connect to D-Bus session bus: " + std::string(err.message);
            dbus_error_free(&err);
            syslog(LOG_WARNING, "%s", errorMsg.c_str());
            close(pipeFds[1]);
            _exit(1);
        }
        DBusMessage* msg = dbus_message_new_method_call(
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
            "Notify"
        );
        if (!msg) {
            syslog(LOG_WARNING, "Failed to create D-Bus message");
            close(pipeFds[1]);
            _exit(1);
        }

        // Send notification
        char* summaryCStr = strdup(summary.c_str());
        char* bodyCStr = strdup(body.c_str());
        if (!summaryCStr || !bodyCStr) {
            if (summaryCStr) free(summaryCStr);
            if (bodyCStr) free(bodyCStr);
            dbus_message_unref(msg);
            syslog(LOG_WARNING, "Failed to allocate memory for summary or body");
            close(pipeFds[1]);
            _exit(1);
        }

        DBusMessageIter iter, subIter, dictIter;
        dbus_message_iter_init_append(msg, &iter);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &appName);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &replaceId);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &iconName);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &summaryCStr);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &bodyCStr);
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &subIter);
        dbus_message_iter_close_container(&iter, &subIter);
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dictIter);
        dbus_message_iter_close_container(&iter, &dictIter);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &timeoutMs);

        // Get notification ID (always request a reply to refresh ids on replace)
        DBusPendingCall* pending;
        if (!dbus_connection_send_with_reply(conn, msg, &pending, DBUS_REPLY_TIMEOUT_MS)) {
            dbus_message_unref(msg);
            syslog(LOG_WARNING, "Failed to send D-Bus message");
            close(pipeFds[1]);
            _exit(1);
        }
        dbus_connection_flush(conn);
        dbus_message_unref(msg);

        dbus_pending_call_block(pending);
        DBusMessage* reply = dbus_pending_call_steal_reply(pending);
        dbus_pending_call_unref(pending);
        if (!reply) {
            syslog(LOG_WARNING, "Failed to receive D-Bus reply");
            close(pipeFds[1]);
            _exit(1);
        }
        if (!dbus_message_get_args(reply, &err, DBUS_TYPE_UINT32, &replaceId, DBUS_TYPE_INVALID)) {
            std::string errorMsg = "Failed to parse D-Bus reply: " + std::string(err.message);
            dbus_error_free(&err);
            dbus_message_unref(reply);
            syslog(LOG_WARNING, "%s", errorMsg.c_str());
            close(pipeFds[1]);
            _exit(1);
        }
        dbus_message_unref(reply);

        free(summaryCStr);
        free(bodyCStr);

        ssize_t written = write(pipeFds[1], &replaceId, sizeof(replaceId));
        if (written != static_cast<ssize_t>(sizeof(replaceId))) {
            syslog(LOG_WARNING, "Failed to write notification id to parent process");
        }
        close(pipeFds[1]);
        _exit(0);
    }

    endutent();

    int64_t now = getTimestampMs();
    for (const auto& child : children) {
        dbus_uint32_t receivedId = 0;
        ssize_t readBytes = read(child.readFd, &receivedId, sizeof(receivedId));
        close(child.readFd);
        int status = 0;
        if (waitpid(child.pid, &status, 0) == -1) {
            syslog(LOG_WARNING, "Failed to wait for notification process: %s", std::strerror(errno));
        }
        if (readBytes != static_cast<ssize_t>(sizeof(receivedId)) || receivedId == 0) {
            continue;
        }
        NotificationEntry entry;
        entry.notificationId = receivedId;
        entry.expireAtMs = now + static_cast<int64_t>(timeoutMs);
        entry.uid = child.uid;
        entry.gid = child.gid;
        notifications[child.key] = entry;
    }
    return now + static_cast<int64_t>(timeoutMs); // Return the next expiration time for efficient scheduling
}

int64_t NotificationManager::clearExpired() {
    int64_t next = std::numeric_limits<int64_t>::max();
    if (notifications.empty()) {
        return next;
    }
    int64_t now = getTimestampMs();
    for (auto it = notifications.begin(); it != notifications.end();) {
        if (it->second.notificationId == 0) {
            ++it;
            continue;
        }
        if (it->second.expireAtMs > now) {
            next = std::min(next, it->second.expireAtMs);
            ++it;
            continue;
        }

        const auto& key = it->first;
        const auto& entry = it->second;
        pid_t pid = fork();
        if (pid == -1) {
            syslog(LOG_WARNING, "Failed to fork for notification close: %s", std::strerror(errno));
            ++it;
            continue;
        }

        if (pid == 0) {
            setenv("DBUS_SESSION_BUS_ADDRESS", key.second.c_str(), 1);
            std::string runtimeDir = std::string("/run/user/") + std::to_string(entry.uid);
            setenv("XDG_RUNTIME_DIR", runtimeDir.c_str(), 1);
            if (setgid(entry.gid) == -1 || setuid(entry.uid) == -1) {
                syslog(LOG_WARNING, "Failed to setuid/setgid for notification close: %s", std::strerror(errno));
                _exit(1);
            }

            openlog("hotkey-manager-notification", LOG_PID | LOG_CONS, LOG_DAEMON);

            DBusError err;
            dbus_error_init(&err);
            DBusConnection* conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
            if (dbus_error_is_set(&err)) {
                dbus_error_free(&err);
                syslog(LOG_WARNING, "Failed to connect to D-Bus session bus for notification close: %s", err.message);
                _exit(1);
            }

            try {
                closeNotification(conn, entry.notificationId);
            } catch (const std::exception& e) {
                syslog(LOG_WARNING, "Failed to close notification with id %u for user %s, detailed: %s", entry.notificationId, key.first.c_str(), e.what());
                _exit(1);
            }

            _exit(0);
        }

        int status = 0;
        if (waitpid(pid, &status, 0) == -1) {
            syslog(LOG_WARNING, "Failed to wait for close process: %s", std::strerror(errno));
            ++it;
            next = std::min(next, entry.expireAtMs);
            continue;
        }

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            it = notifications.erase(it);
        } else {
            ++it;
            next = std::min(next, entry.expireAtMs);
            syslog(LOG_WARNING, "Close process for notification id %u did not exit successfully", entry.notificationId);
        }
    }
    return next;
}
