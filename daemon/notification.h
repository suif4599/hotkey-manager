#ifndef DAEMON_NOTIFICATION_H
#define DAEMON_NOTIFICATION_H

#include "dbus/dbus.h"
#include <string>
#include <utility>
#include <map>
#include <cstdint>

namespace hotkey_manager {


class NotificationManager {
    struct NotificationEntry {
        dbus_uint32_t notificationId;
        int64_t expireAtMs;
        uid_t uid;
        gid_t gid;
    };
    char* appName;
    char* iconName;
    // (username, dbusAddress) -> notification state
    std::map<std::pair<std::string, std::string>, NotificationEntry> notifications;
    void closeNotification(DBusConnection* conn, dbus_uint32_t notificationId);
public:
    NotificationManager(const std::string& appName, const std::string& iconName);
    ~NotificationManager();
    NotificationManager(const NotificationManager&) = delete;
    NotificationManager& operator=(const NotificationManager&) = delete;
    NotificationManager(NotificationManager&&) = delete;
    NotificationManager& operator=(NotificationManager&&) = delete;

    int64_t sendNotification(const std::string& summary, const std::string& body, int timeoutMs = 1000); // timeoutMs > 0
    int64_t clearExpired();
};


}


#endif // DAEMON_NOTIFICATION_H
