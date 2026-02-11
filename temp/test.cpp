#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <utmp.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>
#include <dbus/dbus.h>
#include <set>
#include <string>


void send_and_close_notification() {
    DBusConnection *conn;
    DBusError err;
    DBusMessage *msg;
    DBusMessageIter iter, dict_iter;
    dbus_uint32_t serial = 0;
    dbus_uint32_t replace_id = 0;
    dbus_int32_t timeout = -1; // -1 表示使用系统默认超时
    char *app_name = "HotkeyService";
    char *icon = "input-gaming"; // 图标名
    char *summary = "游戏模式";
    char *body = "已开启";
    char *actions[] = {NULL};

    dbus_error_init(&err);

    // 1. 连接到 Session Bus
    conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (dbus_error_is_set(&err)) {
        fprintf(stderr, "Connection Error (%s)\n", err.message);
        dbus_error_free(&err);
        return;
    }

    // 2. 创建 Notify 方法调用
    msg = dbus_message_new_method_call(
        "org.freedesktop.Notifications",      // 目标服务
        "/org/freedesktop/Notifications",     // 对象路径
        "org.freedesktop.Notifications",      // 接口
        "Notify"                              // 方法名
    );

    // 3. 填充参数
    dbus_message_iter_init_append(msg, &iter);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &app_name);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &replace_id);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &icon);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &summary);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &body);

    // 参数：Actions (as) - 空数组
    DBusMessageIter sub_iter;
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &sub_iter);
    dbus_message_iter_close_container(&iter, &sub_iter);

    // 参数：Hints (a{sv}) - 简单起见发送一个空的 dict
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict_iter);
    dbus_message_iter_close_container(&iter, &dict_iter);

    dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &timeout);

    // 4. 发送并等待回复以获取 ID
    DBusPendingCall *pending;
    if (!dbus_connection_send_with_reply(conn, msg, &pending, -1)) {
        return;
    }
    dbus_connection_flush(conn);
    dbus_message_unref(msg);

    dbus_pending_call_block(pending);
    DBusMessage *reply = dbus_pending_call_steal_reply(pending);
    dbus_uint32_t notification_id = 0;
    dbus_message_get_args(reply, &err, DBUS_TYPE_UINT32, &notification_id, DBUS_TYPE_INVALID);
    dbus_message_unref(reply);
    dbus_pending_call_unref(pending);

    printf("Notification sent, ID: %u\n", notification_id);

    // 5. 阻塞等待（模拟你的逻辑）
    printf("Waiting 5 seconds before closing...\n");
    sleep(5);

    // 6. 构造 CloseNotification 调用
    msg = dbus_message_new_method_call(
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
        "CloseNotification"
    );
    dbus_message_append_args(msg, DBUS_TYPE_UINT32, &notification_id, DBUS_TYPE_INVALID);
    dbus_connection_send(conn, msg, &serial);
    dbus_connection_flush(conn);
    dbus_message_unref(msg);

    printf("Notification closed.\n");
}


const char* get_process_env(pid_t pid, const char* env_var) {
    char path[256];
    char* result = NULL;
    FILE* fp;
    
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    fp = fopen(path, "r");
    if (!fp) return NULL;
    
    // 读取环境变量
    char env_buffer[4096];
    size_t len = fread(env_buffer, 1, sizeof(env_buffer)-1, fp);
    fclose(fp);
    
    if (len == 0) return NULL;
    env_buffer[len] = '\0';
    
    // 解析环境变量
    char* start = env_buffer;
    while (*start) {
        if (strncmp(start, env_var, strlen(env_var)) == 0 && start[strlen(env_var)] == '=') {
            result = strdup(start + strlen(env_var) + 1);
            break;
        }
        start += strlen(start) + 1;
    }
    
    return result;
}

int main() {
    struct utmp *ut;
    struct passwd *pw;
    std::set<std::string> processedUsers;
    int cnt = 0;
    setutent(); // 将文件指针移动到文件开头

    while ((ut = getutent()) != NULL) {
        const char* dbusAddress = get_process_env(ut->ut_pid, "DBUS_SESSION_BUS_ADDRESS");
        if (!dbusAddress)
            continue;
        if (processedUsers.count(ut->ut_user) > 0)
            continue; // 已处理过该用户，跳过
        pid_t pid = fork();
        if (pid != 0) {
            // 父进程继续循环
            printf("Found user: %s, PID: %d, DBUS_SESSION_BUS_ADDRESS: %s\n", ut->ut_user, ut->ut_pid, dbusAddress);
            processedUsers.insert(ut->ut_user);
            cnt++;
            continue;
        }
        setenv("DBUS_SESSION_BUS_ADDRESS", dbusAddress, 1);
        pw = getpwnam(ut->ut_user);
        if (!pw)
            return 1; // 无法获取用户信息，退出子进程
        setgid(pw->pw_gid);
        setuid(pw->pw_uid);
        send_and_close_notification();
        return 0; // 子进程完成任务后退出
    }
    printf("Total entries: %d\n", cnt);

    endutent(); // 关闭文件
    return 0;
}