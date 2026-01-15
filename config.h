#ifndef CONFIG_H
#define CONFIG_H

// This config file won't work, leaving it here in case the IDE complains

#define BACK_LOG 100
#define MAX_CONNECTIONS_FOR_ONE_PROCESS 5
#define RECEIVER_CHECK_RESPONSE_INTERVAL_MS 10
#define KEEP_ALIVE_TIME (5 * 60 * 1000)
#define CONFIG_FILE_PATH "/usr/local/etc/hotkey-manager-config.json"
#define EPOLL_TIMEOUT_MS 1000
#define DEFAULT_SOCKET_NAME "hotkey-manager-ipc"

#endif // CONFIG_H
