#ifndef IPC_EVENT_H
#define IPC_EVENT_H

#include <sys/epoll.h>
#include <utility>

namespace hotkey_manager {

class EventManager {
    int epollFd;
    struct epoll_event events[64];
    static constexpr int maxEvents = sizeof(events) / sizeof(events[0]);
public:
    EventManager();
    ~EventManager();
    EventManager(const EventManager&) = delete;
    EventManager& operator=(const EventManager&) = delete;
    EventManager(EventManager&&) = delete;
    EventManager& operator=(EventManager&&) = delete;
    void addFd(int fd, uint32_t events = EPOLLIN) const;
    void deleteFd(int fd) const;
    std::pair<struct epoll_event*, int> wait(int timeoutMs = -1);
};

} // namespace hotkey_manager

#endif // IPC_EVENT_H
