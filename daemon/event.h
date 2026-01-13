#ifndef DEAMON_EVENT_H
#define DEAMON_EVENT_H

#include <libevdev-1.0/libevdev/libevdev.h>
#include <iostream>
#include <sys/epoll.h>

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

class Event {
protected:
    key_t key;
public:
    explicit Event(key_t k): key(k) {}
    virtual ~Event() = default;
    key_t get_key() const { return key; }
    virtual int get_type() const = 0;
    friend std::ostream& operator<<(std::ostream& os, const Event& ev);
};

class PressEvent : public Event {
public:
    explicit PressEvent(key_t k): Event(k) {}
    int get_type() const override { return 1; }
};

class ReleaseEvent : public Event {
public:
    explicit ReleaseEvent(key_t k): Event(k) {}
    int get_type() const override { return 2; }
};

class RepeatEvent : public Event {
public:
    explicit RepeatEvent(key_t k): Event(k) {}
    int get_type() const override { return 3; }
};

} // namespace hotkey_manager

#endif // DEAMON_EVENT_H
