#ifndef DEAMON_EVENT_H
#define DEAMON_EVENT_H

#include <libevdev-1.0/libevdev/libevdev.h>
#include <iostream>

namespace hotkey_manager {

class Event {
protected:
    key_t key;
    int type; // 1: Press, 2: Release, 3: Repeat
public:
    explicit Event(key_t k, int t): key(k), type(t) {}
    explicit Event(const Event& other): key(other.key), type(other.type) {}
    virtual ~Event() = default;
    key_t get_key() const { return key; }
    int get_type() const { return type; }
    friend std::ostream& operator<<(std::ostream& os, const Event& ev);
};

class PressEvent : public Event {
public:
    explicit PressEvent(key_t k): Event(k, 1) {}
};

class ReleaseEvent : public Event {
public:
    explicit ReleaseEvent(key_t k): Event(k, 2) {}
};

class RepeatEvent : public Event {
public:
    explicit RepeatEvent(key_t k): Event(k, 3) {}
};

} // namespace hotkey_manager

#endif // DEAMON_EVENT_H
