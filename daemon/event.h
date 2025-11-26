#ifndef DEAMON_EVENT_H
#define DEAMON_EVENT_H

#include <libevdev-1.0/libevdev/libevdev.h>
#include <iostream>

namespace hotkey_manager {

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
