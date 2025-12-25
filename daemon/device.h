#ifndef DEAMON_DEVICE_H
#define DEAMON_DEVICE_H

#include "daemon/event.h"
#include <libevdev-1.0/libevdev/libevdev.h>
#include <libevdev-1.0/libevdev/libevdev-uinput.h>
#include <string>
#include <unordered_map>

namespace hotkey_manager {

class Device {
    struct libevdev* dev;
    struct libevdev_uinput* uidev;
    std::unordered_map<key_t, key_t> keyBindings;
    int fd;
public:
    explicit Device(const std::string& file, bool grab = false);
    ~Device();
    static std::string autoDetectDeviceFile();
    Event* next() const;
    void passThroughEvent(const Event& ev) const;
    bool isGrabbed() const;
    void addKeyBinding(key_t from, key_t to);
    void addKeyBinding(const std::string& from, const std::string& to);
};

} // namespace hotkey_manager

#endif // DEAMON_DEVICE_H
