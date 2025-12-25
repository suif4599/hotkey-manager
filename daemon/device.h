#ifndef DEAMON_DEVICE_H
#define DEAMON_DEVICE_H

#include "daemon/event.h"
#include <libevdev-1.0/libevdev/libevdev.h>
#include <libevdev-1.0/libevdev/libevdev-uinput.h>
#include <string>

namespace hotkey_manager {

class Device {
    struct libevdev* dev;
    struct libevdev_uinput* uidev;
    int fd;
public:
    explicit Device(const std::string& file, bool grab = false);
    ~Device();
    static std::string autoDetectDeviceFile();
    Event* next() const;
    void passThroughEvent(const Event& ev) const;
    bool isGrabbed() const;
};

} // namespace hotkey_manager

#endif // DEAMON_DEVICE_H
