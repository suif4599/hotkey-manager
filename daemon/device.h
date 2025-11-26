#ifndef DEAMON_DEVICE_H
#define DEAMON_DEVICE_H

#include "daemon/event.h"
#include <libevdev-1.0/libevdev/libevdev.h>
#include <string>

namespace hotkey_manager {

class Device {
    struct libevdev* dev;
    int fd;
public:
    explicit Device(const std::string& file);
    ~Device();
    static std::string autoDetectDeviceFile();
    Event* next() const;
};

} // namespace hotkey_manager

#endif // DEAMON_DEVICE_H
