#include "daemon/device.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>
#include <vector>

using namespace hotkey_manager;

namespace hotkey_manager {

static bool isKeyboard(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return false;
    struct libevdev* test_dev = nullptr;
    bool result = false;
    if (libevdev_new_from_fd(fd, &test_dev) >= 0) {
        if (libevdev_has_event_type(test_dev, EV_KEY) // Check for some keys
            && libevdev_has_event_code(test_dev, EV_KEY, KEY_A)
            && libevdev_has_event_code(test_dev, EV_KEY, KEY_Z)
            && libevdev_has_event_code(test_dev, EV_KEY, KEY_ENTER))
            result = true;
        libevdev_free(test_dev);
    }
    close(fd);
    return result;
}

Device::Device(const std::string& file, bool grab) {
    fd = open(file.c_str(), O_RDONLY);
    if (fd < 0) {
        throw std::runtime_error("Failed to open device file: " + file);
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        close(fd);
        throw std::runtime_error("Failed to configure device file as non-blocking: " + file);
    }

    if (libevdev_new_from_fd(fd, &dev) < 0) {
        close(fd);
        throw std::runtime_error("Failed to initialize libevdev for file: " + file);
    }

    if (!libevdev_has_event_type(dev, EV_KEY)) {
        libevdev_free(dev);
        close(fd);
        throw std::runtime_error("Device does not support key events: " + file);
    }

    if (!grab) {
        uidev = nullptr;
        return;
    }

    if (
        libevdev_uinput_create_from_device(
            dev,
            LIBEVDEV_UINPUT_OPEN_MANAGED,
            &uidev
        ) < 0
    ) {
        libevdev_free(dev);
        close(fd);
        throw std::runtime_error("Failed to create uinput device from: " + file);
    }

    if (libevdev_grab(dev, LIBEVDEV_GRAB) < 0) {
        libevdev_uinput_destroy(uidev);
        libevdev_free(dev);
        close(fd);
        throw std::runtime_error("Failed to grab device: " + file);
    }
};

Device::~Device() {
    libevdev_free(dev);
    close(fd);
}

std::string Device::autoDetectDeviceFile() {
    // Simple auto-detection: return the first event device found in /dev/input/
    const std::string inputPath = "/dev/input/event";
    std::vector<std::string> candidates;
    for (int i = 0; i < 32; ++i) {
        std::string deviceFile = inputPath + std::to_string(i);
        if (isKeyboard(deviceFile))
            candidates.push_back(deviceFile);
    }
    if (candidates.empty())
        throw std::runtime_error("No suitable input device found for auto-detection");
    if (candidates.size() > 1)
        throw std::runtime_error("Multiple suitable input devices found for auto-detection");
    return candidates[0];
}

Event* Device::next() const {
    struct input_event ev;
    int rc = libevdev_next_event(dev, LIBEVDEV_READ_FLAG_NORMAL, &ev);
    if (rc == LIBEVDEV_READ_STATUS_SUCCESS) {
        if (ev.type != EV_KEY) {
            if (!uidev)
                return nullptr;
            if (libevdev_uinput_write_event(uidev, ev.type, ev.code, ev.value) < 0 ||
                libevdev_uinput_write_event(uidev, EV_SYN, SYN_REPORT, 0) < 0) {
                throw std::runtime_error("Failed to write non-key event to uinput device");
            }
            return nullptr;
        }
        switch (ev.value) {
            case 1:
                return new PressEvent(ev.code);
            case 0:
                return new ReleaseEvent(ev.code);
            case 2:
                return new RepeatEvent(ev.code);
            default:
                return nullptr;
        }
    }
    if (rc == LIBEVDEV_READ_STATUS_SYNC || rc == -EAGAIN)
        return nullptr;
    throw std::runtime_error("Error reading event from device");
}

void Device::passThroughEvent(const Event& ev) const {
    if (!uidev)
        throw std::runtime_error("Uinput device not initialized for pass-through");

    int value;
    switch (ev.get_type()) {
        case 1:
            value = 1; // Press
            break;
        case 2:
            value = 0; // Release
            break;
        case 3:
            value = 2; // Repeat
            break;
        default:
            throw std::runtime_error("Unknown event type for pass-through");
    }

    if (libevdev_uinput_write_event(uidev, EV_KEY, ev.get_key(), value) < 0 ||
        libevdev_uinput_write_event(uidev, EV_SYN, SYN_REPORT, 0) < 0) {
        throw std::runtime_error("Failed to write event to uinput device");
    }

    if (libevdev_uinput_write_event(uidev, EV_SYN, SYN_REPORT, 0) < 0) {
        throw std::runtime_error("Failed to write SYN event to uinput device");
    }
}

bool Device::isGrabbed() const {
    return uidev != nullptr;
}

} // namespace hotkey_manager
