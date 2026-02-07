#include "daemon/device.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>
#include <vector>
#include <syslog.h>

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

Device::Device(const std::string& file, const EventManager& manager, bool grab)
: keyBindings()
, eventManager(const_cast<EventManager&>(manager))
, keyboard() {
    fd = open(file.c_str(), O_RDONLY);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open device file: %s", file.c_str());
        throw std::runtime_error("Failed to open device file: " + file);
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        close(fd);
        syslog(LOG_ERR, "Failed to configure device file as non-blocking: %s", file.c_str());
        throw std::runtime_error("Failed to configure device file as non-blocking: " + file);
    }

    if (libevdev_new_from_fd(fd, &dev) < 0) {
        close(fd);
        syslog(LOG_ERR, "Failed to initialize libevdev for file: %s", file.c_str());
        throw std::runtime_error("Failed to initialize libevdev for file: " + file);
    }

    if (!libevdev_has_event_type(dev, EV_KEY)) {
        libevdev_free(dev);
        close(fd);
        syslog(LOG_ERR, "Device does not support key events: %s", file.c_str());
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
        syslog(LOG_ERR, "Failed to create uinput device from: %s", file.c_str());
        throw std::runtime_error("Failed to create uinput device from: " + file);
    }

    if (libevdev_grab(dev, LIBEVDEV_GRAB) < 0) {
        libevdev_uinput_destroy(uidev);
        libevdev_free(dev);
        close(fd);
        syslog(LOG_ERR, "Failed to grab device: %s", file.c_str());
        throw std::runtime_error("Failed to grab device: " + file);
    }

    try {
        manager.addFd(fd, EPOLLIN | EPOLLPRI);
    } catch (const std::exception& e) {
        syslog(LOG_ERR, "Failed to add device fd to EventManager: %s", e.what());
        libevdev_grab(dev, LIBEVDEV_UNGRAB);
        libevdev_uinput_destroy(uidev);
        libevdev_free(dev);
        close(fd);
        throw;
    }
};

Device::~Device() {
    libevdev_free(dev);
    if (uidev) {
        libevdev_grab(dev, LIBEVDEV_UNGRAB);
        libevdev_uinput_destroy(uidev);
    }
    eventManager.deleteFd(fd);
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
    if (candidates.size() > 1) {
        std::string result;
        for (size_t i = 0; i < candidates.size(); ++i) {
            if (i > 0) result += ",";
            result += candidates[i];
        }
        return result;
    }
    return candidates[0];
}

Event* Device::next() const {
    struct input_event ev;
    while (true) {
        int rc = libevdev_next_event(dev, LIBEVDEV_READ_FLAG_NORMAL, &ev);
        if (rc == LIBEVDEV_READ_STATUS_SUCCESS) {
            if (ev.type != EV_KEY) {
                if (!uidev)
                    return nullptr;
                if (libevdev_uinput_write_event(uidev, ev.type, ev.code, ev.value) < 0 ||
                    libevdev_uinput_write_event(uidev, EV_SYN, SYN_REPORT, 0) < 0) {
                    throw std::runtime_error("Failed to write non-key event to uinput device");
                }
                continue; // Drain non-key events fully before returning to caller
            }
            key_t code = ev.code;
            auto it = keyBindings.find(code);
            if (it != keyBindings.end()) {
                code = it->second;
            }
            Event* result = nullptr;
            switch (ev.value) {
                case 1:
                    result = new PressEvent(code);
                    break;
                case 0:
                    result = new ReleaseEvent(code);
                    break;
                case 2:
                    result = new RepeatEvent(code);
                    break;
            }
            keyboard.update(*result);
            return result;
        }
        if (rc == LIBEVDEV_READ_STATUS_SYNC) {
            // Clear sync backlog so level-triggered epoll won't keep firing
            while (rc == LIBEVDEV_READ_STATUS_SYNC)
                rc = libevdev_next_event(dev, LIBEVDEV_READ_FLAG_SYNC, &ev);
            continue;
        }
        if (rc == -EAGAIN)
            return nullptr; // Fully drained
        throw std::runtime_error("Error reading event from device");
    }
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

void Device::addKeyBinding(key_t from, key_t to) {
    if (from == to)
        throw std::runtime_error("Cannot bind a key to itself");
    if (keyBindings.find(from) != keyBindings.end())
        throw std::runtime_error("Key binding for the source key already exists");
    keyBindings[from] = to;
}

void Device::addKeyBinding(const std::string& from, const std::string& to) {
    key_t fromKey = libevdev_event_code_from_name(EV_KEY, ("KEY_" + from).c_str());
    if (fromKey == -1)
        throw std::runtime_error("Invalid source key name for binding: " + from);
    key_t toKey = libevdev_event_code_from_name(EV_KEY, ("KEY_" + to).c_str());
    if (toKey == -1)
        throw std::runtime_error("Invalid target key name for binding: " + to);
    addKeyBinding(fromKey, toKey);
}

bool Device::check(Condition& cond) const {
    return keyboard.check(cond);
}

} // namespace hotkey_manager
