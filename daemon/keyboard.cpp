#include "daemon/keyboard.h"
#include <libevdev-1.0/libevdev/libevdev.h>
#include <syslog.h>

using namespace hotkey_manager;

namespace hotkey_manager {

Keyboard::Keyboard() {
    for (auto& state : key_states) {
        state = false;
    }
}

void Keyboard::update(const Event& ev) {
    syslog(LOG_DEBUG, "Keyboard::update called with Event key=%d, type=%d", ev.get_key(), ev.get_type());
    switch (ev.get_type()) {
        case 1: // PressEvent
        case 3: // RepeatEvent
        {
            key_states[ev.get_key()] = true;
            lastUpdatedKey = ev.get_key();
            break;
        }
        case 2: // ReleaseEvent
        {
            key_states[ev.get_key()] = false;
            lastUpdatedKey = ev.get_key();
            break;
        }
    }
}

bool Keyboard::check(Condition& cond) const {
    return cond.check(*this);
}

KeyMapper::KeyMapper() {
    for (int code = 0; code < 256; ++code) {
        const char* key_name = libevdev_event_code_get_name(EV_KEY, code);
        // All keys are named "Key_{name}"
        if (key_name) {
            std::string name(key_name + 4);
            keycode_to_string[code] = name;
            string_to_keycode[name] = code;
        } else {
            keycode_to_string[code] = "UNKNOWN";
        }
    }
}

const std::string& KeyMapper::operator[](key_t keycode) const {
    return keycode_to_string[keycode];
}

key_t KeyMapper::operator[](const std::string& key_name) const {
    auto it = string_to_keycode.find(key_name);
    if (it != string_to_keycode.end()) {
        return it->second;
    } else {
        return -1;
    }
}

std::ostream& operator<<(std::ostream& os, const KeyMapper& mapper) {
    os << "KeyMapper(" << std::endl;
    for (int i = 0; i < 256; ++i) {
        std::string name = mapper[i];
        if (name == "UNKNOWN") {
            continue;
        }
        os << "    " << i << ": " << name << std::endl;
    }
    os << ")";
    return os;
}

KeyMapper& KeyMapper::getInstance() {
    static KeyMapper mapper;
    return mapper;
}

const std::vector<std::string> KeyMapper::availableKeys() const {
    std::vector<std::string> keys;
    for (int i = 0; i < 256; ++i) {
        std::string name = keycode_to_string[i];
        if (name != "UNKNOWN")
            keys.push_back(name);
    }
    return keys;
}

} // namespace hotkey_manager
