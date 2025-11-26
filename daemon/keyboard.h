#ifndef DEAMON_KEYBOARD_H
#define DEAMON_KEYBOARD_H
#include "daemon/event.h"
#include "daemon/condition.h"
#include <unordered_map>
#include <iostream>
#include <string>
#include <array>

namespace hotkey_manager {

class Keyboard {
    std::array<bool, 256> key_states;
    key_t lastUpdatedKey = -1;
    Keyboard();
public:
    ~Keyboard() = default;
    static Keyboard& getInstance();
    void update(const Event& ev);
    bool check(Condition& cond) const;

    friend class Condition;
    friend class SingleKeyCondition;
};

class KeyMapper {
    std::array<std::string, 256> keycode_to_string;
    std::unordered_map<std::string, key_t> string_to_keycode;
    KeyMapper();
public:
    ~KeyMapper() = default;
    const std::string& operator[](key_t keycode) const;
    key_t operator[](const std::string& keyname) const;
    friend std::ostream& operator<<(std::ostream& os, const KeyMapper& mapper);
    static KeyMapper& getInstance();
    const std::vector<std::string> availableKeys() const;
};

} // namespace hotkey_manager

#endif // DEAMON_KEYBOARD_H
