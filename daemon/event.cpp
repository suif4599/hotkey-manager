#include "daemon/event.h"
#include "daemon/keyboard.h"
#include <string>

using namespace hotkey_manager;

namespace hotkey_manager {

std::ostream& operator<<(std::ostream& os, const Event& ev) {
    std::string type_str, key_str;
    switch(ev.get_type()) {
        case 1:
            type_str = "PressEvent";
            break;
        case 2:
            type_str = "ReleaseEvent";
            break;
        case 3:
            type_str = "RepeatEvent";
            break;
        default:
            type_str = "UnknownEvent";
    }
    os << type_str << "(Key=" << KeyMapper::getInstance()[ev.get_key()] << ")";
    return os;
}

} // namespace hotkey_manager