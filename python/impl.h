#ifndef PYTHON_IMPL_H
#define PYTHON_IMPL_H

// Use limited API for python3 (Python 3.2 introducted Py_LIMITED_API)
#define Py_LIMITED_API 3
#include <Python.h>
#if !defined(PY_VERSION_HEX) || PY_VERSION_HEX < 0x03020000
#error "hotkey_manager requires Python 3.2 or newer"
#endif

#include <cstdint>
#include <map>
#include <vector>

#include "client/interface.h"

namespace hotkey_manager {

typedef struct {
    PyObject_HEAD
    HotkeyInterface* hotkeyInterface;
    std::map<std::string, std::vector<PyObject*>>* registeredCallbacks;
    uint64_t callbackCount;
    PyObject* socketName;
    PyObject* timeoutMs;
} HotkeyManagerInterfaceObject;

extern "C" int HotkeyManagerInterface_init(HotkeyManagerInterfaceObject* self, PyObject* args, PyObject* kwargs);
extern "C" void HotkeyManagerInterface_del(HotkeyManagerInterfaceObject* self);
extern "C" PyObject* authenticate(HotkeyManagerInterfaceObject* self, PyObject* args, PyObject* kwargs);
extern "C" PyObject* register_hotkey(HotkeyManagerInterfaceObject* self, PyObject* args, PyObject* kwargs);
extern "C" PyObject* delete_hotkey(HotkeyManagerInterfaceObject* self, PyObject* args, PyObject* kwargs);
extern "C" PyObject* delete_callback(HotkeyManagerInterfaceObject* self, PyObject* args, PyObject* kwargs);
extern "C" PyObject* mainloop(HotkeyManagerInterfaceObject* self, PyObject* args, PyObject* kwargs);

extern const char* HotkeyManagerModule_docstring;
extern const char* HotkeyManagerInterface_docstring;
extern const char* HotkeyManagerInterface_socketName_docstring;
extern const char* HotkeyManagerInterface_timeoutMs_docstring;
extern const char* HotKeyManagerInterface_init_docstring;
extern const char* HotkeyManagerInterface_authenticate_docstring;
extern const char* HotkeyManagerInterface_register_hotkey_docstring;
extern const char* HotkeyManagerInterface_delete_hotkey_docstring;
extern const char* HotkeyManagerInterface_delete_callback_docstring;
extern const char* HotkeyManagerInterface_mainloop_docstring;

} // namespace hotkey_manager

#endif // PYTHON_IMPL_H
