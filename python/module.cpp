#include "python/impl.h"
#include <structmember.h>

using namespace hotkey_manager;

static PyMemberDef hotkeyManagerInterfaceMembers[] = {
    // T_OBJECT_EX will raise an AttributeError when the attribute is NULL
    {
        "socket_name", T_OBJECT_EX, offsetof(HotkeyManagerInterfaceObject, socketName),
        READONLY, HotkeyManagerInterface_socketName_docstring
    },
    {
        "timeout_ms", T_OBJECT_EX, offsetof(HotkeyManagerInterfaceObject, timeoutMs),
        READONLY, HotkeyManagerInterface_timeoutMs_docstring
    },
    {NULL}
};

static PyMethodDef hotkeyManagerInterfaceMethods[] = {
    {"authenticate", (PyCFunction)authenticate, METH_VARARGS | METH_KEYWORDS, HotkeyManagerInterface_authenticate_docstring},
    {"register_hotkey", (PyCFunction)register_hotkey, METH_VARARGS | METH_KEYWORDS, HotkeyManagerInterface_register_hotkey_docstring},
    {"delete_hotkey", (PyCFunction)delete_hotkey, METH_VARARGS | METH_KEYWORDS, HotkeyManagerInterface_delete_hotkey_docstring},
    {"delete_callback", (PyCFunction)delete_callback, METH_VARARGS | METH_KEYWORDS, HotkeyManagerInterface_delete_callback_docstring},
    {"mainloop", (PyCFunction)mainloop, METH_VARARGS | METH_KEYWORDS, HotkeyManagerInterface_mainloop_docstring},
    {NULL}
};

// Avoid "incomplete type" error when define "static PyTypeObject HotkeyManagerInterfaceType" directly
static PyType_Slot HotkeyManagerInterfaceSlots[] = {
    {Py_tp_doc, const_cast<char*>(HotkeyManagerInterface_docstring)},
    {Py_tp_methods, hotkeyManagerInterfaceMethods},
    {Py_tp_members, hotkeyManagerInterfaceMembers},
    {Py_tp_init, (void*)HotkeyManagerInterface_init},
    {Py_tp_new, (void*)PyType_GenericNew},
    {Py_tp_dealloc, (void*)HotkeyManagerInterface_del},
    {0, nullptr}
};

static PyType_Spec HotkeyManagerInterfaceSpec = {
    "hotkey_manager.HotkeyManagerInterface",
    sizeof(HotkeyManagerInterfaceObject),
    0,
    Py_TPFLAGS_DEFAULT,
    HotkeyManagerInterfaceSlots
};

static PyMethodDef hotkeyManagerMethods[] = {
    {NULL}
};

static struct PyModuleDef hotkey_manager_module = {
    PyModuleDef_HEAD_INIT,
    "hotkey_manager",
    PyDoc_STR(HotkeyManagerModule_docstring),
    -1,
    hotkeyManagerMethods
};

PyMODINIT_FUNC PyInit_hotkey_manager(void) {
    PyObject* module = PyModule_Create(&hotkey_manager_module);
    if (module == nullptr)
        return nullptr;

    PyObject* interfaceType = PyType_FromSpec(&HotkeyManagerInterfaceSpec);
    if (interfaceType == nullptr) {
        Py_DECREF(module);
        return nullptr;
    }

    if (PyModule_AddObject(module, "HotkeyManagerInterface", interfaceType) < 0) {
        Py_DECREF(interfaceType);
        Py_DECREF(module);
        return nullptr;
    }

    return module;
}
