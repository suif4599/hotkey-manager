#include "python/impl.h"
#include <algorithm>
#include <string>

using namespace hotkey_manager;

namespace hotkey_manager {

// PyUnicode_AsUTF8 is not available in Py_LIMITED_API
static bool UnicodeToUtf8(PyObject* unicode, std::string& out) {
    PyObject* bytes = PyUnicode_AsUTF8String(unicode);
    if (bytes == nullptr) {
        return false;
    }

    char* buffer = nullptr;
    Py_ssize_t size = 0;
    if (PyBytes_AsStringAndSize(bytes, &buffer, &size) < 0) {
        Py_DECREF(bytes);
        return false;
    }

    out.assign(buffer, static_cast<size_t>(size));
    Py_DECREF(bytes);
    return true;
}

extern "C" int HotkeyManagerInterface_init(HotkeyManagerInterfaceObject* self, PyObject* args, PyObject* kwargs) {
    self->hotkeyInterface = nullptr;
    self->registeredCallbacks = nullptr;
    self->callbackCount = 0;
    self->socketPath = nullptr;
    self->timeoutMs = nullptr;

    PyObject* socketPath = nullptr; // Borrow reference
    PyObject* timeoutMs = nullptr; // Borrow too
    static char kw_socket_path[] = "socket_path";
    static char kw_timeout_ms[] = "timeout_ms";
    static char* kwlist[] = {kw_socket_path, kw_timeout_ms, nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|O", kwlist, &socketPath, &timeoutMs))
        return -1;
    if (socketPath == nullptr)
        return -1;

    // Type checking and default value and setting attributes
    if (!PyUnicode_Check(socketPath)) {
        PyErr_SetString(PyExc_TypeError, "socket_path must be a string");
        return -1;
    }
    if (timeoutMs == nullptr) {
        timeoutMs = PyLong_FromLong(5000); // Owner reference
        if (timeoutMs == nullptr)
            return -1;
        self->timeoutMs = timeoutMs;
    } else if (!PyLong_Check(timeoutMs)) {
        PyErr_SetString(PyExc_TypeError, "timeout_ms must be an integer");
        return -1;
    } else {
        self->timeoutMs = timeoutMs;
        Py_INCREF(timeoutMs); // Increment reference count for borrowed reference
    }
    self->socketPath = socketPath;
    Py_INCREF(socketPath);

    try {
        self->registeredCallbacks = new std::map<std::string, std::vector<PyObject*>>();
    } catch (const std::bad_alloc&) {
        Py_XDECREF(self->socketPath);
        self->socketPath = nullptr;
        Py_XDECREF(self->timeoutMs);
        self->timeoutMs = nullptr;
        PyErr_SetString(PyExc_RuntimeError, "Failed to allocate memory for registeredCallbacks");
        return -1;
    }

    std::string socketPathUtf8;
    if (!UnicodeToUtf8(socketPath, socketPathUtf8)) {
        delete self->registeredCallbacks;
        self->registeredCallbacks = nullptr;
        Py_XDECREF(self->socketPath);
        self->socketPath = nullptr;
        Py_XDECREF(self->timeoutMs);
        self->timeoutMs = nullptr;
        return -1;
    }
    long timeout_ms_clong = PyLong_AsLong(timeoutMs);
    if (PyErr_Occurred()) {
        delete self->registeredCallbacks;
        self->registeredCallbacks = nullptr;
        Py_XDECREF(self->socketPath);
        self->socketPath = nullptr;
        Py_XDECREF(self->timeoutMs);
        self->timeoutMs = nullptr;
        return -1;
    }

    std::string initError;
    bool initFailed = false;
    PyThreadState* threadState = PyEval_SaveThread();
    try {
        self->hotkeyInterface = new HotkeyInterface(socketPathUtf8, static_cast<int>(timeout_ms_clong));
    } catch (const std::exception& e) {
        initFailed = true;
        initError = e.what();
    }
    PyEval_RestoreThread(threadState);

    if (initFailed) {
        PyErr_SetString(PyExc_RuntimeError, initError.c_str());
        delete self->registeredCallbacks;
        self->registeredCallbacks = nullptr;
        Py_XDECREF(self->socketPath);
        self->socketPath = nullptr;
        Py_XDECREF(self->timeoutMs);
        self->timeoutMs = nullptr;
        return -1;
    }

    return 0;
}

extern "C" void HotkeyManagerInterface_del(HotkeyManagerInterfaceObject* self) {
    // Close session
    PyThreadState* _save = PyEval_SaveThread();
    delete self->hotkeyInterface;
    PyEval_RestoreThread(_save);

    // Handle Reference Counts
    if (self->registeredCallbacks != nullptr) {
        // Notice: must decref all registered callbacks
        for (const auto& [hotkeyStr, callbacks] : *self->registeredCallbacks) {
            for (PyObject* callback : callbacks) {
                Py_XDECREF(callback);
            }
        }
        delete self->registeredCallbacks;
        self->registeredCallbacks = nullptr;
    }
    Py_XDECREF(self->socketPath);
    Py_XDECREF(self->timeoutMs);

    PyObject_Free(reinterpret_cast<PyObject*>(self));
}

extern "C" PyObject* authenticate(HotkeyManagerInterfaceObject* self, PyObject* args, PyObject* kwargs) {
    PyObject* passwordObj = nullptr;
    static char kw_password[] = "password";
    static char* kwlist[] = {kw_password, nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O", kwlist, &passwordObj))
        return nullptr;

    if (!PyUnicode_Check(passwordObj)) {
        PyErr_SetString(PyExc_TypeError, "password must be a string");
        return nullptr;
    }

    std::string passwordUtf8;
    if (!UnicodeToUtf8(passwordObj, passwordUtf8))
        return nullptr;

    std::string errorMessage;
    bool failed = false;
    PyThreadState* threadState = PyEval_SaveThread();
    try {
        self->hotkeyInterface->authenticate(passwordUtf8);
    } catch (const std::exception& e) {
        failed = true;
        errorMessage = e.what();
    }
    PyEval_RestoreThread(threadState);

    if (failed) {
        PyErr_SetString(PyExc_RuntimeError, errorMessage.c_str());
        return nullptr;
    }

    Py_RETURN_NONE;
}

extern "C" PyObject* register_hotkey(HotkeyManagerInterfaceObject* self, PyObject* args, PyObject* kwargs) {
    PyObject* hotkeyStrObj = nullptr;
    PyObject* callbackObj = nullptr;
    static char kw_hotkey[] = "hotkey";
    static char kw_callback[] = "callback";
    static char* kwlist[] = {kw_hotkey, kw_callback, nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO", kwlist, &hotkeyStrObj, &callbackObj))
        return nullptr;

    if (!PyUnicode_Check(hotkeyStrObj)) {
        PyErr_SetString(PyExc_TypeError, "hotkey_str must be a string");
        return nullptr;
    }
    if (!PyCallable_Check(callbackObj)) {
        PyErr_SetString(PyExc_TypeError, "callback must be callable");
        return nullptr;
    }

    std::string hotkeyUtf8;
    if (!UnicodeToUtf8(hotkeyStrObj, hotkeyUtf8))
        return nullptr;

    Py_INCREF(callbackObj);

    // Use callback object's address and a number as functionId
    self->callbackCount++;
    std::string functionId;
    try {
        functionId = std::to_string(reinterpret_cast<uintptr_t>(callbackObj)) + "_" + std::to_string(self->callbackCount);
    } catch (const std::exception& e) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to generate function ID");
        self->callbackCount--;
        Py_DECREF(callbackObj); // Notice: Must DECREF on failure
        return nullptr;
    }

    std::string formatedHotketStr;
    std::string errorMessage;
    bool failed = false;
    PyThreadState* threadState = PyEval_SaveThread();
    try {
        formatedHotketStr = self->hotkeyInterface->registerHotkey(
            hotkeyUtf8,
            [callbackObj]() {
                PyGILState_STATE gstate = PyGILState_Ensure();
                PyObject* result = PyObject_CallObject(callbackObj, nullptr);
                if (result == nullptr) {
                    if (PyErr_ExceptionMatches(PyExc_KeyboardInterrupt)) {
                        // Defer KeyboardInterrupt so mainloop sees it instead of dumping a traceback here.
                        PyErr_Clear();
                        PyErr_SetInterrupt();
                    } else {
                        PyErr_Print();
                    }
                } else {
                    Py_DECREF(result);
                }
                PyGILState_Release(gstate);
            },
            functionId
        );
    } catch (const std::exception& e) {
        failed = true;
        errorMessage = e.what();
    }
    PyEval_RestoreThread(threadState);

    if (failed) {
        PyErr_SetString(PyExc_RuntimeError, errorMessage.c_str());
        self->callbackCount--;
        Py_DECREF(callbackObj); // Notice: Must DECREF on failure
        return nullptr;
    }

    // Store the callback for later XDECREF
    auto& callbacks = (*self->registeredCallbacks)[formatedHotketStr];
    callbacks.push_back(callbackObj);

    Py_RETURN_NONE;
}

extern "C" PyObject* delete_hotkey(HotkeyManagerInterfaceObject* self, PyObject* args, PyObject* kwargs) {
    PyObject* hotkeyStrObj = nullptr;
    static char kw_hotkey[] = "hotkey";
    static char* kwlist[] = {kw_hotkey, nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O", kwlist, &hotkeyStrObj))
        return nullptr;
    if (!PyUnicode_Check(hotkeyStrObj)) {
        PyErr_SetString(PyExc_TypeError, "hotkey_str must be a string");
        return nullptr;
    }

    std::string hotkeyUtf8;
    if (!UnicodeToUtf8(hotkeyStrObj, hotkeyUtf8))
        return nullptr;

    std::string formatedHotkeyStr;
    std::string formatError;
    bool formatFailed = false;
    PyThreadState* threadState = PyEval_SaveThread();
    try {
        formatedHotkeyStr = self->hotkeyInterface->formatHotkey(hotkeyUtf8);
    } catch (const std::exception& e) {
        formatFailed = true;
        formatError = e.what();
    }
    PyEval_RestoreThread(threadState);

    if (formatFailed) {
        PyErr_SetString(PyExc_RuntimeError, formatError.c_str());
        return nullptr;
    }

    auto it = self->registeredCallbacks->find(formatedHotkeyStr);
    if (it == self->registeredCallbacks->end()) {
        PyErr_SetString(PyExc_RuntimeError, "Unregistered hotkey");
        return nullptr;
    }

    // Do Cpp call
    std::string deleteError;
    bool deleteFailed = false;
    threadState = PyEval_SaveThread();
    try {
        self->hotkeyInterface->deleteHotkey(hotkeyUtf8);
    } catch (const std::exception& e) {
        deleteFailed = true;
        deleteError = e.what();
    }
    PyEval_RestoreThread(threadState);

    if (deleteFailed) {
        PyErr_SetString(PyExc_RuntimeError, deleteError.c_str());
        return nullptr;
    }

    // XDECREF and delete vector
    for (PyObject* callbackObj : it->second) {
        Py_XDECREF(callbackObj);
    }
    self->registeredCallbacks->erase(it);

    Py_RETURN_NONE;
}

extern "C" PyObject* delete_callback(HotkeyManagerInterfaceObject* self, PyObject* args, PyObject* kwargs) {
    PyObject* callableObj = nullptr;
    static char kw_callable[] = "callable";
    static char* kwlist[] = {kw_callable, nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O", kwlist, &callableObj))
        return nullptr;

    // Find the functionObj
    auto interfaceCallbackMap = self->hotkeyInterface->getCallbacks();
    std::string prefix = std::to_string(reinterpret_cast<uintptr_t>(callableObj));
    std::vector<std::string> functionIdNeedDelete;
    for (const auto& [hotStr, callbacks] : interfaceCallbackMap) {
        for (const auto& [fid, func] : callbacks) {
            if (fid.rfind(prefix) == std::string::npos)
                continue;
            functionIdNeedDelete.push_back(fid);
        }
    }
    if (functionIdNeedDelete.empty()) {
        PyErr_SetString(PyExc_RuntimeError, "Cannot delete an unregistered hotkey callback function");
        return nullptr;
    }

    // Delete the callbacks in server
    std::string deleteError;
    bool deleteFailed = false;
    PyThreadState* threadState = PyEval_SaveThread();
    try {
        for (const auto& fid : functionIdNeedDelete) {
            self->hotkeyInterface->deleteCallback(fid);
        }
    } catch (const std::exception& e) {
        deleteFailed = true;
        deleteError = e.what();
    }
    PyEval_RestoreThread(threadState);

    if (deleteFailed) {
        std::string msg = "Fail to delete the callback function, ";
        msg += deleteError;
        PyErr_SetString(PyExc_RuntimeError, msg.c_str());
        return nullptr;
    }

    // Delete the callbacks in struct
    threadState = PyEval_SaveThread();
    std::vector<std::string> hotkeyNeedDelete;
    size_t decrefCount = 0;
    for (auto& [hotkeyStr, callbacks] : *self->registeredCallbacks) {
        auto removeBegin = std::remove(callbacks.begin(), callbacks.end(), callableObj);
        size_t removed = static_cast<size_t>(std::distance(removeBegin, callbacks.end()));
        decrefCount += removed;
        callbacks.erase(removeBegin, callbacks.end());
        if (callbacks.empty())
            hotkeyNeedDelete.push_back(hotkeyStr);
    }
    for (const auto& hotkeyStr : hotkeyNeedDelete) {
        self->registeredCallbacks->erase(hotkeyStr);
    }

    PyEval_RestoreThread(threadState);
    while (decrefCount-- > 0) {
        Py_XDECREF(callableObj);
    }
    Py_RETURN_NONE;
}

extern "C" PyObject* mainloop(HotkeyManagerInterfaceObject* self, PyObject* args, PyObject* kwargs) {
    // No argumentssystemd-ask-password
    PyObject* keepRunningObj = nullptr;
    bool isNone;
    static char kw_keep_running[] = "keep_running";
    static char* kwlist[] = {kw_keep_running, nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O", kwlist, &keepRunningObj))
        return nullptr;
    if (keepRunningObj == nullptr || Py_IsNone(keepRunningObj)) {
        isNone = true;
    } else {
        isNone = false;
        if (!PyCallable_Check(keepRunningObj)) {
            PyErr_SetString(PyExc_TypeError, "keep_running must be callable or None");
            return nullptr;
        }
        Py_INCREF(keepRunningObj);
    }

    std::string errorMessage;
    bool failed = false;
    PyThreadState* threadState = PyEval_SaveThread();
    try {
        self->hotkeyInterface->mainloop([keepRunningObj, isNone]() {
            PyGILState_STATE gstate = PyGILState_Ensure();
            bool keepRunning = PyErr_CheckSignals() == 0; // KeyboardInterrupt and other exception will exit the loop
            if (!isNone) {
                PyObject* result = PyObject_CallObject(keepRunningObj, nullptr);
                if (result == nullptr) {
                    if (PyErr_ExceptionMatches(PyExc_KeyboardInterrupt)) {
                        // Same as register_hotkey
                        PyErr_Clear();
                        PyErr_SetInterrupt();
                    } else {
                        PyErr_Print();
                    }
                    keepRunning = false;
                } else {
                    int isTrue = PyObject_IsTrue(result);
                    Py_DECREF(result);
                    if (isTrue == -1) {
                        if (PyErr_ExceptionMatches(PyExc_KeyboardInterrupt)) {
                            PyErr_Clear();
                            PyErr_SetInterrupt();
                        } else {
                            PyErr_Print();
                        }
                        keepRunning = false;
                    } else {
                        keepRunning = keepRunning && (isTrue != 0);
                    }
                }
            }
            PyGILState_Release(gstate);
            return keepRunning;
        });
    } catch (const std::exception& e) {
        failed = true;
        errorMessage = e.what();
    }
    PyEval_RestoreThread(threadState);

    if (failed) {
        PyErr_SetString(PyExc_RuntimeError, errorMessage.c_str());
        return nullptr;
    }
    if (PyErr_Occurred())
        return nullptr; // Propagate pending exceptions such as KeyboardInterrupt
    Py_RETURN_NONE;
}

const char* HotkeyManagerModule_docstring = \
    "Linux hotkey manager with native daemon bindings";
const char* HotkeyManagerInterface_docstring = \
    "Hotkey Manager Interface";
const char* HotkeyManagerInterface_socketPath_docstring = \
    "Path to the Unix domain socket";
const char* HotkeyManagerInterface_timeoutMs_docstring = \
    "Timeout in milliseconds for IPC operations";
const char* HotKeyManagerInterface_init_docstring = \
    "Initialize the HotkeyManagerInterface with socket_path and timeout_ms.";
const char* HotkeyManagerInterface_authenticate_docstring = \
    "Authenticate with the hotkey manager using a password.";
const char* HotkeyManagerInterface_register_hotkey_docstring = \
    "Register a hotkey with a callback function.";
const char* HotkeyManagerInterface_delete_hotkey_docstring = \
    "Delete all callback functions for a hotkey.";
const char* HotkeyManagerInterface_delete_callback_docstring = \
    "Delete the given callback function.";
const char* HotkeyManagerInterface_mainloop_docstring = \
    "Start the main event loop to listen for hotkey events.";

} // namespace hotkey_manager
