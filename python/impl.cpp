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
    self->socketName = nullptr;
    self->timeoutMs = nullptr;

    PyObject* socketNameObj = nullptr; // Borrow reference
    PyObject* timeoutMs = nullptr; // Borrow too
    static char kw_socket_name[] = "socket_name";
    static char kw_timeout_ms[] = "timeout_ms";
    static char* kwlist[] = {kw_socket_name, kw_timeout_ms, nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|OO", kwlist, &socketNameObj, &timeoutMs))
        return -1;

    // Type checking and default value and setting attributes
    if (socketNameObj == nullptr) {
        socketNameObj = PyUnicode_FromString(DEFAULT_SOCKET_NAME);
        if (socketNameObj == nullptr)
            return -1;
        self->socketName = socketNameObj; // Owns reference from constructor
    } else if (!PyUnicode_Check(socketNameObj)) {
        PyErr_SetString(PyExc_TypeError, "socket_name must be a string");
        return -1;
    } else {
        self->socketName = socketNameObj;
        Py_INCREF(socketNameObj);
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

    try {
        self->registeredCallbacks = new std::map<std::string, std::vector<PyObject*>>();
    } catch (const std::bad_alloc&) {
        Py_XDECREF(self->socketName);
        self->socketName = nullptr;
        Py_XDECREF(self->timeoutMs);
        self->timeoutMs = nullptr;
        PyErr_SetString(PyExc_RuntimeError, "Failed to allocate memory for registeredCallbacks");
        return -1;
    }

    std::string socketNameUtf8;
    if (!UnicodeToUtf8(self->socketName, socketNameUtf8)) {
        delete self->registeredCallbacks;
        self->registeredCallbacks = nullptr;
        Py_XDECREF(self->socketName);
        self->socketName = nullptr;
        Py_XDECREF(self->timeoutMs);
        self->timeoutMs = nullptr;
        return -1;
    }
    long timeout_ms_clong = PyLong_AsLong(timeoutMs);
    if (PyErr_Occurred()) {
        delete self->registeredCallbacks;
        self->registeredCallbacks = nullptr;
        Py_XDECREF(self->socketName);
        self->socketName = nullptr;
        Py_XDECREF(self->timeoutMs);
        self->timeoutMs = nullptr;
        return -1;
    }

    std::string initError;
    bool initFailed = false;
    PyThreadState* threadState = PyEval_SaveThread();
    try {
        self->hotkeyInterface = new HotkeyInterface(socketNameUtf8, static_cast<int>(timeout_ms_clong));
    } catch (const std::exception& e) {
        initFailed = true;
        initError = e.what();
    }
    PyEval_RestoreThread(threadState);

    if (initFailed) {
        PyErr_SetString(PyExc_RuntimeError, initError.c_str());
        delete self->registeredCallbacks;
        self->registeredCallbacks = nullptr;
        Py_XDECREF(self->socketName);
        self->socketName = nullptr;
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
    Py_XDECREF(self->socketName);
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
    PyObject* passThroughObj = nullptr;
    static char kw_hotkey[] = "hotkey";
    static char kw_callback[] = "callback";
    static char kw_pass_through[] = "pass_through";
    static char* kwlist[] = {kw_hotkey, kw_callback, kw_pass_through, nullptr};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|O", kwlist, &hotkeyStrObj, &callbackObj, &passThroughObj))
        return nullptr;

    if (!PyUnicode_Check(hotkeyStrObj)) {
        PyErr_SetString(PyExc_TypeError, "hotkey_str must be a string");
        return nullptr;
    }
    if (!PyCallable_Check(callbackObj)) {
        PyErr_SetString(PyExc_TypeError, "callback must be callable");
        return nullptr;
    }
    if (passThroughObj != nullptr && !PyBool_Check(passThroughObj)) {
        PyErr_SetString(PyExc_TypeError, "pass_through must be a boolean");
        return nullptr;
    }

    std::string hotkeyUtf8;
    if (!UnicodeToUtf8(hotkeyStrObj, hotkeyUtf8))
        return nullptr;

    Py_INCREF(callbackObj);

    bool passThrough = false;
    if (passThroughObj != nullptr) {
        passThrough = (passThroughObj == Py_True);
    }

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
            functionId,
            passThrough
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

    // Prepare Python return value before mutating state
    PyObject* canonicalStrObj = PyUnicode_FromString(formatedHotketStr.c_str());
    if (canonicalStrObj == nullptr) {
        // Roll back the registration to keep client/server state aligned
        try {
            self->hotkeyInterface->deleteCallback(functionId);
        } catch (...) {
            // Suppress secondary errors; original Unicode failure takes precedence
        }
        self->callbackCount--;
        Py_DECREF(callbackObj);
        return nullptr;
    }

    // Store the callback for later XDECREF
    auto& callbacks = (*self->registeredCallbacks)[formatedHotketStr];
    callbacks.push_back(callbackObj);

    return canonicalStrObj;
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
    "hotkey_manager module\n"\
    "\n"\
    "Comprehensive Python bindings for the hotkey-manager daemon. The module\n"\
    "exposes a single entry point, HotkeyManagerInterface, which handles\n"\
    "encrypted IPC, authentication, and hotkey dispatch for system-wide\n"\
    "shortcuts.";
const char* HotkeyManagerInterface_docstring = \
    "HotkeyManagerInterface(socket_name: str = \"" DEFAULT_SOCKET_NAME "\", timeout_ms: int = 5000)\n"\
    "--\n"\
    "\n"\
    "High-level client for interacting with the hotkey-manager daemon.\n"\
    "It manages socket connections, libsodium key exchange, password\n"\
    "authentication, callback registration, and keep-alive heartbeats so Python\n"\
    "applications can react to global shortcuts without dealing with raw IPC.";
const char* HotkeyManagerInterface_socketName_docstring = \
    "socket_name: str\n"\
    "    Read-only name of the AF_UNIX abstract socket exposed by the daemon.\n"\
    "    Defaults to \"" DEFAULT_SOCKET_NAME "\" (matches the socketName configuration).";
const char* HotkeyManagerInterface_timeoutMs_docstring = \
    "timeout_ms: int\n"\
    "    Read-only per-request timeout (milliseconds). Applied whenever the\n"\
    "    client waits for a response from the daemon.";
const char* HotKeyManagerInterface_init_docstring = \
    "__init__($self, /, socket_name='" DEFAULT_SOCKET_NAME "', timeout_ms=5000)\n"\
    "--\n"\
    "\n"\
    "Establish a new client session bound to the given abstract Unix domain socket name.\n"\
    "The constructor connects to the daemon, retrieves its public key,\n"\
    "registers a fresh client key pair, and prepares encrypted messaging.\n"\
    "The timeout controls how long commands wait for responses.\n"\
    "\n"\
    "Parameters\n"\
    "----------\n"\
    "socket_name: str\n"\
    "    Name of the daemon's abstract Unix socket (matches configuration).\n"\
    "timeout_ms: int, default 5000\n"\
    "    Milliseconds to wait for each daemon response before timing out.";
const char* HotkeyManagerInterface_authenticate_docstring = \
    "authenticate($self, password: str)\n"\
    "--\n"\
    "\n"\
    "Authenticate this process with the daemon using the configured password.\n"\
    "The cleartext password travels inside the encrypted channel alongside the\n"\
    "current pid:uid:gid tuple.\n"\
    "\n"\
    "Parameters\n"\
    "----------\n"\
    "password: str\n"\
    "    Plaintext password whose Argon2 hash is stored in the daemon config.\n"\
    "\n"\
    "Raises\n"\
    "------\n"\
    "RuntimeError\n"\
    "    Raised when authentication fails or the session is already authenticated.";
const char* HotkeyManagerInterface_register_hotkey_docstring = \
    "register_hotkey($self, hotkey: str, callback: Callable[[], None], pass_through: bool = False)\n"\
    "--\n"\
    "\n"\
    "Register a hotkey expression and associate a zero-argument callback.\n"\
    "The daemon validates the expression (combinations, Double(...), Hold(...),\n"\
    "etc.) and returns the canonicalized string, which is also returned here.\n"\
    "Callbacks are invoked on the thread running mainloop().\n"\
    "\n"\
    "Parameters\n"\
    "----------\n"\
    "hotkey: str\n"\
    "    Hotkey grammar accepted by the daemon (e.g. 'LEFTCTRL + C', 'Double(ESC)').\n"\
    "callback: Callable[[], None]\n"\
    "    Zero-argument callable executed whenever the daemon signals the hotkey.\n"\
    "pass_through: bool, default False\n"\
    "    If True, the hotkey key events are also passed through to the OS;\n"\
    "    otherwise, the daemon suppresses them system-wide.\n"\
    "\n"\
    "Returns\n"\
    "-------\n"\
    "str\n"\
    "    Canonical hotkey string as normalized by the daemon.\n"\
    "\n"\
    "Raises\n"\
    "------\n"\
    "RuntimeError\n"\
    "    Raised if the expression is invalid or the session is not authenticated.";
const char* HotkeyManagerInterface_delete_hotkey_docstring = \
    "delete_hotkey($self, hotkey: str)\n"\
    "--\n"\
    "\n"\
    "Remove all callbacks registered for the given hotkey expression and drop\n"\
    "the daemon-side mapping. The expression is normalized before removal.\n"\
    "\n"\
    "Parameters\n"\
    "----------\n"\
    "hotkey: str\n"\
    "    Hotkey expression previously registered with register_hotkey().\n"\
    "\n"\
    "Raises\n"\
    "------\n"\
    "RuntimeError\n"\
    "    Raised if the hotkey has not been registered for this session.";
const char* HotkeyManagerInterface_delete_callback_docstring = \
    "delete_callback($self, callback: Callable[[], None])\n"\
    "--\n"\
    "\n"\
    "Remove a previously registered callback object from every hotkey.\n"\
    "If the last callback for a hotkey disappears, the daemon mapping is cleared.\n"\
    "\n"\
    "Parameters\n"\
    "----------\n"\
    "callback: Callable[[], None]\n"\
    "    The same Python callable object previously passed to register_hotkey().\n"\
    "\n"\
    "Raises\n"\
    "------\n"\
    "RuntimeError\n"\
    "    Raised when the callback is unknown for this session.";
const char* HotkeyManagerInterface_mainloop_docstring = \
    "mainloop($self, keep_running: Optional[Callable[[], bool]] = None)\n"\
    "--\n"\
    "\n"\
    "Enter the event loop to dispatch hotkey callbacks. The optional\n"\
    "keep_running callable is evaluated each iteration to allow cooperative\n"\
    "shutdown. Pending signals (e.g. KeyboardInterrupt) are propagated back to\n"\
    "the caller.\n"\
    "\n"\
    "Parameters\n"\
    "----------\n"\
    "keep_running: Optional[Callable[[], bool]]\n"\
    "    Callable returning True to continue looping; returning False or raising\n"\
    "    an exception stops the loop. When None, the loop runs until interrupted.";

} // namespace hotkey_manager
