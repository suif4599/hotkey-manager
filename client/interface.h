#ifndef CLIENT_INTERFACE_H
#define CLIENT_INTERFACE_H

#include "ipc/uds.h"
#include "ipc/encrypt.h"

#include <unordered_map>
#include <string>
#include <functional>
#include <mutex>

namespace hotkey_manager {

class HotkeyInterface {
    std::unordered_map<
        std::string,
        std::vector<std::pair<
            std::string,
            std::function<void()>
        >>
    > callbackMap;
    UnixDomainSocketClient client;
    Encryptor encryptor;
    std::string serverPublicKey;
    mutable std::recursive_mutex interfaceMutex;
public:
    HotkeyInterface(const std::string& socketPath, int64_t timeoutMs = 5000);
    ~HotkeyInterface();
    // Callback should return true if need to continue, false to break the mainloop
    std::string registerHotkey(
        const std::string& hotkeyStr,
        std::function<void()> callback,
        std::string functionId = ""
    );
    void deleteHotkey(const std::string& hotkeyStr);
    void deleteCallback(std::string functionId);
    void authenticate(const std::string& password);
    std::string formatHotkey(const std::string& hotkeyStr);
    void mainloop(std::function<bool()> keepRunning = []() {
        return true;
    });
    const decltype(callbackMap)& getCallbacks() const;
};

} // namespace hotkey_manager

#endif // CLIENT_INTERFACE_H
