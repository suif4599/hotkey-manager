#ifndef DEAMON_MANAGER_H
#define DEAMON_MANAGER_H

#include "daemon/keyboard.h"
#include "daemon/device.h"
#include "daemon/condition.h"
#include "daemon/session.h"
#include "ipc/uds.h"
#include "ipc/encrypt.h"

#include <sodium.h>
#include <vector>
#include <string>
#include <map>
#include <unordered_map>
#include <functional>

namespace hotkey_manager {

// Commands:
// (Text) getPublicKey -> publicKey
// (Encrypted) RegisterPublicKey(publicKey) -> "[OK]"
// (Encrypted) Authenticate(passward, pid:uid:gid) -> "[OK]" / "[Error]: ..."
// (Encrypted) RegisterHotkey(conditionStr) -> "[OK]: hotkeyStr" / "[Error]: ..."; Allow Reregistering same hotkey
// (Encrypted) DeleteHotkey(hotkeyStr) -> "[OK]" / "[Error]: ..."
// (Encrypted) KeepAlive() -> "[OK]" / "[Error]: ..."; Error only if not authenticated
// (Encrypted) CloseSession() -> "[OK]"
// (Encrypted) FormatHotkey() -> "[OK]: hotkeyStr"

// Responses:
// (Text) publicKey
// (Text) "[ENCRYPTION ERROR]: ..."
// (Encrypted) "[OK]"
// (Encrypted) "[Error]: ..."

class HotkeyManager {
    Keyboard& keyboard;
    std::map<int, Session*> sessionMap; // Maintain life cycle of Session*
    std::unordered_map<Condition*, std::vector<Session*>> hotkeyMap; // Borrow Session*, Maintain Condition*
    Device device;
    UnixDomainSocketServer server;
    Encryptor encryptor;
    std::string passwordHash;
    std::map<std::string, std::function<std::string(int, const std::string&)>> commands;
    std::vector<int> deleteWaitlist; // Send Response and then delete session
    std::map<Session*, int64_t> lastKeepAliveTimestamps;
    std::map<int, int> pidSessionCounts;
    void execute(int clientFd, const std::string& command);
    std::string commandRegisterPublicKey(int clientFd, const std::string& args);
    std::string commandAuthenticate(int clientFd, const std::string& args);
    std::string commandRegisterHotkey(int clientFd, const std::string& args);
    std::string commandDeleteHotkey(int clientFd, const std::string& args);
    std::string commandKeepAlive(int clientFd, const std::string& args);
    std::string commandCloseSession(int clientFd, const std::string& args);
    std::string commandFormatHotkey(int clientFd, const std::string& args);
    HotkeyManager(
        const std::string& file,
        const std::string& socketPath,
        const std::string& passwordHash
    );
    void closeSession(int clientFd);
public:
    static HotkeyManager& getInstance(const std::string& configFile = "");
    ~HotkeyManager();
    void mainloop();
};

} // namespace hotkey_manager

#endif // DEAMON_MANAGER_H
