#ifndef DEAMON_MANAGER_H
#define DEAMON_MANAGER_H

#include "config.h"
#include "daemon/keyboard.h"
#include "daemon/device.h"
#include "daemon/condition.h"
#include "daemon/session.h"
#include "daemon/notification.h"
#include "ipc/uds.h"
#include "ipc/encrypt.h"

#include <sodium.h>
#include <vector>
#include <string>
#include <map>
#include <unordered_map>
#include <functional>
#include <memory>

namespace hotkey_manager {

// Commands:
// (Text) getPublicKey -> publicKey
// (Encrypted) RegisterPublicKey(publicKey) -> "[OK]"
// (Encrypted) Authenticate(passward, pid:uid:gid) -> "[OK]" / "[Error]: ..."
// (Encrypted) RegisterHotkey(conditionStr; true/false) -> "[OK]: hotkeyStr" / "[Error]: ..."; Allow Reregistering same hotkey
// (Encrypted) DeleteHotkey(hotkeyStr) -> "[OK]" / "[Error]: ..."
// (Encrypted) KeepAlive() -> "[OK]" / "[Error]: ..."; Error only if not authenticated
// (Encrypted) CloseSession() -> "[OK]"
// (Encrypted) FormatHotkey() -> "[OK]: hotkeyStr"

// Responses:
// (Text) publicKey
// (Text) "[ENCRYPTION ERROR]: ..."
// (Encrypted) "[OK]"
// (Encrypted) "[Error]: ..."

class HotkeyManagerConfig {
    std::string configFile;
    std::string deviceFile;
    std::string socketName;
    std::string passwordHash;
    std::string keyBinding;
    std::string gamemodeHotkey;
    static bool isAsciiPath(const std::string& path);
    static bool isPlainText(const std::string& content);
    void setSecurePermissions() const;
    void parseConfig(const std::string& content);
    void createDefaultConfig();
    HotkeyManagerConfig(const std::string& filePath);
public:
    HotkeyManagerConfig(const HotkeyManagerConfig&) = delete;
    HotkeyManagerConfig& operator=(const HotkeyManagerConfig&) = delete;
    HotkeyManagerConfig(HotkeyManagerConfig&&) = delete;
    HotkeyManagerConfig& operator=(HotkeyManagerConfig&&) = delete;

    static HotkeyManagerConfig& getInstance(const std::string& configFile = "");
    static void resetToDefault(const std::string& configFile = CONFIG_FILE_PATH);
    std::string& operator[](const std::string& key);
    const std::string& operator[](const std::string& key) const;
    void save() const;
};

class HotkeyManager {
    std::map<int, Session*> sessionMap; // Maintain life cycle of Session*
    std::unordered_map<Condition*, std::vector<std::pair<Session*, bool>>> hotkeyMap; // Borrow Session*, Maintain Condition*
    EventManager eventManager;
    std::vector<std::unique_ptr<Device>> devices;
    bool grabDevice;
    int gamemode; // 0: Off(default), 1: On(ignore), 2: On(bypass)
    key_t gamemodeKey;
    bool gamemodeKeyDown;
    std::string gamemodeHotkey;
    int internalClientFd;
    std::unique_ptr<ClientInfo> internalClientInfo;
    Session* internalSession;
    UnixDomainSocketServer server;
    Encryptor encryptor;
    std::string passwordHash;
    std::map<std::string, std::function<std::string(int, const std::string&)>> commands;
    std::vector<int> deleteWaitlist; // Send Response and then delete session
    std::map<Session*, int64_t> lastKeepAliveTimestamps;
    std::map<int, int> pidSessionCounts;
    NotificationManager notificationManager;
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
        const std::string& socketName,
        const std::string& passwordHash,
        const std::string& gamemodeHotkey,
        const std::string& keyBinding,
        bool grabDevice
    );
    void closeSession(int clientFd);
public:
    HotkeyManager(const HotkeyManager&) = delete;
    HotkeyManager& operator=(const HotkeyManager&) = delete;
    HotkeyManager(HotkeyManager&&) = delete;
    HotkeyManager& operator=(HotkeyManager&&) = delete;

    static HotkeyManager& getInstance(
        const std::string& configFile = "",
        bool grabDevice = false
    );
    ~HotkeyManager();
    void mainloop();
};

} // namespace hotkey_manager

#endif // DEAMON_MANAGER_H
