#include "daemon/manager.h"
#include "config.h"
#include <stdexcept>
#include <regex>
#include <fstream>
#include <filesystem>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <chrono>
#include <algorithm>
#include <memory>
#include <cerrno>
#include <cstring>
#include <system_error>

using namespace hotkey_manager;

namespace hotkey_manager {

static auto findHotkeyEntry(
    std::unordered_map<Condition*, std::vector<std::pair<Session*, bool>>>& map,
    const Condition& target
) -> decltype(map.begin()) {
    return std::find_if(
        map.begin(),
        map.end(),
        [&target](const auto& entry) {
            return *entry.first == target;
        }
    );
}

static const std::regex configRe {
    "^\\s*\\{"
    "\\s*[\"'](\\w+)[\"']: *[\"']([\\s\\S]+?)[\"'],\\s*"
    "\\s*[\"'](\\w+)[\"']: *[\"']([\\s\\S]+?)[\"'],\\s*"
    "\\s*[\"'](\\w+)[\"']: *[\"']([\\s\\S]+?)[\"'],\\s*"
    "\\s*[\"'](\\w+)[\"']: *[\"']([\\s\\S]+?)[\"'],?\\s*"
    "\\}\\s*$"
};

bool HotkeyManagerConfig::isAsciiPath(const std::string& path) {
    if (path.empty())
        return false;
    return std::all_of(path.begin(), path.end(), [](unsigned char ch) {
        return ch >= 0x20 && ch <= 0x7E;
    });
}

bool HotkeyManagerConfig::isPlainText(const std::string& content) {
    return std::all_of(content.begin(), content.end(), [](unsigned char ch) {
        return ch == '\n' || ch == '\r' || ch == '\t' || (ch >= 0x20 && ch <= 0x7E);
    });
}

void HotkeyManagerConfig::setSecurePermissions() const {
    if (chmod(configFile.c_str(), S_IRUSR | S_IWUSR) == -1)
        throw std::runtime_error(
            "Failed to set config permissions for '" + configFile + "': " + std::strerror(errno)
        );
}

void HotkeyManagerConfig::parseConfig(const std::string& content) {
    if (content.empty())
        throw std::runtime_error("Config file is empty: " + configFile);
    if (!isPlainText(content))
        throw std::runtime_error("Config file contains non-text data: " + configFile);

    std::smatch match;
    if (!std::regex_match(content, match, configRe))
        throw std::runtime_error("Invalid config file format");

    for (size_t i = 1; i < match.size(); i += 2) {
        std::string key = match[i];
        std::string value = match[i + 1];
        if (key == "deviceFile") {
            if (value == "auto")
                deviceFile = Device::autoDetectDeviceFile();
            else
                deviceFile = value;
        } else if (key == "socketPath")
            socketPath = value;
        else if (key == "passwordHash")
            passwordHash = value;
        else if (key == "keyBinding")
            keyBinding = value;
        else
            throw std::runtime_error("Unknown config key: " + key);
    }
}

void HotkeyManagerConfig::createDefaultConfig() {
    if (!isAsciiPath(configFile))
        throw std::runtime_error("Config file path must use printable ASCII characters");
    namespace fs = std::filesystem;
    fs::path path(configFile);
    fs::path parent = path.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        if (!fs::exists(parent, ec))
            throw std::runtime_error("Config parent directory does not exist: " + parent.string());
        if (ec)
            throw std::runtime_error("Failed to inspect config parent directory: " + ec.message());
    }

    std::error_code ec;
    if (fs::exists(path, ec))
        throw std::runtime_error("Config file already exists: " + configFile);
    if (ec)
        throw std::runtime_error("Failed to inspect config file path: " + ec.message());

    int fd = open(configFile.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd == -1)
        throw std::runtime_error(
            "Failed to create default config file '" + configFile + "': " + std::strerror(errno)
        );

    std::string payload {
        "{\n"
        "    \"deviceFile\": \"auto\",\n"
        "    \"socketPath\": \"/tmp/hotkey-manager.sock\",\n"
        "    \"passwordHash\": \"$argon2id$v=19$m=65536,t=2,p=1$gVhSWbbAsC+mm2QfArc/xw$5fdVpc61mjx0xkbrMVi9YCXhIcl29h3fHvZkYO4TsIU\",\n"
        "    \"keyBinding\": \"\"\n"
        "}\n"
    }; // 123456
    ssize_t written = ::write(fd, payload.data(), payload.size());
    if (written < 0 || static_cast<std::size_t>(written) != payload.size()) {
        close(fd);
        throw std::runtime_error(
            "Failed to write default config file '" + configFile + "': " + std::strerror(errno)
        );
    }
    close(fd);
    setSecurePermissions();
    syslog(LOG_INFO, "Created default config file at: %s", configFile.c_str());
}

HotkeyManagerConfig::HotkeyManagerConfig(const std::string& filePath)
    : configFile(filePath) {
    if (!isAsciiPath(configFile))
        throw std::runtime_error("Config file path must use printable ASCII characters");

    namespace fs = std::filesystem;
    std::error_code ec;
    fs::file_status status = fs::symlink_status(configFile, ec);
    if (ec)
        throw std::runtime_error("Failed to inspect config file '" + configFile + "': " + ec.message());

    if (!fs::exists(status)) {
        createDefaultConfig();
        status = fs::symlink_status(configFile, ec);
        if (ec)
            throw std::runtime_error("Failed to inspect config file after creation: " + ec.message());
    }

    if (!fs::exists(status))
        throw std::runtime_error("Config file is missing: " + configFile);
    if (fs::is_symlink(status) || !fs::is_regular_file(status))
        throw std::runtime_error("Config file must be a regular text file: " + configFile);

    std::ifstream file(configFile, std::ios::binary);
    if (!file.is_open())
        throw std::runtime_error("Failed to open config file: " + configFile);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (!file)
        throw std::runtime_error("Failed to read config file: " + configFile);

    parseConfig(content);
    setSecurePermissions();
    syslog(LOG_INFO, "Using config file: %s", configFile.c_str());
    syslog(LOG_INFO, "Config loaded: deviceFile=%s, socketPath=%s, passwordHash=%s",
            deviceFile.c_str(), socketPath.c_str(), passwordHash.c_str());
}

HotkeyManagerConfig& HotkeyManagerConfig::getInstance(const std::string& configFile) {
    static HotkeyManagerConfig instance(configFile);
    static bool initialized = false;
    if (initialized && !configFile.empty())
        throw std::runtime_error("HotkeyManagerConfig should not be initialized twice.");
    initialized = true;
    return instance;
}

std::string& HotkeyManagerConfig::operator[](const std::string& key) {
    // Setitem
    if (key == "deviceFile")
        return deviceFile;
    else if (key == "socketPath")
        return socketPath;
    else if (key == "passwordHash")
        return passwordHash;
    else if (key == "keyBinding")
        return keyBinding;
    else
        throw std::runtime_error("Unknown config key: " + key);
}

const std::string& HotkeyManagerConfig::operator[](const std::string& key) const {
    // Getitem
    if (key == "deviceFile")
        return deviceFile;
    else if (key == "socketPath")
        return socketPath;
    else if (key == "passwordHash")
        return passwordHash;
    else if (key == "keyBinding")
        return keyBinding;
    else
        throw std::runtime_error("Unknown config key: " + key);
}

void HotkeyManagerConfig::save() const {
    if (!isAsciiPath(configFile))
        throw std::runtime_error("Config file path must use printable ASCII characters");
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::file_status status = fs::symlink_status(configFile, ec);
    if (ec)
        throw std::runtime_error("Failed to inspect config file before saving: " + ec.message());
    if (!fs::exists(status) || fs::is_symlink(status) || !fs::is_regular_file(status))
        throw std::runtime_error("Config file must be an existing regular file: " + configFile);

    std::ofstream file(configFile, std::ios::out | std::ios::trunc);
    if (!file.is_open())
        throw std::runtime_error("Failed to open config file for writing");
    file << "{\n"
            << "    \"deviceFile\": \"" << deviceFile << "\",\n"
            << "    \"socketPath\": \"" << socketPath << "\",\n"
            << "    \"passwordHash\": \"" << passwordHash << "\",\n"
            << "    \"keyBinding\": \"" << keyBinding << "\"\n"
            << "}\n";
    file.close();
    if (!file)
        throw std::runtime_error("Failed to persist config file: " + configFile);
    setSecurePermissions();
    syslog(LOG_INFO, "Config saved to file: %s", configFile.c_str());
}

HotkeyManager::HotkeyManager(
    const std::string& file,
    const std::string& socketPath,
    const std::string& passwordHash,
    const std::string& keyBinding,
    bool grabDevice
): keyboard(Keyboard::getInstance())
, sessionMap()
, hotkeyMap()
, device(file, grabDevice)
, grabDevice(grabDevice)
, server(socketPath)
, encryptor()
, commands()
, deleteWaitlist()
, lastKeepAliveTimestamps()
, passwordHash(passwordHash)
, pidSessionCounts() {
    commands["RegisterPublicKey"] = [this](int clientFd, const std::string& args) {
        return commandRegisterPublicKey(clientFd, args);
    };
    commands["Authenticate"] = [this](int clientFd, const std::string& args) {
        return commandAuthenticate(clientFd, args);
    };
    commands["RegisterHotkey"] = [this](int clientFd, const std::string& args) {
        return commandRegisterHotkey(clientFd, args);
    };
    commands["DeleteHotkey"] = [this](int clientFd, const std::string& args) {
        return commandDeleteHotkey(clientFd, args);
    };
    commands["KeepAlive"] = [this](int clientFd, const std::string& args) {
        return commandKeepAlive(clientFd, args);
    };
    commands["CloseSession"] = [this](int clientFd, const std::string& args) {
        return commandCloseSession(clientFd, args);
    };
    commands["FormatHotkey"] = [this](int clinetFd, const std::string& args) {
        return commandFormatHotkey(clinetFd, args);
    };

    // Parse key bindings
    if (!keyBinding.empty()) {
        static const std::regex bindingRe(" *(\\w+)->(\\w+) *,?");
        std::sregex_iterator iter(keyBinding.begin(), keyBinding.end(), bindingRe);
        std::sregex_iterator end;
        for (; iter != end; ++iter) {
            std::string fromStr = (*iter)[1];
            std::string toStr = (*iter)[2];
            try {
                device.addKeyBinding(fromStr, toStr);
            } catch (const std::exception& e) {
                syslog(LOG_WARNING, "Failed to add key binding '%s->%s': %s",
                       fromStr.c_str(), toStr.c_str(), e.what());
            }
        }
    }
    syslog(LOG_INFO, "HotkeyManager initialized with deviceFile=%s, socketPath=%s",
        file.c_str(), socketPath.c_str());
};

void HotkeyManager::closeSession(int clientFd) {
    auto it = sessionMap.find(clientFd);
    if (it == sessionMap.end()) {
        syslog(LOG_WARNING, "Attempted to close non-existing session for clientFd=%d", clientFd);
        return;
    }
    Session* session = it->second;
    syslog(LOG_INFO, "Closing session for clientFd=%d", clientFd);
    // Decrease pidSessionCounts
    int pid = session->getPid();
    auto pidIt = pidSessionCounts.find(pid);
    if (pidIt != pidSessionCounts.end()) {
        pidIt->second--;
        if (pidIt->second <= 0) {
            pidSessionCounts.erase(pidIt);
        }
    }
    // Remove session from hotkeyMap
    for (auto& [cond, sessions] : hotkeyMap) {
        sessions.erase(
            std::remove_if(sessions.begin(), sessions.end(), [session](const std::pair<Session*, bool>& p) {
                return p.first == session;
            }),
            sessions.end()
        );
    }
    // Delete unused Conditions
    for (auto it = hotkeyMap.begin(); it != hotkeyMap.end(); ) {
        if (it->second.empty()) {
            delete it->first;
            it = hotkeyMap.erase(it);
        } else {
            ++it;
        }
    }
    // Delete last keep-alive timestamp
    lastKeepAliveTimestamps.erase(session);
    // Delete session
    sessionMap.erase(it);
    delete session;
}

HotkeyManager& HotkeyManager::getInstance(
    const std::string& configFile,
    bool grabDevice
) {
    static HotkeyManagerConfig& config = HotkeyManagerConfig::getInstance(configFile);
    static HotkeyManager instance(
        config["deviceFile"],
        config["socketPath"],
        config["passwordHash"],
        config["keyBinding"],
        grabDevice
    );
    static bool initialized = false;
    if (initialized && !configFile.empty())
        throw std::runtime_error("HotkeyManager should not be initialized twice.");
    initialized = true;
    return instance;
}

HotkeyManager::~HotkeyManager() {
    for (auto& [cond, _] : hotkeyMap)
        delete cond;
    for (auto& [fd, session] : sessionMap)
        delete session;
}

void HotkeyManager::mainloop() {
    syslog(LOG_INFO, "HotkeyManager mainloop started.");
    while (true) {
        bool updated = false;
        // Delete sessions in waitlist
        for (int clientFd : deleteWaitlist) {
            server.deleteClient(clientFd);
            closeSession(clientFd);
            updated = true;
        }
        deleteWaitlist.clear();

        // Handle new UDS events
        server.next();
        // Accept
        ClientInfo* newClient = server.getNewClient();
        if (newClient) {
            // Limit connections per process
            int pid = std::stoi(newClient->getProcessInfo().substr(0, newClient->getProcessInfo().find(':')));
            auto it = pidSessionCounts.find(pid);
            if (it == pidSessionCounts.end()) {
                pidSessionCounts[pid] = 1;
            } else {
                it->second++;
                if (it->second > MAX_CONNECTIONS_FOR_ONE_PROCESS) {
                    syslog(LOG_WARNING, "Process %d exceeded max connections (%d), rejecting new connection",
                           pid, MAX_CONNECTIONS_FOR_ONE_PROCESS);
                    server.sendResponse(
                        newClient->getFd(),
                        encryptor.encrypt("[Error]: Exceeded max connections per process", "")
                    );
                    server.deleteClient(newClient->getFd());
                    it->second--;
                    continue;
                }
            }
            sessionMap[newClient->getFd()] = new Session(newClient);
            lastKeepAliveTimestamps[sessionMap[newClient->getFd()]] = getTimestampMs();
            syslog(LOG_INFO, "New client connected: %s", newClient->getProcessInfo().c_str());
            updated = true;
        }
        // Receive
        auto [clientFd, command] = server.receiveCommand();
        if (command) {
            execute(clientFd, *command);
            delete command;
            updated = true;
        }
        // Close
        int deletedClientFd = server.getDeletedClientFd();
        if (deletedClientFd != -1)
            closeSession(deletedClientFd);

        // Handle new keyboard events
        Event* ev = device.next();
        if (!ev) {
            if (!updated)
                usleep(1000);
            continue;
        }
        keyboard.update(*ev);
        bool suppressed = false;
        for (auto& [cond, sessions] : hotkeyMap) {
            if (!keyboard.check(*cond))
                continue;
            syslog(LOG_DEBUG, "Hotkey triggered: %s", cond->to_string().c_str());
            for (auto& [session, passThrough] : sessions) {
                server.sendResponse(
                    session->getFd(),
                    encryptor.encrypt("[HOTKEY]: " + cond->to_string(), session->getPublicKey())
                );
                if (!passThrough)
                    suppressed = true;
            }
            updated = true;
        }
        if (grabDevice && !suppressed)
            device.passThroughEvent(*ev);
        delete ev;

        // Delete sessions with timeout
        int64_t lastTime = getTimestampMs() - KEEP_ALIVE_TIME;
        for (auto& [session, timestamp] : lastKeepAliveTimestamps) {
            if (timestamp > lastTime)
                continue;
            int clientFd = session->getFd();
            syslog(LOG_INFO, "Session timeout for clientFd=%d, closing session", clientFd);
            server.sendResponse(
                clientFd,
                encryptor.encrypt("[Error]: KeepAlive timeout, closing session", session->getPublicKey())
            );
            deleteWaitlist.push_back(clientFd);
            updated = true;
        }

        if (!updated)
            usleep(1000);
    }
}

void HotkeyManager::execute(int clientFd, const std::string& command) {
    static const std::regex parserRe {"^(\\w+)\\(([\\s\\S]*)\\)$"};
    syslog(LOG_DEBUG, "Executing command from clientFd=%d: %s", clientFd, command.c_str());
    if (command == "getPublicKey") {
        server.sendResponse(clientFd, encryptor.getPublicKey());
        return;
    }

    std::string decryptedCmd = encryptor.decrypt(command);
    std::smatch match;
    if (!std::regex_match(decryptedCmd, match, parserRe))
        server.sendResponse(
            clientFd,
            encryptor.encrypt(
                "[Error]: Invalid command format '" + decryptedCmd + "'",
                sessionMap[clientFd]->getPublicKey()
            )
        );
    std::string cmdName = match[1];
    std::string cmdArgs = match[2];

    auto it = commands.find(cmdName);
    if (it != commands.end()) {
        std::string response = it->second(clientFd, cmdArgs);
        server.sendResponse(
            clientFd,
            encryptor.encrypt(response, sessionMap[clientFd]->getPublicKey())
        );
    } else {
        server.sendResponse(
            clientFd,
            encryptor.encrypt("[Error]: Unknown command: " + cmdName, sessionMap[clientFd]->getPublicKey())
        );
        syslog(LOG_NOTICE, "Unknown command from clientFd=%d: %s", clientFd, cmdName.c_str());
    }
}

std::string HotkeyManager::commandRegisterPublicKey(int clientFd, const std::string& args) {
    syslog(LOG_DEBUG, "Registering public key for clientFd=%d, publicKey=%s", clientFd, args.c_str());
    if (sessionMap[clientFd]->setPublicKey(args))
        return "[OK]";
    syslog(LOG_NOTICE, "Failed to register public key for clientFd=%d. Invalid public key size", clientFd);
    return "[Error]: Invalid public key size";
}

std::string HotkeyManager::commandAuthenticate(int clientFd, const std::string& args) {
    static const std::regex authRe {"^(.+), *([0-9:]+)$"};
    syslog(LOG_DEBUG, "Authenticating clientFd=%d with args=%s", clientFd, args.c_str());
    std::smatch match;
    if (!std::regex_match(args, match, authRe)) {
        syslog(LOG_NOTICE, "Invalid authenticate arguments from clientFd=%d: %s", clientFd, args.c_str());
        return "[Error]: Invalid authenticate arguments, expected format Authenticate(<passward>; <pid>:<uid>:<gid>)";
    }

    std::string hash = match[1];
    std::string processInfo = match[2];
    if (sessionMap[clientFd]->isAuthenticated()) {
        syslog(LOG_NOTICE, "ClientFd=%d is already authenticated", clientFd);
        return "[Error]: Already authenticated";
    }
    if (!sessionMap[clientFd]->checkProcessInfo(processInfo)) {
        syslog(LOG_WARNING, "Process info mismatch for clientFd=%d: got %s",
               clientFd, processInfo.c_str());
        return "[Error]: Process info mismatch";
    }
    if (!Encryptor::verifyPassword(hash, passwordHash)) {
        syslog(LOG_NOTICE, "Authentication failed for clientFd=%d", clientFd);
        return "[Error]: Authentication failed";
    }
    sessionMap[clientFd]->authenticate();
    return "[OK]";
}

std::string HotkeyManager::commandRegisterHotkey(int clientFd, const std::string& args) {
    static const std::regex hotkeyRe {"^(.+); *(true|false)$"};
    if (!sessionMap[clientFd]->isAuthenticated()) {
        syslog(LOG_NOTICE, "ClientFd=%d attempted to register hotkey without authentication", clientFd);
        deleteWaitlist.push_back(clientFd);
        return "[Error]: Not authenticated";
    }

    syslog(LOG_INFO, "Registering hotkey for clientFd=%d with condition: %s", clientFd, args.c_str());
    try {
        std::smatch match;
        if (!std::regex_match(args, match, hotkeyRe)) {
            syslog(LOG_NOTICE, "Invalid hotkey registration arguments from clientFd=%d: %s", clientFd, args.c_str());
            return "[Error]: Invalid hotkey registration arguments, expected format RegisterHotkey(<conditionStr>; <true/false>)";
        }
        bool passThrough = (match[2] == "true");

        std::unique_ptr<Condition> parsedCond(new Condition(Condition::from_string(match[1])));
        auto it = findHotkeyEntry(hotkeyMap, *parsedCond);

        if (it == hotkeyMap.end()) {
            Condition* storedCond = parsedCond.release();
            auto insertResult = hotkeyMap.emplace(storedCond, std::vector<std::pair<Session*, bool>>());
            it = insertResult.first;
        }

        auto* session = sessionMap[clientFd];
        auto& sessions = it->second;
        auto itSession = std::find_if(
            sessions.begin(),
            sessions.end(),
            [session](const std::pair<Session*, bool>& p) {
                return p.first == session;
            }
        );
        if (itSession != sessions.end()) {
            return "[OK]: " + it->first->to_string();
        }

        sessions.push_back(std::make_pair(session, passThrough));
        return "[OK]: " + it->first->to_string();
    } catch (const std::exception& e) {
        syslog(LOG_NOTICE, "Failed to register hotkey for clientFd=%d: %s", clientFd, e.what());
        return std::string("[Error]: Failed to register hotkey: ") + e.what();
    }
}

std::string HotkeyManager::commandDeleteHotkey(int clientFd, const std::string& args) {
    if (!sessionMap[clientFd]->isAuthenticated()) {
        syslog(LOG_NOTICE, "ClientFd=%d attempted to delete hotkey without authentication", clientFd);
        deleteWaitlist.push_back(clientFd);
        return "[Error]: Not authenticated";
    }

    syslog(LOG_INFO, "Deleting hotkey for clientFd=%d with hotkeyStr: %s", clientFd, args.c_str());
    try {
        std::unique_ptr<Condition> parsedCond(new Condition(Condition::from_string(args)));
        auto it = findHotkeyEntry(hotkeyMap, *parsedCond);
        if (it == hotkeyMap.end()) {
            return "[Error]: Hotkey not found";
        }
        auto& sessions = it->second;
        sessions.erase(
            std::remove_if(
                sessions.begin(),
                sessions.end(),
                [this, clientFd](const std::pair<Session*, bool>& p) {
                    return p.first == sessionMap[clientFd];
                }
            ),
            sessions.end()
        );
        // Delete unused Conditions
        if (sessions.empty()) {
            Condition* storedCond = it->first;
            hotkeyMap.erase(it);
            delete storedCond;
        }
        return "[OK]";
    } catch (const std::exception& e) {
        syslog(LOG_NOTICE, "Failed to delete hotkey for clientFd=%d: %s", clientFd, e.what());
        return std::string("[Error]: Failed to delete hotkey: ") + e.what();
    }
}

std::string HotkeyManager::commandKeepAlive(int clientFd, const std::string& args) {
    if (!sessionMap[clientFd]->isAuthenticated()) {
        syslog(LOG_NOTICE, "ClientFd=%d attempted to send KeepAlive without authentication", clientFd);
        deleteWaitlist.push_back(clientFd);
        return "[Error]: Not authenticated";
    }
    lastKeepAliveTimestamps[sessionMap[clientFd]] = getTimestampMs();
    syslog(LOG_DEBUG, "Received KeepAlive from clientFd=%d", clientFd);
    return "[OK]";
}

std::string HotkeyManager::commandCloseSession(int clientFd, const std::string& args) {
    syslog(LOG_INFO, "ClientFd=%d requested to close session", clientFd);
    if (std::find(deleteWaitlist.begin(), deleteWaitlist.end(), clientFd) == deleteWaitlist.end())
        deleteWaitlist.push_back(clientFd);
    return "[OK]";
}

std::string HotkeyManager::commandFormatHotkey(int clientFd, const std::string& args) {
    if (!sessionMap[clientFd]->isAuthenticated()) {
        syslog(LOG_NOTICE, "ClientFd=%d attempted to send FormatHotkey without authentication", clientFd);
        deleteWaitlist.push_back(clientFd);
        return "[Error]: Not authenticated";
    }
    try {
        std::string hotkeyStr = Condition::from_string(args).to_string();
        return "[OK]: " + hotkeyStr;
    } catch (const std::exception& e) {
        syslog(LOG_NOTICE, "Failed to format hotkey for clientFd=%d: %s", clientFd, e.what());
        return std::string("[Error]: Invalid hotkey format: ") + e.what();
    }
}

} // namespace hotkey_manager

