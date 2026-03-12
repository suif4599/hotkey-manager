#include "client/interface.h"
#include "config.h"

#include "unistd.h"
#include <stdexcept>
#include <regex>
#include <algorithm>
#include <sys/prctl.h>

using namespace hotkey_manager;

namespace hotkey_manager {

HotkeyInterface::HotkeyInterface(const std::string& socketName, int64_t timeoutMs)
: callbackMap()
, eventManager()
, client(socketName, eventManager, timeoutMs)
, encryptor() {
    std::lock_guard<std::mutex> ioLock(ioMutex);
    #ifndef ALLOW_DUMP
    if (prctl(PR_SET_DUMPABLE, 0) != 0) {
        throw std::runtime_error("Failed to disable core dumps for HotkeyInterface process");
    }
    #endif
    std::string* resp = client.sendCommand("getPublicKey");
    if (!resp)
        throw std::runtime_error("Failed to receive response for command getPublicKey");
    serverPublicKey = *resp;
    delete resp;
    if (serverPublicKey.empty())
        throw std::runtime_error("Failed to get server public key");

    std::string command = "RegisterPublicKey(" + encryptor.getPublicKey() + ")";
    std::string encryptedCmd = encryptor.encrypt(command, serverPublicKey);
    std::string* response = client.sendCommand(encryptedCmd);
    if (!response)
        throw std::runtime_error("Failed to receive response for RegisterPublicKey");
    if (response->rfind("[ENCRYPTION ERROR]:", 0) == 0) {
        std::string errMsg = *response;
        delete response;
        throw std::runtime_error("Encryption error when registering public key: " + errMsg);
    }
    std::string decryptedResp = encryptor.decrypt(*response);
    delete response;
    if (decryptedResp != "[OK]")
        throw std::runtime_error("Failed to register public key: " + decryptedResp);
    // If reached here, there won't be [ENCRYPTION ERROR] anymore
}

HotkeyInterface::~HotkeyInterface() {
    std::lock_guard<std::mutex> ioLock(ioMutex);
    std::string* response = client.sendCommand(
        encryptor.encrypt("CloseSession()", serverPublicKey)
    );
    if (!response) {
        std::cerr << "[HotkeyInterface::~HotkeyInterface] Warning: No response for CloseSession" << std::endl;
        return;
    }
    std::string decryptedResp = encryptor.decrypt(*response);
    delete response;
    if (decryptedResp != "[OK]")
        std::cerr << "[HotkeyInterface::~HotkeyInterface] Warning: Failed to close session: " << decryptedResp << std::endl;
}

std::string HotkeyInterface::registerHotkey(
    const std::string& hotkeyStr,
    std::function<void()> callback,
    std::string functionId,
    bool passThrough
) {
    {
        std::lock_guard<std::mutex> callbackLock(callbackMutex);
        // Don't allow duplicate non-empty functionId
        if (!functionId.empty()) {
            auto it = callbackMap.find(hotkeyStr);
            if (it != callbackMap.end()) {
                for (const auto& [fid, cb] : it->second) {
                    if (fid == functionId)
                    throw std::runtime_error("Duplicate functionId '" + functionId + "'");
                }
            }
        }
    }

    static const std::regex hotkeyRe {"^\\[OK\\]: *(.+)$"};
    std::string command = "RegisterHotkey(" + hotkeyStr + "; " + (passThrough ? "true" : "false") + ")";
    std::string decryptedResp;
    {
        std::lock_guard<std::mutex> ioLock(ioMutex);
        std::string encryptedCmd = encryptor.encrypt(command, serverPublicKey);
        std::string* response = client.sendCommand(encryptedCmd);
        if (!response)
            throw std::runtime_error("Failed to receive response for RegisterHotkey");
        decryptedResp = encryptor.decrypt(*response);
        delete response;
    }
    if (decryptedResp.rfind("[OK]:", 0) != 0)
        throw std::runtime_error("Failed to register hotkey: " + decryptedResp);
    std::smatch match;
    if (!std::regex_match(decryptedResp, match, hotkeyRe))
        throw std::runtime_error("Invalid response format when registering hotkey");
    std::string registeredHotkeyStr = match[1];
    std::lock_guard<std::mutex> callbackLock2(callbackMutex);
    if (callbackMap.find(registeredHotkeyStr) == callbackMap.end()) {
        callbackMap[registeredHotkeyStr] = std::vector<std::pair<std::string, std::function<void()>>>();
    }
    callbackMap[registeredHotkeyStr].push_back(std::make_pair(functionId, callback));
    return registeredHotkeyStr;
}

void HotkeyInterface::deleteHotkey(const std::string& hotkeyStr) {
    std::string formatedHotkeyStr = formatHotkey(hotkeyStr);
    {
        std::lock_guard<std::mutex> callbackLock(callbackMutex);
        auto it = callbackMap.find(formatedHotkeyStr);
        if (it == callbackMap.end())
            return; // callback not found(Maybe already deleted)
    }
    std::string command = "DeleteHotkey(" + hotkeyStr + ")";
    std::string decryptedResp;
    {
        std::lock_guard<std::mutex> ioLock(ioMutex);
        std::string encryptedCmd = encryptor.encrypt(command, serverPublicKey);
        std::string* response = client.sendCommand(encryptedCmd);
        if (!response)
            throw std::runtime_error("Failed to receive response for DeleteHotkey");
        decryptedResp = encryptor.decrypt(*response);
        delete response;
    }
    if (decryptedResp != "[OK]")
        throw std::runtime_error("Failed to delete hotkey: " + decryptedResp);
    std::lock_guard<std::mutex> callbackLock(callbackMutex);
    callbackMap.erase(formatedHotkeyStr);
}

void HotkeyInterface::deleteCallback(std::string functionId) {
    if (functionId.empty())
        throw std::runtime_error("FunctionId cannot be empty to specify a callback");
    std::string hotkeyNeedDelete;
    bool found = false;
    bool needDeleteHotkey = false;
    {
        std::lock_guard<std::mutex> callbackLock(callbackMutex);
        for (auto it = callbackMap.begin(); it != callbackMap.end(); ++it) {
            auto& vec = it->second;
            auto vecIt = std::remove_if(vec.begin(), vec.end(),
                [&functionId](const auto& pair) {
                    return pair.first == functionId;
                }
            );
            if (vecIt != vec.end()) {
                found = true;
                vec.erase(vecIt, vec.end());
                if (vec.empty()) {
                    hotkeyNeedDelete = it->first;
                    needDeleteHotkey = true;
                }
                break;
            }
        }
    }
    if (!found)
        throw std::runtime_error("No callback found with functionId: " + functionId);
    if (!needDeleteHotkey)
        return;

    std::string command = "DeleteHotkey(" + hotkeyNeedDelete + ")";
    std::string decryptedResp;
    {
        std::lock_guard<std::mutex> ioLock(ioMutex);
        std::string encryptedCmd = encryptor.encrypt(command, serverPublicKey);
        std::string* response = client.sendCommand(encryptedCmd);
        if (!response)
            throw std::runtime_error("Failed to receive response for DeleteHotkey");
        decryptedResp = encryptor.decrypt(*response);
        delete response;
    }
    if (decryptedResp != "[OK]")
        throw std::runtime_error("Failed to delete hotkey: " + decryptedResp);

    std::lock_guard<std::mutex> callbackLock(callbackMutex);
    callbackMap.erase(hotkeyNeedDelete);
}

void HotkeyInterface::authenticate(const std::string& password) {
    pid_t pid = getpid();
    uid_t uid = getuid();
    gid_t gid = getgid();
    std::string processInfo = std::to_string(pid) + ":" + std::to_string(uid) + ":" + std::to_string(gid);
    std::string command = "Authenticate(" + password + "," + processInfo + ")";
    std::string decryptedResp;
    {
        std::lock_guard<std::mutex> ioLock(ioMutex);
        std::string encryptedCmd = encryptor.encrypt(command, serverPublicKey);
        std::string* response = client.sendCommand(encryptedCmd);
        if (!response)
            throw std::runtime_error("Failed to receive response for Authenticate");
        decryptedResp = encryptor.decrypt(*response);
        delete response;
    }
    if (decryptedResp != "[OK]")
        throw std::runtime_error("Authentication failed: " + decryptedResp);
}

std::string HotkeyInterface::formatHotkey(const std::string& hotkeyStr) {
    static const std::regex keyRe {"^\\[OK\\]: *(.+)$"};
    std::string command = "FormatHotkey(" + hotkeyStr + ")";
    std::string decryptedResp;
    {
        std::lock_guard<std::mutex> ioLock(ioMutex);
        std::string encryptedCmd = encryptor.encrypt(command, serverPublicKey);
        std::string* response = client.sendCommand(encryptedCmd);
        if (!response)
            throw std::runtime_error("Failed to receive response for FormatHotkey");
        decryptedResp = encryptor.decrypt(*response);
        delete response;
    }
    std::smatch match;
    if (std::regex_search(decryptedResp, match, keyRe)) {
        std::string result = match[1];
        return result;
    }
    throw std::runtime_error("Failed to format hotkey: " + decryptedResp);
}

void HotkeyInterface::inject(const std::string& key, const std::string& action, int beforeMs, int afterMs, bool block) {
    std::string command = (block ? "Inject(/" : "Inject(") + (action.empty() ? "" : action + ":") + key + ", " + std::to_string(beforeMs) + ", " + std::to_string(afterMs) + ")";
    std::string decryptedResp;
    {
        std::lock_guard<std::mutex> ioLock(ioMutex);
        std::string encryptedCmd = encryptor.encrypt(command, serverPublicKey);
        std::string* response = client.sendCommand(encryptedCmd);
        if (!response)
            throw std::runtime_error("Failed to receive response for Inject");
        decryptedResp = encryptor.decrypt(*response);
        delete response;
    }
    if (decryptedResp != "[OK]")
        throw std::runtime_error("Failed to inject key: " + decryptedResp);
}


void HotkeyInterface::mainloop(std::function<bool()> keepRunning) {
    static const std::regex hotkeyRe {"^\\[HOTKEY\\]: *(.+)$"};
    int64_t lastKeepAliveTime = 0;
    while (true) {
        // Handle all pending responses
        bool handledResponse = false;
        try {
            eventManager.wait(100);
            while (true) {
                std::string decryptedResp;
                {
                    std::lock_guard<std::mutex> ioLock(ioMutex);
                    std::string* response = client.receiveResponse();
                    if (!response)
                        break;
                    handledResponse = true;
                    if (response->rfind("[ENCRYPTION ERROR]:", 0) == 0) {
                        std::cerr << "[HotkeyInterface::mainloop] Error: " << *response << std::endl;
                        delete response;
                        continue;
                    }
                    if (response->rfind("[Error]:", 0) == 0) {
                        std::cerr << "[HotkeyInterface::mainloop] Server returned error: " << *response << std::endl;
                        delete response;
                        continue;
                    }
                    decryptedResp = encryptor.decrypt(*response);
                    delete response;
                }
                std::smatch match;
                if (std::regex_match(decryptedResp, match, hotkeyRe)) {
                    std::string hotkeyStr = match[1];
                    std::vector<std::pair<std::string, std::function<void()>>> callbacks;
                    {
                        std::lock_guard<std::mutex> callbackLock(callbackMutex);
                        auto it = callbackMap.find(hotkeyStr);
                        if (it != callbackMap.end()) {
                            callbacks = it->second;
                        }
                    }
                    if (!callbacks.empty()) {
                        for (auto& [fid, callback] : callbacks) {
                            callback();
                        }
                    } else {
                        std::cerr << "[HotkeyInterface::mainloop] Warning: No callback registered for hotkey " << hotkeyStr << std::endl;
                    }
                } else {
                    std::cerr << "[HotkeyInterface::mainloop] Warning: Unknown response from server: " << decryptedResp << std::endl;
                }
            }
        } catch (const std::exception& e) {
            std::string errMsg = e.what();
            if (errMsg == "Connection closed by server")
                throw; // Fatal error, rethrow
            std::cerr << "[HotkeyInterface::mainloop] Exception: " << e.what() << std::endl;
        }

        // Send KeepAlive
        int64_t currentTime = getTimestampMs();
        try {
            if (currentTime - lastKeepAliveTime >= KEEP_ALIVE_TIME / 2) {
                std::string command = "KeepAlive()";
                std::string decryptedResp;
                std::lock_guard<std::mutex> ioLock(ioMutex);
                std::string encryptedCmd = encryptor.encrypt(command, serverPublicKey);
                std::string* response = client.sendCommand(encryptedCmd);
                if (!response) {
                    std::cerr << "[HotkeyInterface::mainloop] Error: No response for KeepAlive" << std::endl;
                    continue;
                }
                decryptedResp = encryptor.decrypt(*response);
                delete response;
                if (decryptedResp != "[OK]") {
                    std::cerr << "[HotkeyInterface::mainloop] Error: KeepAlive failed: " << decryptedResp << std::endl;
                    continue;
                }
                lastKeepAliveTime = currentTime;
            }
        } catch (const std::exception& e) {
            std::cerr << "[HotkeyInterface::mainloop] Exception during KeepAlive: " << e.what() << std::endl;
        }

        // Check whether to exit
        if (!keepRunning())
            break;
    }
}

const decltype(HotkeyInterface::callbackMap)& HotkeyInterface::getCallbacks() const {
    return callbackMap;
}

} // namespace hotkey_manager
