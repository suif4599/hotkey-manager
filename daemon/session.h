#ifndef DEAMON_SESSION_H
#define DEAMON_SESSION_H

#include "ipc/uds.h"

namespace hotkey_manager {

class Session {
    int fd;
    std::string processInfo;
    std::string publicKey;
    bool authenticated;
    bool allowInject;
public:
    Session();
    explicit Session(const ClientInfo& info);
    bool checkProcessInfo(const std::string& processInfo) const;
    bool setPublicKey(const std::string& key);
    void authenticate(bool allowInject = false);
    bool isAuthenticated() const;
    bool canInject() const;
    int getFd() const;
    std::string getPublicKey() const;
    int getPid() const;
};

} // namespace hotkey_manager


#endif // DEAMON_SESSION_H
