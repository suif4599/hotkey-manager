#ifndef DEAMON_SESSION_H
#define DEAMON_SESSION_H

#include "ipc/uds.h"

namespace hotkey_manager {

class Session {
    ClientInfo* clientInfo;
    std::string publicKey;
    bool authenticated;
public:
    Session();
    explicit Session(ClientInfo* info);
    bool checkProcessInfo(const std::string& processInfo) const;
    bool setPublicKey(const std::string& key);
    void authenticate();
    bool isAuthenticated() const;
    int getFd() const;
    std::string getPublicKey() const;
    int getPid() const;
};

} // namespace hotkey_manager


#endif // DEAMON_SESSION_H
