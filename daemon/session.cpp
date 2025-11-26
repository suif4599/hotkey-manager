#include "daemon/session.h"

#include <sodium.h>
#include <stdexcept>

using namespace hotkey_manager;

namespace hotkey_manager {

Session::Session() {
    throw std::runtime_error("Default constructor not allowed");
}

Session::Session(ClientInfo* info)
: clientInfo(info)
, publicKey()
, authenticated(false) {}

bool Session::checkProcessInfo(const std::string& processInfo) const {
    return clientInfo->getProcessInfo() == processInfo;
}

bool Session::setPublicKey(const std::string& key) {
    if (key.size() != crypto_box_PUBLICKEYBYTES)
        return false;
    publicKey = key;
    return true;
}

void Session::authenticate() {
    authenticated = true;
}

bool Session::isAuthenticated() const {
    return authenticated;
}

int Session::getFd() const {
    return clientInfo->getFd();
}

std::string Session::getPublicKey() const {
    return publicKey;
}

int Session::getPid() const {
    return std::stoi(
        clientInfo->getProcessInfo().substr(0, clientInfo->getProcessInfo().find(':'))
    );
}

} // namespace hotkey_manager
