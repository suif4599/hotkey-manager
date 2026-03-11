#include "daemon/session.h"

#include <sodium.h>
#include <stdexcept>

using namespace hotkey_manager;

namespace hotkey_manager {

Session::Session() {
    throw std::runtime_error("Default constructor not allowed");
}

Session::Session(const ClientInfo& info)
: fd(info.getFd())
, processInfo(info.getProcessInfo())
, publicKey()
, authenticated(false)
, allowInject(false) {}

bool Session::checkProcessInfo(const std::string& processInfo) const {
    return this->processInfo == processInfo;
}

bool Session::setPublicKey(const std::string& key) {
    if (key.size() != crypto_box_PUBLICKEYBYTES)
        return false;
    publicKey = key;
    return true;
}

void Session::authenticate(bool allowInject) {
    authenticated = true;
    this->allowInject = allowInject;
}

bool Session::isAuthenticated() const {
    return authenticated;
}

bool Session::canInject() const {
    return allowInject;
}

int Session::getFd() const {
    return fd;
}

std::string Session::getPublicKey() const {
    return publicKey;
}

int Session::getPid() const {
    return std::stoi(processInfo.substr(0, processInfo.find(':')));
}

} // namespace hotkey_manager
