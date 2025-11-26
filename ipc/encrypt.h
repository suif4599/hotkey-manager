#ifndef IPC_ENCRYPT_H
#define IPC_ENCRYPT_H

#include <sodium.h>
#include <string>

namespace hotkey_manager {

class Encryptor {
    unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
    unsigned char secretKey[crypto_box_SECRETKEYBYTES];
public:
    Encryptor();
    std::string encrypt(const std::string& message, const std::string recipientPublicKey);
    std::string decrypt(const std::string& ciphertext);
    std::string getPublicKey() const;
    static std::string hashPassword(const std::string& password);
    static bool verifyPassword(const std::string& password, const std::string& storedHash);
};

} // namespace hotkey_manager

#endif // IPC_ENCRYPT_H
