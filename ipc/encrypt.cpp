#include "ipc/encrypt.h"

#include <stdexcept>

using namespace hotkey_manager;

namespace hotkey_manager {

Encryptor::Encryptor() {
    if (sodium_init() == -1)
        throw std::runtime_error("Failed to initialize libsodium");
    crypto_box_keypair(publicKey, secretKey);
}

std::string Encryptor::encrypt(const std::string& message, const std::string recipientPublicKey) {
    if (recipientPublicKey.empty())
        return "[ENCRYPTION ERROR]: Recipient public key is empty";
    if (recipientPublicKey.size() != crypto_box_PUBLICKEYBYTES)
        throw std::invalid_argument("Recipient public key has invalid size");

    std::string ciphertext(crypto_box_SEALBYTES + message.size(), '\0');
    if (crypto_box_seal(
            reinterpret_cast<unsigned char*>(ciphertext.data()),
            reinterpret_cast<const unsigned char*>(message.data()),
            static_cast<unsigned long long>(message.size()),
            reinterpret_cast<const unsigned char*>(recipientPublicKey.data())
        ) != 0)
        throw std::runtime_error("Encryption failed");

    return ciphertext;
}

std::string Encryptor::decrypt(const std::string& ciphertext) {
    if (ciphertext.rfind("[ENCRYPTION ERROR]:", 0) == 0)
        return ciphertext;
    if (ciphertext.size() < crypto_box_SEALBYTES)
        throw std::invalid_argument("Ciphertext too short");

    std::string plaintext(ciphertext.size() - crypto_box_SEALBYTES, '\0');
    if (crypto_box_seal_open(
            reinterpret_cast<unsigned char*>(plaintext.data()),
            reinterpret_cast<const unsigned char*>(ciphertext.data()),
            static_cast<unsigned long long>(ciphertext.size()),
            publicKey,
            secretKey
        ) != 0)
        throw std::runtime_error("Decryption failed");

    return plaintext;
}

std::string Encryptor::getPublicKey() const {
    return std::string(reinterpret_cast<const char*>(publicKey), crypto_box_PUBLICKEYBYTES);
}

std::string Encryptor::hashPassword(const std::string& password) {
    std::string hash(crypto_pwhash_STRBYTES, '\0');
    if (crypto_pwhash_str(
            reinterpret_cast<char*>(hash.data()),
            password.c_str(),
            static_cast<unsigned long long>(password.size()),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        ) != 0)
        throw std::runtime_error("Password hashing failed");
    return hash;
}

bool Encryptor::verifyPassword(const std::string& password,
                               const std::string& storedHash) {
    return crypto_pwhash_str_verify(
        storedHash.c_str(),
        password.c_str(),
        static_cast<unsigned long long>(password.size())
    ) == 0;
}

} // namespace hotkey_manager
