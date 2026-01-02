#ifndef AES_HANDLER_H
#define AES_HANDLER_H

#include <string>
#include <vector>
#include <cstdint>

// AES-128 encryption handler
class AESHandler {
public:
    static const size_t AES_BLOCK_SIZE;  // AES-128 block size in bytes
    static const size_t AES_KEY_SIZE;    // AES-128 key size in bytes
    static const size_t NONCE_SIZE;      // Nonce size in bytes
    static const size_t MAC_SIZE;        // MAC size in bytes

    // Constructor with existing encryption credentials
    AESHandler(const uint8_t* key, size_t keySize, 
               const uint8_t* nonce, size_t nonceSize);

    // Encrypt data and compute MAC
    bool encryptAndComputeMAC(const std::vector<uint8_t>& input, 
                             std::vector<uint8_t>& encryptedOutput, 
                             std::vector<uint8_t>& macOutput);

    // Compute MAC for data using existing encryption context
    bool computeMAC(const std::vector<uint8_t>& data, 
                   std::vector<uint8_t>& macOutput);

private:
    // Simple AES-128 encryption (for demonstration purposes)
    // In real implementation, use a secure cryptographic library like OpenSSL
    bool aes128Encrypt(const std::vector<uint8_t>& input, 
                      std::vector<uint8_t>& output);

    // Simple MAC computation (HMAC-like)
    void computeHMAC(const std::vector<uint8_t>& key, 
                    const std::vector<uint8_t>& data, 
                    std::vector<uint8_t>& mac);

    // Encryption credentials
    std::vector<uint8_t> key_;
    std::vector<uint8_t> nonce_;
};

#endif // AES_HANDLER_H
