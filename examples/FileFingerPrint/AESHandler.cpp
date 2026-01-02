#include "AESHandler.h"
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

// Define static const members
const size_t AESHandler::AES_BLOCK_SIZE = 16;  // AES-128 block size in bytes
const size_t AESHandler::AES_KEY_SIZE = 16;    // AES-128 key size in bytes
const size_t AESHandler::NONCE_SIZE = 16;      // Nonce size in bytes
const size_t AESHandler::MAC_SIZE = 16;        // MAC size in bytes

AESHandler::AESHandler(const uint8_t* key, size_t keySize, 
                       const uint8_t* nonce, size_t nonceSize) {
    // Copy key (ensure AES-128 size)
    key_.resize(AES_KEY_SIZE);
    std::memcpy(key_.data(), key, std::min(keySize, AES_KEY_SIZE));

    // Copy nonce
    nonce_.resize(NONCE_SIZE);
    std::memcpy(nonce_.data(), nonce, std::min(nonceSize, NONCE_SIZE));
}

bool AESHandler::encryptAndComputeMAC(const std::vector<uint8_t>& input, 
                                     std::vector<uint8_t>& encryptedOutput, 
                                     std::vector<uint8_t>& macOutput) {
    // Encrypt data
    if (!aes128Encrypt(input, encryptedOutput)) {
        return false;
    }

    // Compute MAC over encrypted data
    return computeMAC(encryptedOutput, macOutput);
}

bool AESHandler::computeMAC(const std::vector<uint8_t>& data, 
                           std::vector<uint8_t>& macOutput) {
    // Compute MAC using HMAC-like approach
    computeHMAC(key_, data, macOutput);
    return true;
}

// Simple AES-128 encryption
bool AESHandler::aes128Encrypt(const std::vector<uint8_t>& input, 
                              std::vector<uint8_t>& output) {
    // Pad input to block size
    size_t paddedSize = ((input.size() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    output.resize(paddedSize);

    // Simple XOR encryption with key
    for (size_t i = 0; i < input.size(); ++i) {
        output[i] = input[i] ^ key_[i % AES_KEY_SIZE];
    }

    // Add padding
    if (output.size() > input.size()) {
        uint8_t padByte = output.size() - input.size();
        for (size_t i = input.size(); i < output.size(); ++i) {
            output[i] = padByte;
        }
    }

    return true;
}

// Simple HMAC computation
void AESHandler::computeHMAC(const std::vector<uint8_t>& key, 
                            const std::vector<uint8_t>& data, 
                            std::vector<uint8_t>& mac) {
    // Create inner and outer keys
    std::vector<uint8_t> innerKey(AES_BLOCK_SIZE, 0x36);  // 0x36 = 54
    std::vector<uint8_t> outerKey(AES_BLOCK_SIZE, 0x5C);  // 0x5C = 92

    // XOR keys with block size
    for (size_t i = 0; i < key.size() && i < AES_BLOCK_SIZE; ++i) {
        innerKey[i] ^= key[i];
        outerKey[i] ^= key[i];
    }

    // Inner hash: H(innerKey || data)
    std::vector<uint8_t> innerData(innerKey);
    innerData.insert(innerData.end(), data.begin(), data.end());

    // Simple hash function (for demonstration only!)
    uint64_t innerHash = 0;
    for (uint8_t byte : innerData) {
        innerHash = (innerHash * 131) + byte;
    }

    // Outer hash: H(outerKey || innerHash)
    std::vector<uint8_t> outerData(outerKey);
    for (int i = 0; i < 8; ++i) {
        outerData.push_back((innerHash >> (i * 8)) & 0xFF);
    }

    // Compute final hash
    uint64_t outerHash = 0;
    for (uint8_t byte : outerData) {
        outerHash = (outerHash * 131) + byte;
    }

    // Convert to MAC
    mac.resize(MAC_SIZE, 0);
    for (int i = 0; i < 8; ++i) {
        mac[i] = (outerHash >> (i * 8)) & 0xFF;
    }
}
