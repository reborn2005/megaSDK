#include "FileCopyDecision.h"
#include <fstream>
#include <memory>

FileCopyDecision::FileCopyDecision() {
    fingerprint_.reset(new FileFingerprint());
}

bool FileCopyDecision::compareFingerprints(const std::string& localFilePath, 
                                          const std::string& fingerprint) const {
    // Compute local fingerprint
    std::string localFingerprint = fingerprint_->compute(localFilePath);
    if (localFingerprint.empty()) {
        return false;
    }

    // Compare fingerprints
    return localFingerprint == fingerprint;
}

bool FileCopyDecision::shouldCopyInsteadOfUpload(const std::string& localFilePath,
                                                const EncryptionCredentials& remoteCredentials,
                                                const std::string& remoteMAC) {
    // Read local file content
    std::vector<uint8_t> localFileContent;
    if (!readFile(localFilePath, localFileContent)) {
        return false;
    }

    // Create AES handler with remote credentials
    AESHandler aesHandler(remoteCredentials.key.data(), remoteCredentials.key.size(),
                         remoteCredentials.nonce.data(), remoteCredentials.nonce.size());

    // Encrypt local file and compute MAC using remote credentials
    std::vector<uint8_t> encryptedData;
    std::vector<uint8_t> computedMAC;

    if (!aesHandler.encryptAndComputeMAC(localFileContent, encryptedData, computedMAC)) {
        return false;
    }

    // Convert computed MAC to string
    localMAC_ = macToString(computedMAC);

    // Compare MACs
    return localMAC_ == remoteMAC;
}

bool FileCopyDecision::readFile(const std::string& filePath, std::vector<uint8_t>& buffer) const {
    // Open file
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return false;
    }

    // Get file size
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read file content
    buffer.resize(fileSize);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

    return static_cast<size_t>(file.gcount()) == fileSize;
}

std::string FileCopyDecision::macToString(const std::vector<uint8_t>& mac) const {
    // Convert MAC to hex string
    std::string result;
    result.reserve(mac.size() * 2);
    const char hexDigits[] = "0123456789ABCDEF";

    for (uint8_t byte : mac) {
        result.push_back(hexDigits[byte >> 4]);
        result.push_back(hexDigits[byte & 0xF]);
    }

    return result;
}
