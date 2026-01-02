#ifndef FILE_COPY_DECISION_H
#define FILE_COPY_DECISION_H

#include "FileFingerprint.h"
#include "AESHandler.h"
#include <string>
#include <vector>
#include <memory>

// Struct to hold encryption credentials
struct EncryptionCredentials {
    std::vector<uint8_t> key;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> remoteMAC;
};

// Class to handle file copying decisions
class FileCopyDecision {
public:
    // Constructor
    FileCopyDecision();

    // Set the number of bytes to use for fingerprint hashing
    void setFingerprintHashBytes(size_t bytes) {
        fingerprint_.reset(new FileFingerprint(bytes));
    }

    // Compare file fingerprints
    bool compareFingerprints(const std::string& localFilePath, 
                            const std::string& fingerprint) const;

    // Make decision whether to copy or reupload
    // Returns true if copy is safe (MAC matches), false if reupload is needed
    bool shouldCopyInsteadOfUpload(const std::string& localFilePath,
                                  const EncryptionCredentials& remoteCredentials,
                                  const std::string& remoteMAC);

    // Get the computed MAC for the local file (valid after shouldCopyInsteadOfUpload)
    std::string getLocalMAC() const {
        return localMAC_;
    }

private:
    // Read entire file into buffer
    bool readFile(const std::string& filePath, std::vector<uint8_t>& buffer) const;

    // Convert MAC to string representation
    std::string macToString(const std::vector<uint8_t>& mac) const;

    // File fingerprint calculator
    std::unique_ptr<FileFingerprint> fingerprint_;

    // Computed MAC for local file
    std::string localMAC_;
};

#endif // FILE_COPY_DECISION_H
