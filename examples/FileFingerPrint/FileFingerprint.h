#ifndef FILE_FINGERPRINT_H
#define FILE_FINGERPRINT_H

#include <string>
#include <fstream>
#include <sys/stat.h>
#include <cstdint>

// A lightweight file fingerprint mechanism
// Consists of a hash over a small subset of bytes, file size, and mtime
class FileFingerprint {
public:
    // Default number of bytes to hash from beginning, middle, and end
    static constexpr size_t DEFAULT_HASH_BYTES = 128;

    // Constructor
    FileFingerprint(size_t hashBytes = DEFAULT_HASH_BYTES);

    // Compute fingerprint for a file
    // Returns empty string on failure
    std::string compute(const std::string& filePath);

    // Get individual fingerprint components
    uint64_t getFileSize() const { return fileSize_; }
    time_t getMtime() const { return mtime_; }
    std::string getHash() const { return hash_; }

private:
    // Compute hash over a subset of file bytes
    std::string computeSubsetHash(std::ifstream& file);

    // Number of bytes to hash from each segment
    size_t hashBytes_;

    // Cached fingerprint components
    uint64_t fileSize_;
    time_t mtime_;
    std::string hash_;
};

#endif // FILE_FINGERPRINT_H
