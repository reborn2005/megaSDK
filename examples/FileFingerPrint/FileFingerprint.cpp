#include "FileFingerprint.h"
#include <string>
#include <fstream>
#include <sys/stat.h>
#include <cstdint>

FileFingerprint::FileFingerprint(size_t hashBytes) : hashBytes_(hashBytes) {
    fileSize_ = 0;
    mtime_ = 0;
}

std::string FileFingerprint::compute(const std::string& filePath) {
    // Get file metadata
    struct stat fileStat;
    if (stat(filePath.c_str(), &fileStat) != 0) {
        return "";
    }

    fileSize_ = fileStat.st_size;
    mtime_ = fileStat.st_mtime;

    // Open file
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }

    // Compute hash over subset of bytes
    hash_ = computeSubsetHash(file);
    file.close();

    // Format fingerprint as: hash:size:mtime
    return hash_ + ":" + std::to_string(fileSize_) + ":" + std::to_string(mtime_);
}

std::string FileFingerprint::computeSubsetHash(std::ifstream& file) {
    uint64_t hash = 0;
    size_t bytesRead = 0;

    // Read from beginning
    char buffer[256];
    size_t readSize = std::min(hashBytes_, sizeof(buffer));
    file.read(buffer, readSize);
    for (int i = 0; i < static_cast<int>(file.gcount()); ++i) {
        hash = (hash * 131) + static_cast<unsigned char>(buffer[i]);
        bytesRead++;
    }

    // Read from middle if file is large enough
    if (fileSize_ > hashBytes_ * 2) {
        file.seekg(fileSize_ / 2);
        file.read(buffer, readSize);
        for (int i = 0; i < static_cast<int>(file.gcount()); ++i) {
            hash = (hash * 131) + static_cast<unsigned char>(buffer[i]);
            bytesRead++;
        }
    }

    // Read from end
    if (fileSize_ > hashBytes_) {
        file.seekg(-static_cast<long>(hashBytes_), std::ios::end);
        file.read(buffer, readSize);
        for (int i = 0; i < static_cast<int>(file.gcount()); ++i) {
            hash = (hash * 131) + static_cast<unsigned char>(buffer[i]);
            bytesRead++;
        }
    }

    // Convert hash to hex string
    std::string hexHash;
    char hexBuffer[17];
    snprintf(hexBuffer, sizeof(hexBuffer), "%016lx", hash);
    hexHash = hexBuffer;

    return hexHash;
}
