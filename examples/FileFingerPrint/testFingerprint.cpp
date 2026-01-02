#include "FileFingerprint.h"
#include "AESHandler.h"
#include "FileCopyDecision.h"
#include <iostream>
#include <fstream>
#include <string>

// Create a test file
bool createTestFile(const std::string& filePath, const std::string& content) {
    std::ofstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Failed to create test file: " << filePath << std::endl;
        return false;
    }
    file << content;
    file.close();
    return true;
}

int main() {
    std::cout << "=== File Fingerprint and Secure Copy Test ===\n";

    // Create test file
    const std::string testFilePath = "/tmp/test_file.txt";
    const std::string testContent = "This is a test file for fingerprinting and secure copying.";
    
    if (!createTestFile(testFilePath, testContent)) {
        return 1;
    }
    
    std::cout << "✓ Test file created: " << testFilePath << std::endl;

    // Step 1: Compute file fingerprint
    FileFingerprint fingerprint;
    std::string fileFingerprint = fingerprint.compute(testFilePath);
    
    if (fileFingerprint.empty()) {
        std::cerr << "✗ Failed to compute file fingerprint." << std::endl;
        return 1;
    }
    
    std::cout << "✓ File fingerprint computed: " << fileFingerprint << std::endl;
    std::cout << "  - Hash: " << fingerprint.getHash() << std::endl;
    std::cout << "  - Size: " << fingerprint.getFileSize() << " bytes" << std::endl;
    std::cout << "  - Mtime: " << fingerprint.getMtime() << std::endl;

    // Step 2: Simulate remote file with matching fingerprint
    std::cout << "\n=== Simulating Remote File with Matching Fingerprint ===\n";
    
    // Simulate encryption credentials (in real scenario, these would come from the remote)
    const uint8_t mockKey[AESHandler::AES_KEY_SIZE] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                                      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    const uint8_t mockNonce[AESHandler::NONCE_SIZE] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                                      0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

    // Create encryption credentials
    EncryptionCredentials remoteCreds;
    remoteCreds.key.assign(mockKey, mockKey + AESHandler::AES_KEY_SIZE);
    remoteCreds.nonce.assign(mockNonce, mockNonce + AESHandler::NONCE_SIZE);

    // Step 3: Create AES handler with remote credentials and encrypt test file
    AESHandler aesHandler(mockKey, AESHandler::AES_KEY_SIZE, mockNonce, AESHandler::NONCE_SIZE);
    
    // Read test file content
    std::ifstream file(testFilePath, std::ios::binary);
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> fileContent(fileSize);
    file.read(reinterpret_cast<char*>(fileContent.data()), fileSize);
    file.close();

    // Encrypt and compute MAC (simulating remote file's MAC)
    std::vector<uint8_t> encryptedData;
    std::vector<uint8_t> remoteMAC;
    aesHandler.encryptAndComputeMAC(fileContent, encryptedData, remoteMAC);
    
    std::string remoteMACStr;
    for (uint8_t byte : remoteMAC) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02X", byte);
        remoteMACStr += hex;
    }
    
    std::cout << "✓ Remote file MAC (simulated): " << remoteMACStr << std::endl;

    // Step 4: Make copy/upload decision
    std::cout << "\n=== Making Copy/Upload Decision ===\n";
    FileCopyDecision decision;
    
    bool shouldCopy = decision.shouldCopyInsteadOfUpload(testFilePath, remoteCreds, remoteMACStr);
    
    if (shouldCopy) {
        std::cout << "✓ DECISION: COPY - Local file matches remote file (MACs match)." << std::endl;
        std::cout << "  Local computed MAC: " << decision.getLocalMAC() << std::endl;
        std::cout << "  Remote file MAC:    " << remoteMACStr << std::endl;
        std::cout << "  Upload skipped - using remote file copy." << std::endl;
    } else {
        std::cout << "✗ DECISION: UPLOAD - Local file differs from remote file (MACs don't match)." << std::endl;
        std::cout << "  Local computed MAC: " << decision.getLocalMAC() << std::endl;
        std::cout << "  Remote file MAC:    " << remoteMACStr << std::endl;
        std::cout << "  File will be uploaded in full." << std::endl;
    }

    // Step 5: Test with modified file
    std::cout << "\n=== Testing with Modified File ===\n";
    const std::string modifiedFilePath = "/tmp/modified_file.txt";
    const std::string modifiedContent = testContent + " (modified)";
    
    if (!createTestFile(modifiedFilePath, modifiedContent)) {
        return 1;
    }
    
    bool shouldCopyModified = decision.shouldCopyInsteadOfUpload(modifiedFilePath, remoteCreds, remoteMACStr);
    
    if (shouldCopyModified) {
        std::cout << "✗ ERROR: Should not copy modified file - this indicates a bug!" << std::endl;
    } else {
        std::cout << "✓ Correctly decided to UPLOAD modified file." << std::endl;
        std::cout << "  Local computed MAC: " << decision.getLocalMAC() << std::endl;
        std::cout << "  Remote file MAC:    " << remoteMACStr << std::endl;
    }

    // Cleanup
    remove(testFilePath.c_str());
    remove(modifiedFilePath.c_str());

    std::cout << "\n=== Test Completed Successfully ===\n";
    return 0;
}
