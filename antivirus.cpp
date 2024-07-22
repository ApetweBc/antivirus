#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/md5.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <filesystem>
#include <algorithm>
#include "antivirus.h"

std::string Antivirus::calculate_md5(const std::string& file_path) {
    unsigned char c[MD5_DIGEST_LENGTH];
    std::ifstream file(file_path, std::ifstream::binary);
    if (!file) {
        std::cerr << "Unable to open file: " << file_path << std::endl;
        return "";
    }

    MD5_CTX mdContext;
    MD5_Init(&mdContext);
    char buffer[1024];
    while (file.read(buffer, sizeof(buffer))) {
        MD5_Update(&mdContext, buffer, file.gcount());
    }
    MD5_Update(&mdContext, buffer, file.gcount());
    MD5_Final(c, &mdContext);

    std::ostringstream result;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        result << std::hex << std::setw(2) << std::setfill('0') << (int)c[i];
    }

    return result.str();
}

bool Antivirus::heuristic_check(const std::string& file_content) {
    // Example heuristic: suspicious pattern (e.g., presence of suspicious keywords)
    std::vector<std::string> suspicious_patterns = { "evil", "malicious", "trojan" };
    for (const auto& pattern : suspicious_patterns) {
        if (file_content.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void Antivirus::take_action(const std::string& file_path, const std::string& action) {
    if (action == "quarantine") {
        std::filesystem::path quarantine_path = "quarantine/" + std::filesystem::path(file_path).filename().string();
        std::filesystem::create_directory("quarantine");
        std::filesystem::rename(file_path, quarantine_path);
        std::cout << "File " << file_path << " has been moved to quarantine." << std::endl;
    }
    else if (action == "delete") {
        std::filesystem::remove(file_path);
        std::cout << "File " << file_path << " has been deleted." << std::endl;
    }
}

void Antivirus::check_file(const std::string& file_path) {
    // Calculate the file's MD5 hash
    std::string file_hash = calculate_md5(file_path);

    // Check against known signatures
    if (std::find_if(known_signatures.begin(), known_signatures.end(),
        [&file_hash](const auto& pair) { return pair.second == file_hash; }) != known_signatures.end()) {
        std::cout << "File " << file_path << " identified as malicious based on signature." << std::endl;
        take_action(file_path, "quarantine");
        return;
    }

    // Perform heuristic analysis
    std::ifstream file(file_path);
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string file_content = buffer.str();

    if (heuristic_check(file_content)) {
        std::cout << "File " << file_path << " identified as suspicious based on heuristics." << std::endl;
        take_action(file_path, "quarantine");
        return;
    }

    std::cout << "File " << file_path << " is clean." << std::endl;
}
