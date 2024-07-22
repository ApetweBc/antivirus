#ifndef ANTIVIRUS_H
#define ANTIVIRUS_H

#include <string>
#include <unordered_map>

class Antivirus {
public:
    void check_file(const std::string& file_path);
    std::string calculate_md5(const std::string& file_path);
    bool heuristic_check(const std::string& file_content);
    void take_action(const std::string& file_path, const std::string& action);

    // Define known malicious signatures (hashes)
    std::unordered_map<std::string, std::string> known_signatures = {
        {"malware1", "5d41402abc4b2a76b9719d911017c592"},  // Example hash
        {"malware2", "d41d8cd98f00b204e9800998ecf8427e"}   // Example hash
    };
};

#endif // ANTIVIRUS_H
