#include "main.h"
#include "antivirus.h"
#include <vector>
#include <filesystem>
#include <iostream>

using namespace std;

int main() {

    Antivirus av;

    // List of files to scan
    std::vector<std::string> files_to_scan = { "C:\\Cplus\\antivirus\\antivirus\\testfile1.txt",
		"C:\\Cplus\\antivirus\\antivirus\\testfile2.txt",
		"C:\\Cplus\\antivirus\\antivirus\\testfile3.txt" };


    for (const auto& file_path : files_to_scan) {
		if (std::filesystem::exists(file_path)) {
			av.check_file(file_path);
          
		}
		else {
			std::cout << "File not found: " << file_path << std::endl;
		}
	}

   
		

    return 0;

}
