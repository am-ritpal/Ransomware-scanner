#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <regex>
#include <chrono>
#include <cctype>

// Use the correct header for filesystem (C++17 and later)
#if __has_include(<filesystem>)
    #include <filesystem>
    namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
    #include <experimental/filesystem>
    namespace fs = std::experimental::filesystem;
#else
    #error "Missing the <filesystem> header."
#endif

using namespace std;

// Global extension sets
inline unordered_set<string> ransomware_exts;
inline unordered_set<string> doc_exts;
inline unordered_set<string> exe_exts;

// Loads extension sets from files. Returns true on success, false on error.
inline bool LoadExtensionSets() {
    bool ok = true;

    // Load ransomware extensions
    ifstream ransomwarefile("ransomware-exe.txt");
    if (!ransomwarefile.is_open()) {
        cerr << "Error: Could not open ransomware-exe.txt" << endl;
        ok = false;
    } else {
        string line;
        while (getline(ransomwarefile, line)) {
            line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());
            if (!line.empty())
                ransomware_exts.insert(line);
        }
        ransomwarefile.close();
    }

    // Load document extensions
    ifstream doc("doc.txt");
    if (!doc.is_open()) {
        cerr << "Error: Could not open doc.txt" << endl;
        ok = false;
    } else {
        string line;
        while (getline(doc, line)) {
            line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());
            if (!line.empty())
                doc_exts.insert(line);
        }
        doc.close();
    }

    // Load executable extensions
    ifstream exe_file("executable.txt");
    if (!exe_file.is_open()) {
        cerr << "Error: Could not open executable.txt" << endl;
        ok = false;
    } else {
        string exe_line;
        while (getline(exe_file, exe_line)) {
            exe_line.erase(remove_if(exe_line.begin(), exe_line.end(), ::isspace), exe_line.end());
            if (!exe_line.empty())
                exe_exts.insert(exe_line);
        }
        exe_file.close();
    }

    return ok;
}

// Extracts all extensions from a filename (e.g. "foo.tar.gz" -> [".tar", ".gz"])
inline vector<string> extract_extensions(const string& filename) {
    vector<string> extensions;
    string lower_filename = filename;
    transform(lower_filename.begin(), lower_filename.end(), lower_filename.begin(), ::tolower);

    size_t start = 0;
    while ((start = lower_filename.find('.', start)) != string::npos) {
        size_t next = lower_filename.find('.', start + 1);
        if (next != string::npos) {
            extensions.push_back(lower_filename.substr(start, next - start));
            start = next;
        } else {
            extensions.push_back(lower_filename.substr(start));
            break;
        }
    }
    return extensions;
}

// Checks for suspicious filename patterns and returns a list of warnings
inline vector<string> check_suspicious_patterns(
    const string& filename,
    const vector<string>& extensions,
    const unordered_set<string>& executable_extensions,
    const unordered_set<string>& document_extensions
) {
    vector<string> warnings;

    // Check for double extensions (common in malware)
    if (extensions.size() > 1) {
        warnings.push_back("Multiple extensions detected (possible disguised malware)");

        // Check for executable hidden behind document extension
        for (size_t i = 0; i < extensions.size() - 1; ++i) {
            if (executable_extensions.count(extensions[i]) &&
                document_extensions.count(extensions.back())) {
                warnings.push_back("Executable disguised as document");
            }
        }
    }

    // Check for hidden files (starting with dot, Unix-style)
    if (!filename.empty() && filename[0] == '.' &&
        filename.find('.') != filename.rfind('.')) { // Exclude common hidden files with only one dot
        warnings.push_back("Hidden file detected");
    }

    // Check for suspicious filename patterns
    const regex suspicious_patterns[] = {
        regex("readme", regex_constants::icase),
        regex("invoice", regex_constants::icase),
        regex("payment", regex_constants::icase),
        regex("urgent", regex_constants::icase),
        regex("confidential", regex_constants::icase),
        regex("decrypt", regex_constants::icase),
        regex("recovery", regex_constants::icase),
        regex("how.*to", regex_constants::icase)
    };

    for (const auto& pattern : suspicious_patterns) {
        if (regex_search(filename, pattern)) {
            warnings.push_back("Suspicious filename pattern");
            break;
        }
    }

    // Check for unusual characters in filename
    if (filename.find_first_of("$@#%^&*()+={}[]|\\:;\"'<>?") != string::npos) {
        warnings.push_back("Unusual characters in filename");
    }

    return warnings;
}

// Scans a directory for suspicious/ransomware files. Prints errors if any.
inline void scan(const string& directory_path) {
    if (!LoadExtensionSets()) {
        cerr << "Error: One or more extension files could not be loaded. Aborting scan." << endl;
        return;
    }
    try {
        for (const auto& entry : fs::recursive_directory_iterator(directory_path)) {
            std::error_code ec;
            if (!entry.is_regular_file(ec)) {
                if (ec) {
                    cerr << "Filesystem error: " << ec.message() << " for " << entry.path() << endl;
                }
                continue;
            }
            string filename = entry.path().filename().string();
            vector<string> extensions = extract_extensions(filename);

            bool is_ransomware = false;
            for (const auto& ext : extensions) {
                if (ransomware_exts.count(ext)) {
                    is_ransomware = true;
                    break;
                }
            }

            vector<string> warnings = check_suspicious_patterns(filename, extensions, exe_exts, doc_exts);

            if (is_ransomware || !warnings.empty()) {
                cerr << "ransomware detected: " << entry.path().filename().string()
                     << " in folder " << entry.path().parent_path().filename() << endl;
                if (!warnings.empty()) {
                    cerr << "  Warnings: ";
                    for (const auto& w : warnings) cerr << w << "; ";
                    cerr << endl;
                }
            } else {
                cerr << "safe file: " << entry.path().filename().string() << endl;
            }
        }
    }
    catch (const fs::filesystem_error& e) {
        cerr << "Error scanning directory: " << e.what() << endl;
    }
}

