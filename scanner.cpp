#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <system_error> 

using namespace std;
namespace fs = std::filesystem;

vector<unsigned char> convertHexToBytes(const string& hexString) {
    vector<unsigned char> result;

    for (size_t i = 0; i < hexString.length(); i += 2) {
        string byte_str = hexString.substr(i, 2);
        unsigned char value = static_cast<unsigned char>(strtol(byte_str.c_str(), nullptr, 16));
        result.push_back(value);
    }

    return result;
}

fs::path getSignatureFilePath() {
    auto currentDir = fs::current_path();
    return currentDir / "filesignatures.txt";
}

class Scanner {
public:
    void crawlDirectory(const fs::path& startPath, const vector<vector<unsigned char>>& knownSignatures) {
        std::error_code dirError;
        fs::recursive_directory_iterator walker(startPath, fs::directory_options::skip_permission_denied, dirError);

        if (dirError) {
            cerr << "Couldn't open directory: " << startPath << " - " << dirError.message() << endl;
            return;
        }

        for (const auto& entry : walker) {
            std::error_code statError;
            
            if (fs::is_symlink(entry.path(), statError)) {
                if (!statError) {
                    cerr << "Skipping symlink: " << entry.path() << endl;
                }
                continue;
            }

            if (!fs::is_regular_file(entry.path(), statError)) {
                continue; 
            }

            bool isThreat = false;
            for (const auto& sig : knownSignatures) {
                ifstream infile(entry.path(), ios::binary);
                if (!infile) {
                    cerr << "Couldn't read file: " << entry.path() << endl;
                    continue;
                }

                vector<unsigned char> fileChunk(sig.size());
                infile.read(reinterpret_cast<char*>(fileChunk.data()), sig.size());

                if (fileChunk == sig) {
                    cout << "Malicious file: " << entry.path().filename()
                         << " (Folder: " << entry.path().parent_path().filename() << ")" << endl;
                    isThreat = true;
                    break;
                }
            }

            if (!isThreat) {
                cout << "Clean file: " << entry.path().filename()
                     << " (Folder: " << entry.path().parent_path().filename() << ")" << endl;
            }
        }
    }

    void scanUserInputFolder() {
        string userInputPath;
        cerr << "Please enter the path to scan (subfolders scaned too in the process): ";
        getline(cin, userInputPath);

        fs::path targetPath(userInputPath);
        std::error_code folderCheck;

        if (!fs::exists(targetPath, folderCheck) || !fs::is_directory(targetPath, folderCheck)) {
            cerr << "Oops. That folder doesn't look valid. Try again.\n" << endl;
            scanUserInputFolder();
            return;
        }

        fs::path sigFile = getSignatureFilePath();
        if (!fs::exists(sigFile, folderCheck)) {
            cerr << "Couldn’t find signature file , Please make sure it's in the program's directory." << endl;
            return;
        }

        vector<vector<unsigned char>> signatures;
        ifstream sigStream(sigFile, ios::in);
        if (!sigStream) {
            cerr << "Something went wrong reading filesignatures.txt" << endl;
            return;
        }

        string line;
        while (getline(sigStream, line)) {
            // Trim whitespace - because sometimes they sneak in
            line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());
            if (!line.empty()) {
                signatures.push_back(convertHexToBytes(line));
            }
        }

        sigStream.close(); 

        crawlDirectory(targetPath, signatures);
    }
};

int main() {
    cerr << "===== Welcome to the Ransomware Detector v1.0 =====" << endl;
    cerr << "This tool will walk through your folders and try to detect suspicious files." << endl;
    cerr << "Note: Make sure 'filesignatures.txt' is present in this folder." << endl;
    cerr << "---------------------------------------------------" << endl;

    Scanner myScanner;
    myScanner.scanUserInputFolder();

    return 0;
}
