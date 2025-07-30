#include <iostream>
#include <vector>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <regex>
#include <chrono>
#include <cctype>


// Risk levels for file extensions
enum RiskLevel {
    SAFE = 0,
    LOW_RISK = 1,
    MEDIUM_RISK = 2,
    HIGH_RISK = 3,
    CRITICAL_RISK = 4
};

// File classification result
struct FileClassification {
    std::string filename;
    std::string extension;
    RiskLevel risk_level;
    std::string category;
    std::string description;
    bool is_hidden;
    bool has_multiple_extensions;
    std::vector<std::string> all_extensions;
    std::vector<std::string> warnings;
};

class FileExtensionDetector {
private:
    // Extension databases
    std::unordered_map<std::string, std::pair<RiskLevel, std::string>> extension_db;
    std::unordered_set<std::string> ransomware_extensions;
    std::unordered_set<std::string> executable_extensions;
    std::unordered_set<std::string> script_extensions;
    std::unordered_set<std::string> document_extensions;
    std::unordered_set<std::string> archive_extensions;
    std::unordered_set<std::string> image_extensions;
    std::unordered_set<std::string> system_extensions;
    
    // Statistics
    int total_files_scanned;
    int malicious_files_found;
    std::unordered_map<RiskLevel, int> risk_counts;
    
public:
    FileExtensionDetector() : total_files_scanned(0), malicious_files_found(0) {
        initialize_extension_database();
    }
    
    void initialize_extension_database() {
        // CRITICAL RISK - Ransomware Extensions
        std::vector<std::string> ransomware_exts = {
            // Recent ransomware families (2024-2025)
            ".lockbit", ".lockbit3.0", ".abcd", ".akira", ".alphv", ".blackcat",
            ".conti", ".ryuk", ".sodin", ".sodinokibi", ".giveme", ".darkside",
            ".ransomexx", ".mount", ".grief", ".pay2win", ".cuba", ".vice",
            ".lv", ".pysa", ".babuk", ".epsilon", ".prometheus", ".thanos",
            ".mailto", ".hive", ".blackbyte", ".quantum", ".ransom", ".cryp1",
            
            // Classic ransomware extensions
            ".encrypted", ".locked", ".crypto", ".aes", ".rsa", ".crypt",
            ".enc", ".vault", ".secure", ".protected", ".locky", ".cerber",
            ".wannacry", ".petya", ".notpetya", ".goldeneye", ".jigsaw",
            ".bart", ".locke", ".zepto", ".thor", ".odin", ".loki", ".shit",
            ".vvv", ".ecc", ".ezz", ".exx", ".xyz", ".zzz", ".aaa", ".abc",
            ".btc", ".ccc", ".micro", ".dharma", ".wallet", ".coin", ".crysis",
            ".matrix", ".phobos", ".nemty", ".snatch", ".maze", ".egregor",
            ".avaddon", ".recovery", ".cryptowall", ".cryptolocker", ".reveton",
            ".gpcode", ".winlocker", ".badblock", ".hydracrypt", ".cryptodef",
            ".cryptoinf", ".paym", ".howdecrypt", ".cryptorbit", ".encryptile",
            ".ctbl", ".ctb2", ".lockcrypt", ".ultracrypter", ".cryptxxx",
            ".7zipper", ".antefrigus", ".teamxrat", ".locklock", ".dxxd",
            ".frendi", ".unlock92", ".rekt", ".petrwrap", ".cryptomix",
            ".globeimposter", ".purge", ".crptrgr", ".herbst", ".java",
            ".payms", ".conficker", ".corona", ".crinf", ".evillock",
            ".fakben", ".fileice", ".genasom", ".gimemo", ".hddcryptor",
            ".justice", ".kegotip", ".m4n1f3st", ".matsnu", ".mayachok",
            ".pornoasset", ".potentially", ".rabbit", ".ragnarok", ".redboot",
            ".rokrat", ".scraper", ".virlock", ".volksrat", ".xpan", ".zbot",
            ".R16M01D05", ".gekko", ".sage", ".wnry", ".wncry"
        };
        
        for (const auto& ext : ransomware_exts) {
            extension_db[ext] = {CRITICAL_RISK, "Ransomware"};
            ransomware_extensions.insert(ext);
        }
        
        // HIGH RISK - Executable Files
        std::vector<std::string> executable_exts = {
            ".exe", ".com", ".scr", ".pif", ".bat", ".cmd", ".msi", ".dll",
            ".sys", ".drv", ".ocx", ".cpl", ".app", ".deb", ".rpm", ".pkg",
            ".dmg", ".run", ".bin", ".elf"
        };
        
        for (const auto& ext : executable_exts) {
            extension_db[ext] = {HIGH_RISK, "Executable"};
            executable_extensions.insert(ext);
        }
        
        // HIGH RISK - Script Files
        std::vector<std::string> script_exts = {
            ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".ps2",
            ".psc1", ".psc2", ".msh", ".msh1", ".msh2", ".mshxml", ".msh1xml",
            ".msh2xml", ".scf", ".lnk", ".inf", ".reg", ".py", ".pl", ".rb",
            ".sh", ".bash", ".zsh", ".fish", ".csh", ".tcsh", ".ksh",
            ".php", ".asp", ".aspx", ".jsp", ".cgi"
        };
        
        for (const auto& ext : script_exts) {
            extension_db[ext] = {HIGH_RISK, "Script"};
            script_extensions.insert(ext);
        }
        
        // MEDIUM RISK - Document Files (can contain macros/exploits)
        std::vector<std::string> document_exts = {
            ".doc", ".docx", ".docm", ".dot", ".dotx", ".dotm", ".xls",
            ".xlsx", ".xlsm", ".xlt", ".xltx", ".xltm", ".xlsb", ".xla",
            ".xlam", ".ppt", ".pptx", ".pptm", ".pot", ".potx", ".potm",
            ".ppa", ".ppam", ".pps", ".ppsx", ".ppsm", ".pdf", ".rtf",
            ".odt", ".ods", ".odp", ".odg", ".odb", ".odf"
        };
        
        for (const auto& ext : document_exts) {
            extension_db[ext] = {MEDIUM_RISK, "Document"};
            document_extensions.insert(ext);
        }
        
        // MEDIUM RISK - Archive Files (can contain malware)
        std::vector<std::string> archive_exts = {
            ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".z",
            ".lz", ".lzma", ".cab", ".iso", ".img", ".vhd", ".vmdk",
            ".ace", ".arj", ".lha", ".lzh", ".zoo", ".arc", ".pak",
            ".egg", ".alz", ".txz", ".tgz", ".tbz2", ".tlz"
        };
        
        for (const auto& ext : archive_exts) {
            extension_db[ext] = {MEDIUM_RISK, "Archive"};
            archive_extensions.insert(ext);
        }
        
        // LOW RISK - System Files
        std::vector<std::string> system_exts = {
            ".tmp", ".temp", ".log", ".bak", ".old", ".swp", ".~",
            ".cache", ".lock", ".pid", ".conf", ".cfg", ".ini",
            ".dat", ".db", ".sqlite", ".mdb", ".accdb"
        };
        
        for (const auto& ext : system_exts) {
            extension_db[ext] = {LOW_RISK, "System"};
            system_extensions.insert(ext);
        }
        
        // SAFE - Image Files
        std::vector<std::string> image_exts = {
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif",
            ".ico", ".svg", ".webp", ".psd", ".ai", ".eps", ".raw",
            ".cr2", ".nef", ".orf", ".sr2", ".dng"
        };
        
        for (const auto& ext : image_exts) {
            extension_db[ext] = {SAFE, "Image"};
            image_extensions.insert(ext);
        }
        
        // SAFE - Media Files
        std::vector<std::string> media_exts = {
            ".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a",
            ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
            ".m4v", ".3gp", ".f4v", ".asf", ".rm", ".rmvb"
        };
        
        for (const auto& ext : media_exts) {
            extension_db[ext] = {SAFE, "Media"};
        }
        
        // SAFE - Text Files
        std::vector<std::string> text_exts = {
            ".txt", ".md", ".rst", ".tex", ".csv", ".tsv", ".json",
            ".xml", ".yaml", ".yml", ".toml", ".ini", ".conf",
            ".log", ".readme", ".license", ".changelog"
        };
        
        for (const auto& ext : text_exts) {
            extension_db[ext] = {SAFE, "Text"};
        }
    }
    
    // Extract all extensions from filename
    std::vector<std::string> extract_extensions(const std::string& filename) {
        std::vector<std::string> extensions;
        std::string lower_filename = filename;
        std::transform(lower_filename.begin(), lower_filename.end(), lower_filename.begin(), ::tolower);
        
        size_t pos = lower_filename.find('.');
        while (pos != std::string::npos && pos < lower_filename.length() - 1) {
            std::string ext = lower_filename.substr(pos);
            
            // Check if this is a valid extension (not just a dot in the middle)
            size_t next_pos = lower_filename.find('.', pos + 1);
            if (next_pos != std::string::npos) {
                ext = lower_filename.substr(pos, next_pos - pos);
            }
            
            extensions.push_back(ext);
            pos = next_pos;
        }
        
        return extensions;
    }
    
    // Get the primary (last) extension
    std::string get_primary_extension(const std::string& filename) {
        std::string lower_filename = filename;
        std::transform(lower_filename.begin(), lower_filename.end(), lower_filename.begin(), ::tolower);
        
        size_t pos = lower_filename.find_last_of('.');
        if (pos != std::string::npos && pos < lower_filename.length() - 1) {
            return lower_filename.substr(pos);
        }
        return "";
    }
    
    // Check for suspicious extension patterns
    std::vector<std::string> check_suspicious_patterns(const std::string& filename, const std::vector<std::string>& extensions) {
        std::vector<std::string> warnings;
        
        // Check for double extensions (common in malware)
        if (extensions.size() > 1) {
            warnings.push_back("Multiple extensions detected (possible disguised malware)");
            
            // Check for executable hidden behind document extension
            for (size_t i = 0; i < extensions.size() - 1; i++) {
                if (executable_extensions.count(extensions[i]) && 
                    document_extensions.count(extensions.back())) {
                    warnings.push_back("Executable disguised as document");
                }
            }
        }
        
        // Check for hidden files (starting with dot on Unix systems)
        if (!filename.empty() && filename[0] == '.') {
            warnings.push_back("Hidden file detected");
        }
        
        // Check for suspicious filename patterns
        std::regex suspicious_patterns[] = {
            std::regex(".*readme.*", std::regex_constants::icase),
            std::regex(".*invoice.*", std::regex_constants::icase),
            std::regex(".*payment.*", std::regex_constants::icase),
            std::regex(".*urgent.*", std::regex_constants::icase),
            std::regex(".*confidential.*", std::regex_constants::icase),
            std::regex(".*decrypt.*", std::regex_constants::icase),
            std::regex(".*recovery.*", std::regex_constants::icase),
            std::regex(".*how.*to.*", std::regex_constants::icase)
        };
        
        for (const auto& pattern : suspicious_patterns) {
            if (std::regex_match(filename, pattern)) {
                warnings.push_back("Suspicious filename pattern");
                break;
            }
        }
        
        // Check for unusual characters in filename
        if (filename.find_first_of("$@#%^&*()+={}[]|\\:;\"'<>?") != std::string::npos) {
            warnings.push_back("Unusual characters in filename");
        }
        
        return warnings;
    }
    
    // Analyze a single file
    FileClassification analyze_file(const std::string& filename) {
        FileClassification result;
        result.filename = filename;
        result.is_hidden = (!filename.empty() && filename[0] == '.');
        
        // Extract extensions
        result.all_extensions = extract_extensions(filename);
        result.extension = get_primary_extension(filename);
        result.has_multiple_extensions = result.all_extensions.size() > 1;
        
        // Determine risk level and category
        if (!result.extension.empty() && extension_db.count(result.extension)) {
            auto& ext_info = extension_db[result.extension];
            result.risk_level = ext_info.first;
            result.category = ext_info.second;
        } else {
            result.risk_level = LOW_RISK;
            result.category = "Unknown";
        }
        
        // Check for suspicious patterns
        result.warnings = check_suspicious_patterns(filename, result.all_extensions);
        
        // Adjust risk based on warnings
        if (!result.warnings.empty()) {
            if (result.risk_level < MEDIUM_RISK) {
                result.risk_level = MEDIUM_RISK;
            }
        }
        
        // Set description based on risk level
        switch (result.risk_level) {
            case CRITICAL_RISK:
                result.description = "CRITICAL: Likely ransomware or highly dangerous malware";
                break;
            case HIGH_RISK:
                result.description = "HIGH: Executable or script file - potential security risk";
                break;
            case MEDIUM_RISK:
                result.description = "MEDIUM: Could contain malicious content or exploits";
                break;
            case LOW_RISK:
                result.description = "LOW: Generally safe but monitor for unusual behavior";
                break;
            case SAFE:
                result.description = "SAFE: Standard file type with low security risk";
                break;
        }
        
        return result;
    }
    
    // Scan directory for files

    
    // Analyze file list from text file
    std::vector<FileClassification> analyze_file_list(const std::string& filename_list_path) {
        std::vector<FileClassification> results;
        std::ifstream file(filename_list_path);
        
        if (!file.is_open()) {
            std::cerr << "Error: Cannot open file list " << filename_list_path << std::endl;
            return results;
        }
        
        std::string filename;
        while (std::getline(file, filename)) {
            if (!filename.empty()) {
                FileClassification result = analyze_file(filename);
                results.push_back(result);
                total_files_scanned++;
                
                if (result.risk_level >= HIGH_RISK) {
                    malicious_files_found++;
                }
                risk_counts[result.risk_level]++;
            }
        }
        
        file.close();
        return results;
    }
    
    // Display single file result
    void display_file_result(const FileClassification& result) {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "File: " << result.filename << std::endl;
        std::cout << "Primary Extension: " << (result.extension.empty() ? "(none)" : result.extension) << std::endl;
        
        if (result.has_multiple_extensions) {
            std::cout << "All Extensions: ";
            for (size_t i = 0; i < result.all_extensions.size(); i++) {
                std::cout << result.all_extensions[i];
                if (i < result.all_extensions.size() - 1) std::cout << ", ";
            }
            std::cout << std::endl;
        }
        
        std::cout << "Category: " << result.category << std::endl;
        std::cout << "Risk Level: ";
        
        switch (result.risk_level) {
            case CRITICAL_RISK:
                std::cout << "🔴 CRITICAL";
                break;
            case HIGH_RISK:
                std::cout << "🟠 HIGH";
                break;
            case MEDIUM_RISK:
                std::cout << "🟡 MEDIUM";
                break;
            case LOW_RISK:
                std::cout << "🟢 LOW";
                break;
            case SAFE:
                std::cout << "✅ SAFE";
                break;
        }
        std::cout << std::endl;
        
        std::cout << "Description: " << result.description << std::endl;
        
        if (result.is_hidden) {
            std::cout << "⚠️  Hidden file detected" << std::endl;
        }
        
        if (!result.warnings.empty()) {
            std::cout << "Warnings:" << std::endl;
            for (const auto& warning : result.warnings) {
                std::cout << "  ⚠️  " << warning << std::endl;
            }
        }
    }
    
    // Display summary statistics
    void display_summary() {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "SCAN SUMMARY" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
        std::cout << "Total files scanned: " << total_files_scanned << std::endl;
        std::cout << "Potentially malicious files: " << malicious_files_found << std::endl;
        std::cout << "Detection rate: " << std::fixed << std::setprecision(2) 
                  << (total_files_scanned > 0 ? (malicious_files_found * 100.0 / total_files_scanned) : 0.0) 
                  << "%" << std::endl;
        
        std::cout << "\nRisk Level Distribution:" << std::endl;
        std::cout << "🔴 Critical: " << risk_counts[CRITICAL_RISK] << std::endl;
        std::cout << "🟠 High: " << risk_counts[HIGH_RISK] << std::endl;
        std::cout << "🟡 Medium: " << risk_counts[MEDIUM_RISK] << std::endl;
        std::cout << "🟢 Low: " << risk_counts[LOW_RISK] << std::endl;
        std::cout << "✅ Safe: " << risk_counts[SAFE] << std::endl;
    }
    
    // Export results to CSV
    void export_to_csv(const std::vector<FileClassification>& results, const std::string& output_file) {
        std::ofstream csv_file(output_file);
        if (!csv_file.is_open()) {
            std::cerr << "Error: Cannot create CSV file " << output_file << std::endl;
            return;
        }
        
        // Write header
        csv_file << "Filename,Extension,Category,Risk_Level,Description,Is_Hidden,Multiple_Extensions,Warnings\n";
        
        // Write data
        for (const auto& result : results) {
            csv_file << "\"" << result.filename << "\",";
            csv_file << "\"" << result.extension << "\",";
            csv_file << "\"" << result.category << "\",";
            
            std::string risk_str;
            switch (result.risk_level) {
                case CRITICAL_RISK: risk_str = "Critical"; break;
                case HIGH_RISK: risk_str = "High"; break;
                case MEDIUM_RISK: risk_str = "Medium"; break;
                case LOW_RISK: risk_str = "Low"; break;
                case SAFE: risk_str = "Safe"; break;
            }
            csv_file << "\"" << risk_str << "\",";
            csv_file << "\"" << result.description << "\",";
            csv_file << (result.is_hidden ? "Yes" : "No") << ",";
            csv_file << (result.has_multiple_extensions ? "Yes" : "No") << ",";
            
            // Combine warnings
            std::string warnings_str;
            for (size_t i = 0; i < result.warnings.size(); i++) {
                warnings_str += result.warnings[i];
                if (i < result.warnings.size() - 1) warnings_str += "; ";
            }
            csv_file << "\"" << warnings_str << "\"\n";
        }
        
        csv_file.close();
        std::cout << "Results exported to " << output_file << std::endl;
    }
    
    // Generate test files for demonstration
    void generate_test_files() {
        std::vector<std::string> test_files = {
            // Safe files
            "document.txt",
            "image.jpg",
            "music.mp3",
            "video.mp4",
            "spreadsheet.csv",
            
            // Medium risk
            "report.pdf",
            "presentation.pptx",
            "data.zip",
            "backup.rar",
            
            // High risk
            "setup.exe",
            "script.bat",
            "macro.vbs",
            "installer.msi",
            "update.scr",
            
            // Critical risk (ransomware)
            "important.doc.exe",
            "invoice.pdf.lockbit",
            "document.encrypted",
            "files.locked",
            "data.akira",
            "backup.ryuk",
            
            // Suspicious patterns
            "README_TO_DECRYPT.txt",
            "HOW_TO_RESTORE_FILES.html",
            ".hidden_file",
            "urgent$payment.exe",
            "invoice.pdf.scr"
        };
        
        std::cout << "Generated " << test_files.size() << " test filenames for analysis." << std::endl;
        
        // Analyze test files
        std::vector<FileClassification> results;
        for (const auto& filename : test_files) {
            FileClassification result = analyze_file(filename);
            results.push_back(result);
            total_files_scanned++;
            
            if (result.risk_level >= HIGH_RISK) {
                malicious_files_found++;
            }
            risk_counts[result.risk_level]++;
        }
        
        // Display critical and high-risk files
        std::cout << "\n🚨 HIGH-RISK AND CRITICAL FILES DETECTED:" << std::endl;
        for (const auto& result : results) {
            if (result.risk_level >= HIGH_RISK) {
                display_file_result(result);
            }
        }
        
        // Export results
        export_to_csv(results, "file_extension_analysis.csv");
    }
};


    return 0;
}int main() {
    std::cout << "=== File Extension Detection and Classification System ===" << std::endl;
    std::cout << "Analyzing file extensions for potential security risks...\n" << std::endl;
    
    FileExtensionDetector detector;
    
    // Menu system
    int choice;
    std::cout << "Select operation mode:" << std::endl;
    std::cout << "1. Analyze single filename" << std::endl;
    std::cout << "2. Scan directory" << std::endl;
    std::cout << "3. Analyze file list from text file" << std::endl;
    std::cout << "4. Run demonstration with test files" << std::endl;
    std::cout << "Enter choice (1-4): ";
    std::cin >> choice;
    std::cin.ignore(); // Clear input buffer
    
    switch (choice) {
        case 1: {
            std::string filename;
            std::cout << "Enter filename to analyze: ";
            std::getline(std::cin, filename);
            
            FileClassification result = detector.analyze_file(filename);
            detector.display_file_result(result);
            break;
        }
        
        case 2: {
            std::string directory;
            char recursive_choice;
            
            std::cout << "Enter directory path: ";
            std::getline(std::cin, directory);
            
            std::cout << "Scan recursively? (y/n): ";
            std::cin >> recursive_choice;
            
            bool recursive = (recursive_choice == 'y' || recursive_choice == 'Y');
            
            std::cout << "\nScanning directory: " << directory << std::endl;
            std::vector<FileClassification> results = detector.scan_directory(directory, recursive);
            
            // Display high-risk files
            std::cout << "\n🚨 HIGH-RISK FILES FOUND:" << std::endl;
            for (const auto& result : results) {
                if (result.risk_level >= HIGH_RISK) {
                    detector.display_file_result(result);
                }
            }
            
            detector.display_summary();
            
            char export_choice;
            std::cout << "\nExport results to CSV? (y/n): ";
            std::cin >> export_choice;
            if (export_choice == 'y' || export_choice == 'Y') {
                detector.export_to_csv(results, "directory_scan_results.csv");
            }
            break;
        }
        
        case 3: {
            std::string file_list_path;
            std::cout << "Enter path to file containing list of filenames: ";
            std::getline(std::cin, file_list_path);
            
            std::vector<FileClassification> results = detector.analyze_file_list(file_list_path);
            
            // Display high-risk files
            std::cout << "\n🚨 HIGH-RISK FILES FOUND:" << std::endl;
            for (const auto& result : results) {
                if (result.risk_level >= HIGH_RISK) {
                    detector.display_file_result(result);
                }
            }
            
            detector.display_summary();
            detector.export_to_csv(results, "file_list_analysis.csv");
            break;
        }
        
        case 4: {
            std::cout << "\nRunning demonstration with test files..." << std::endl;
            detector.generate_test_files();
            detector.display_summary();
            break;
        }
        
        default:
            std::cout << "Invalid choice. Exiting." << std::endl;
            return 1;
    }
    
    std::cout << "\n=== Usage Tips ===" << std::endl;
    std::cout << "• Regularly update extension databases with new threat intelligence" << std::endl;
    std::cout << "• Monitor files with multiple extensions closely" << std::endl;
    std::cout << "• Be especially cautious of executable files disguised as documents" << std::endl;
    std::cout << "• Implement real-time file monitoring in production environments" << std::endl;
    std::cout << "• Integrate with antivirus and EDR solutions for comprehensive protection" << std::endl;
    