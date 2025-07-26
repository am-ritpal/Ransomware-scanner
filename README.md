# Ransomware Detector v1.0

A lightweight command-line tool for detecting potentially malicious files based on known file signatures. This scanner recursively searches through directories to identify files that match known ransomware or malware signatures.

## Features

- **Recursive Directory Scanning**: Automatically scans all subdirectories within the specified path
- **Signature-Based Detection**: Uses hexadecimal file signatures to identify potentially malicious files
- **Symlink Safety**: Automatically skips symbolic links to prevent potential security issues
- **Permission Handling**: Gracefully handles directories with restricted access permissions
- **Real-time Feedback**: Provides immediate output showing both clean and potentially malicious files

## Prerequisites

- C++17 compatible compiler (GCC 8+, Clang 7+, or MSVC 2019+)
- Standard C++ libraries with filesystem support

## Installation

1. **Clone or download** the source code
2. **Compile** the program:
   ```bash
   g++ -std=c++17 -o scanner scanner.cpp
   ```
   
   Or on Windows with MSVC:
   ```cmd
   cl /std:c++17 scanner.cpp
   ```

## Required Files

### filesignatures.txt
You **must** create a `filesignatures.txt` file in the same directory as the executable. This file should contain hexadecimal signatures of known malicious files, one per line.

**Example filesignatures.txt:**
```
4D5A90000300000004000000FFFF0000
504B0304140000000800
89504E470D0A1A0A0000000D494844
```

**Format Requirements:**
- One signature per line
- Hexadecimal format only (0-9, A-F)
- No spaces, prefixes, or additional characters
- Empty lines are ignored

## Usage

1. **Run the program**:
   ```bash
   ./scanner
   ```

2. **Enter the path** when prompted:
   ```
   Please enter the path to scan (subfolders scaned too in the process): /path/to/scan
   ```

3. **Review the results**:
   - Files matching known signatures will be marked as "Malicious file"
   - All other files will be marked as "Clean file"

## Sample Output

```
===== Welcome to the Ransomware Detector v1.0 =====
This tool will walk through your folders and try to detect suspicious files.
Note: Make sure 'filesignatures.txt' is present in this folder.
---------------------------------------------------
Please enter the path to scan (subfolders scaned too in the process): /home/user/documents

Clean file: report.pdf (Folder: documents)
Clean file: image.jpg (Folder: photos)
Malicious file: suspicious.exe (Folder: downloads)
Clean file: notes.txt (Folder: documents)
```

## Important Notes

### Security Considerations
- This tool is for **detection purposes only** - it does not remove or quarantine files
- **Always verify** suspicious files through multiple sources before taking action
- Consider running this tool with appropriate system permissions
- **Backup important data** before investigating potential threats

### Limitations
- **Signature-based detection only**: May not detect new or unknown malware variants
- **False positives possible**: Legitimate files might match malware signatures
- **Performance**: Scanning large directories may take considerable time
- **File access**: Cannot scan files that are locked or in use by other processes

## Troubleshooting

### Common Issues

**"Couldn't find signature file"**
- Ensure `filesignatures.txt` exists in the same directory as the executable
- Check file permissions and accessibility

**"That folder doesn't look valid"**
- Verify the path exists and is accessible
- Use absolute paths when possible
- Check directory permissions

**"Couldn't read file"**
- File may be locked by another process
- Check file permissions
- File might be corrupted or inaccessible

### Error Handling
The program includes robust error handling for:
- Invalid directory paths
- Permission denied errors
- File access issues
- Missing signature files

## Building from Source

### Requirements
- C++17 standard library
- Filesystem library support
- Standard I/O libraries

### Compilation Flags
```bash
# Basic compilation
g++ -std=c++17 -o scanner scanner.cpp

# With optimization and warnings
g++ -std=c++17 -O2 -Wall -Wextra -o scanner scanner.cpp

# Debug build
g++ -std=c++17 -g -DDEBUG -o scanner scanner.cpp
```

## Contributing

When contributing to this project:
1. Maintain C++17 compatibility
2. Follow existing code style and structure
3. Add appropriate error handling
4. Test with various directory structures and file types

## Disclaimer

This tool is provided for educational and security research purposes. Users are responsible for:
- Complying with local laws and regulations
- Verifying scan results through additional means
- Taking appropriate action based on findings
- Understanding the limitations of signature-based detection

**Always exercise caution when dealing with potentially malicious files.**
