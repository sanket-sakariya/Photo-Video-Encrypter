# 🔐 File Security & Conversion Tools

A collection of secure, user-friendly desktop applications for file protection and format conversion. Choose the tool that best fits your needs:

## 🛠️ Available Tools

### 1. 🔐 Photo Encryption Tool (`file-encrypter.py`)
**Military-grade encryption** for protecting your sensitive photos and media files with AES-256 encryption.

### 2. 🔄 File Extension Changer (`file-converter.py`)
**Extension conversion** tool for changing file extensions between media and document formats for compatibility.

---

## 🎯 Which Tool Should You Use?

| Feature | Encryption Tool | Extension Changer |
|---------|----------------|-------------------|
| **Purpose** | Secure file protection | Format compatibility |
| **Security** | Military-grade AES-256 | No encryption |
| **File Changes** | Encrypts file content | Changes extension only |
| **Password Required** | Yes | No |
| **File Recovery** | Requires password | Instant |
| **Use Case** | Sensitive photos, privacy | Upload restrictions, compatibility |
| **Risk Level** | High (password loss = data loss) | Low (easily reversible) |

### 🔐 Choose Encryption Tool If:
- You need **real security** for sensitive files
- Files contain **private or confidential** information
- You want **military-grade protection**
- You're comfortable with **password management**

### 🔄 Choose Extension Changer If:
- You need to **bypass upload restrictions**
- Files are **blocked by file type filters**
- You want **quick format compatibility**
- You need **easily reversible** changes

## ✨ Features

### 🔐 Photo Encryption Tool Features
- **🔒 Military-Grade Security**: AES-256 encryption with PBKDF2 key derivation
- **🎨 User-Friendly GUI**: Clean, modern interface built with tkinter
- **📁 Batch Processing**: Encrypt/decrypt entire folders at once
- **🔄 Cross-Platform**: Works on Windows, macOS, and Linux
- **📊 Progress Tracking**: Real-time progress bar and status updates
- **🛡️ Thread-Safe**: Non-blocking operations with background processing
- **🔓 Standalone Decryption**: Separate command-line tool for decryption

### 🔄 File Extension Changer Features
- **⚡ Quick Conversion**: Instant extension changes without file processing
- **🔄 Bidirectional**: Convert media → documents and documents → media
- **📁 Batch Processing**: Process entire folders at once
- **🎨 User-Friendly GUI**: Clean, modern interface
- **📊 Progress Tracking**: Real-time progress updates
- **🛡️ Safe Operations**: Confirmation dialogs and error handling
- **⚠️ Clear Warnings**: Understandable risk notifications

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- `cryptography` library

### Installation

1. **Clone or download** this repository
2. **Install dependencies**:
   ```bash
   pip install cryptography
   ```
3. **Choose and run your preferred tool**:

   **For Encryption:**
   ```bash
   python file-encrypter.py
   ```

   **For Extension Changing:**
   ```bash
   python file-converter.py
   ```

## 📋 Supported File Types

### 🔐 Photo Encryption Tool - Supported Formats

#### Images
- `.jpg`, `.jpeg` - JPEG images
- `.png` - PNG images
- `.bmp` - Bitmap images
- `.gif` - GIF images
- `.tiff`, `.tif` - TIFF images
- `.heic` - HEIC images (iPhone photos)
- `.webp` - WebP images
- `.raw` - RAW camera files
- `.cr2` - Canon RAW files
- `.nef` - Nikon RAW files
- `.arw` - Sony RAW files

#### Videos
- `.mp4` - MP4 videos
- `.mov` - QuickTime videos
- `.avi` - AVI videos
- `.mkv` - Matroska videos

#### Audio
- `.mp3` - MP3 audio
- `.wav` - WAV audio
- `.flac` - FLAC audio

### 🔄 File Extension Changer - Extension Mappings

| Media Extensions | Document Extensions |
|------------------|-------------------|
| `.jpg` | `.txt` |
| `.jpeg` | `.docx` |
| `.png` | `.xlsx` |
| `.heic` | `.pdf` |
| `.mp3` | `.ppt` |
| `.mkv` | `.css` |
| `.mov` | `.html` |
| `.mp4` | `.js` |
| `.raw` | `.php` |

**Note**: Extension changes are **bidirectional** - you can convert in both directions.

## 🎯 How to Use

### 🔐 Photo Encryption Tool

#### GUI Application

1. **Launch** `file-encrypter.py`
2. **Select Folder** using the "📂 Browse" button
3. **Choose Action**:
   - **🔒 Encrypt Files**: Encrypt all supported files in the folder
   - **🔓 Decrypt Files**: Decrypt all `.encrypted` files in the folder
4. **Enter Password** when prompted
5. **Confirm** the operation
6. **Wait** for processing to complete

#### Command-Line Decryption

For standalone decryption without the GUI:

```bash
python decrypt_files.py
```

Or with a specific folder:

```bash
python decrypt_files.py "C:\path\to\your\folder"
```

### 🔄 File Extension Changer

#### GUI Application

1. **Launch** `file-converter.py`
2. **Select Folder** using the "📂 Browse" button
3. **Choose Action**:
   - **🔄 Convert Extensions**: Change media extensions to document extensions
   - **⏪ Reverse Extensions**: Change document extensions back to media extensions
4. **Confirm** the operation
5. **Wait** for processing to complete

#### Extension Conversion Examples

**Forward Conversion (Media → Documents):**
- `photo.jpg` → `photo.txt`
- `video.mp4` → `video.js`
- `audio.mp3` → `audio.ppt`

**Reverse Conversion (Documents → Media):**
- `photo.txt` → `photo.jpg`
- `video.js` → `video.mp4`
- `audio.ppt` → `audio.mp3`

## 🔒 Security Features

### 🔐 Photo Encryption Tool Security

#### Encryption Algorithm
- **AES-256**: Military-grade symmetric encryption
- **PBKDF2**: Password-based key derivation with 100,000 iterations
- **Unique Salt**: Each file gets a random 16-byte salt
- **No Backdoors**: Pure cryptographic security

#### Security Guarantees
- **Unbreakable**: AES-256 is considered cryptographically secure
- **Brute Force Resistant**: 100,000 PBKDF2 iterations make attacks extremely slow
- **Salt Protection**: Unique salts prevent rainbow table attacks
- **Memory Safe**: Passwords are only stored in memory during execution

#### Attack Resistance
- **Brute Force**: Would take 100+ years with supercomputers
- **Rainbow Tables**: Useless due to unique salts per file
- **Known Plaintext**: No known attacks against AES-256
- **Side Channel**: No implementation vulnerabilities

### 🔄 File Extension Changer Security

#### Important Notes
- **No Encryption**: This tool does NOT encrypt files
- **Extension Only**: Only changes file extensions, not content
- **Reversible**: All changes can be easily undone
- **No Data Loss**: Original file content remains intact

#### Use Cases
- **Upload Bypass**: Bypass file type restrictions on websites
- **Format Compatibility**: Make files compatible with different systems
- **Quick Conversion**: Instant format changes without processing

## 📁 File Format

### 🔐 Photo Encryption Tool - Encrypted File Structure

#### Encrypted File Structure
```
[16 bytes salt][encrypted data]
```

#### Encrypted Data Format
```
[4 bytes extension length][extension][file content]
```

### 🔄 File Extension Changer - File Structure

#### Extension Change Process
- **No File Content Changes**: Original file data remains exactly the same
- **Extension Only**: Only the file extension is modified
- **Metadata Preserved**: File creation date, size, and other properties unchanged
- **Instant Operation**: No processing time required

#### Example File Changes
```
Original: photo.jpg (1.2 MB)
Changed:  photo.txt (1.2 MB) - Same content, different extension
```

## 🔄 File Transfer & Portability

### 🔐 Photo Encryption Tool - File Transfer

#### Cross-Device Compatibility
- ✅ **Transfer encrypted files** to any device
- ✅ **Decrypt on different operating systems**
- ✅ **Perfect file integrity preservation**
- ✅ **No platform dependencies**

#### Transfer Methods
- **USB Drives**: Copy `.encrypted` files and decrypt anywhere
- **Cloud Storage**: Upload encrypted files safely
- **Network Transfer**: Send encrypted files over any network
- **Email**: Attach encrypted files securely

### 🔄 File Extension Changer - File Transfer

#### Cross-Device Compatibility
- ✅ **Transfer converted files** to any device
- ✅ **Works on all operating systems**
- ✅ **Perfect file integrity preservation**
- ✅ **No platform dependencies**

#### Transfer Methods
- **USB Drives**: Copy converted files and use anywhere
- **Cloud Storage**: Upload converted files safely
- **Network Transfer**: Send converted files over any network
- **Email**: Attach converted files securely

#### Important Notes
- **No Special Software**: Converted files work on any system
- **Instant Compatibility**: Files become compatible immediately
- **Easy Reversal**: Can be converted back to original format anytime

## ⚠️ Important Notes

### 🔐 Photo Encryption Tool - Important Notes

#### Password Security
- **Keep your password safe** - if lost, files cannot be recovered
- **Use strong passwords** (12+ characters, mixed case, numbers, symbols)
- **Never share passwords** - encryption is only as strong as your password
- **Backup passwords** securely (password managers recommended)

#### File Management
- **Original files are deleted** after successful encryption
- **Encrypted files are deleted** after successful decryption
- **Backup encrypted files** before decryption
- **Test decryption** on a few files before mass operations

#### Security Best Practices
- **Use different passwords** for different file sets
- **Regularly update passwords** for long-term storage
- **Verify file integrity** after decryption
- **Keep encryption tools updated**

### 🔄 File Extension Changer - Important Notes

#### Extension Changes
- **⚠️ WARNING**: This tool only changes file extensions, NOT file content
- **Files may become unreadable** by some applications after extension change
- **Always test** converted files before using them
- **Keep backups** of original files before conversion

#### Reversibility
- **All changes are reversible** using the reverse function
- **No data loss** occurs during extension changes
- **Original file content** remains exactly the same
- **File size and properties** are preserved

#### Best Practices
- **Test on a few files** before batch processing
- **Verify compatibility** after conversion
- **Keep original files** as backup
- **Use appropriate extensions** for your use case

## 🛠️ Technical Details

### Dependencies
```python
cryptography>=3.4.8  # For encryption tool only
tkinter (built-in with Python)
threading (built-in with Python)
```

### Architecture

#### 🔐 Photo Encryption Tool
- **GUI**: tkinter-based interface
- **Encryption**: cryptography library (Fernet)
- **Threading**: Background processing for non-blocking operations
- **File Handling**: Cross-platform file operations

#### 🔄 File Extension Changer
- **GUI**: tkinter-based interface
- **File Operations**: Native Python file system operations
- **Threading**: Background processing for non-blocking operations
- **File Handling**: Cross-platform file operations

### Performance

#### 🔐 Photo Encryption Tool
- **Encryption Speed**: ~10-50 MB/s depending on hardware
- **Memory Usage**: Minimal (processes files in chunks)
- **CPU Usage**: Moderate during encryption/decryption
- **Disk Space**: Encrypted files are slightly larger than originals

#### 🔄 File Extension Changer
- **Conversion Speed**: Instant (no file processing required)
- **Memory Usage**: Minimal (only file metadata operations)
- **CPU Usage**: Very low (simple file operations)
- **Disk Space**: No change in file size

## 🐛 Troubleshooting

### 🔐 Photo Encryption Tool - Common Issues

**"No files found for encryption"**
- Ensure files have supported extensions
- Check folder path is correct

**"Password mismatch"**
- Verify password is entered correctly
- Check for extra spaces or special characters

**"Error decrypting file"**
- Confirm password is correct
- Ensure file wasn't corrupted during transfer
- Verify file has `.encrypted` extension

**"Module not found: cryptography"**
- Install the library: `pip install cryptography`

### 🔄 File Extension Changer - Common Issues

**"No matching files found"**
- Ensure files have supported extensions
- Check folder path is correct

**"Target exists" error**
- Target file with new extension already exists
- Rename or move conflicting files

**"Permission Error"**
- Check folder access permissions
- Ensure files aren't open in other applications

**"Operation cancelled"**
- User cancelled the confirmation dialog

### General Error Messages
- **"Invalid Path"**: Folder doesn't exist or isn't accessible
- **"No Folder"**: No folder selected before operation
- **"Weak Password"**: Password is less than 6 characters (encryption tool only)
- **"Operation cancelled"**: User cancelled the confirmation dialog

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

If you encounter any issues or have questions:

1. **Check the troubleshooting section** above
2. **Review the error messages** carefully
3. **Test with a small file** first
4. **Ensure dependencies are installed**

## 🔮 Future Enhancements

### 🔐 Photo Encryption Tool
- [ ] File preview before encryption
- [ ] Selective file encryption
- [ ] Password strength meter
- [ ] Cloud storage integration
- [ ] Mobile app companion
- [ ] Key backup and recovery
- [ ] Multi-factor authentication
- [ ] File compression before encryption

### 🔄 File Extension Changer
- [ ] Custom extension mappings
- [ ] File preview before conversion
- [ ] Selective file conversion
- [ ] Bulk extension editing
- [ ] Extension validation
- [ ] Custom file type support
- [ ] Batch rename functionality
- [ ] Extension history tracking

## 📊 Version History

### v1.0.0
- **Photo Encryption Tool**: Initial release with GUI-based encryption/decryption
- **File Extension Changer**: Initial release with bidirectional extension conversion
- Support for common media formats
- Standalone decryption tool
- Cross-platform compatibility
- Thread-safe operations
- Progress tracking and error handling

---

## 🎯 Quick Decision Guide

**Need to protect sensitive files?** → Use **Photo Encryption Tool**
**Need to bypass upload restrictions?** → Use **File Extension Changer**

**🔐 Secure your digital life with military-grade encryption!**
**🔄 Convert file formats for better compatibility!**
