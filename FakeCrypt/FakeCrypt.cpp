#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <ctime>
#include <chrono>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

// ==================== 文件安全操作 ====================

bool safeViewFile(const std::string& filepath) {
    if (!fs::exists(filepath)) {
        std::cout << "文件不存在" << std::endl;
        return false;
    }

    std::string extension = fs::path(filepath).extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

    const std::vector<std::string> allowedExtensions = {
        ".txt", ".md", ".log", ".ini", ".inf", ".cfg", ".json", ".xml",
        ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".ico",
        ".mp3", ".wav", ".ogg", ".flac",
        ".mp4", ".avi", ".mkv", ".mov",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"
    };

    bool isAllowed = false;
    for (const auto& ext : allowedExtensions) {
        if (extension == ext) {
            isAllowed = true;
            break;
        }
    }

    if (!isAllowed) {
        std::cout << "不支持的文件类型" << std::endl;
        return false;
    }

    auto filesize = fs::file_size(filepath);
    const size_t MAX_FILE_SIZE = 2000 * 1024 * 1024;

    if (filesize > MAX_FILE_SIZE) {
        std::cout << "文件过大" << std::endl;
        return false;
    }

    HINSTANCE result = ShellExecuteA(
        NULL,
        "open",
        filepath.c_str(),
        NULL,
        NULL,
        SW_SHOWNORMAL
    );

    if ((INT_PTR)result <= 32) {
        DWORD error = GetLastError();
        std::string errorMsg = "无法打开文件。错误代码: " + std::to_string(error);
        std::cout << errorMsg << std::endl;
        return false;
    }

    return true;
}

// ==================== 加密头结构定义 ====================
#pragma pack(push, 1)
struct EncryptionHeader {
    uint8_t magic[4];
    uint8_t majorVersion;
    uint8_t minorVersion;
    uint8_t algorithmId;
    uint8_t headerLength;
    uint8_t reserved[4];
    uint64_t timestamp;
    uint64_t originalSize;
    uint8_t fileHash[32];  // SHA-256哈希值
    uint64_t checksum;
};
#pragma pack(pop)

const uint8_t MAJOR_VERSION = 2;  // 版本升级到2.0
const uint8_t MINOR_VERSION = 0;
const uint8_t ALGORITHM_ID = 0x02;  // 使用全文件哈希校验
const uint8_t MAGIC_SIGNATURE[4] = { 0x4D, 0x59, 0x43, 0x52 };  // "MYCR"
const size_t HEADER_SIZE = sizeof(EncryptionHeader);

// ==================== 辅助函数 ====================
/**
 * 修复文件路径：如果是相对路径，转换为绝对路径
 */
std::string fixFilePath(const std::string& filepath) {
    try {
        return fs::absolute(filepath).string();
    }
    catch (...) {
        return filepath;
    }
}

/**
 * 检查文件是否存在且有读取权限
 */
bool canAccessFile(const std::string& filepath) {
    std::ifstream test(filepath, std::ios::binary);
    if (!test) return false;

    // 尝试读取一个字节来确认可读性
    char dummy;
    test.read(&dummy, 1);
    return test.gcount() == 1 || !test.fail();
}

// ==================== 校验码计算 ====================
uint64_t calculateHeaderChecksum(const EncryptionHeader& header) {
    EncryptionHeader tempHeader = header;
    tempHeader.checksum = 0;

    uint64_t checksum = 0x123456789ABCDEF0ULL;
    const uint8_t* data = reinterpret_cast<const uint8_t*>(&tempHeader);
    size_t length = sizeof(EncryptionHeader) - sizeof(uint64_t);

    for (size_t i = 0; i < length; i++) {
        checksum = (checksum << 5) ^ (checksum >> 3) ^ static_cast<uint64_t>(data[i]);
        checksum = checksum * 0x9E3779B97F4A7C15ULL;
    }

    return checksum;
}

bool verifyHeaderChecksum(const EncryptionHeader& header) {
    return header.checksum == calculateHeaderChecksum(header);
}

// ==================== 外部Python哈希验证 ====================
/**
 * 运行Python脚本计算文件哈希
 */
std::string runPythonHashScript(const std::string& filepath, bool isEncryptedFile) {
    // 创建Python脚本
    std::string pythonScript = R"(
import hashlib
import sys
import struct

def calculate_file_hash(filepath, is_encrypted):
    try:
        with open(filepath, 'rb') as f:
            if is_encrypted:
                # 对于加密文件，跳过头部计算内容哈希
                f.seek(32 + 8 + 8 + 32)  # 跳过头部直到哈希字段之后
                content = f.read()
                return hashlib.sha256(content).hexdigest()
            else:
                # 对于原始文件，计算整个文件哈希
                content = f.read()
                return hashlib.sha256(content).hexdigest()
    except Exception as e:
        print(f"ERROR:{str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("ERROR:Invalid arguments")
        sys.exit(1)
    
    filepath = sys.argv[1]
    is_encrypted = sys.argv[2].lower() == 'true'
    
    hash_result = calculate_file_hash(filepath, is_encrypted)
    print(f"HASH:{hash_result}")
)";

    // 将脚本写入临时文件
    std::string tempScriptPath = fs::temp_directory_path().string() + "\\file_hash_verifier.py";
    std::ofstream scriptFile(tempScriptPath);
    if (!scriptFile) {
        return "";
    }
    scriptFile << pythonScript;
    scriptFile.close();

    // 构建命令
    std::string command = "python \"" + tempScriptPath + "\" \"" + filepath + "\" " +
        (isEncryptedFile ? "true" : "false");

    // 执行命令并捕获输出
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        fs::remove(tempScriptPath);
        return "";
    }

    char buffer[256];
    std::string result = "";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    _pclose(pipe);

    // 清理临时脚本
    fs::remove(tempScriptPath);

    // 解析结果
    if (result.find("HASH:") != std::string::npos) {
        size_t start = result.find("HASH:") + 5;
        size_t end = result.find("\n", start);
        if (end != std::string::npos) {
            return result.substr(start, end - start);
        }
    }
    else if (result.find("ERROR:") != std::string::npos) {
        std::cerr << "Python脚本错误: " << result << std::endl;
    }

    return "";
}

/**
 * 计算文件的SHA-256哈希
 */
bool calculateFileHash(const std::string& filepath, uint8_t hash[32]) {
    std::string hashStr = runPythonHashScript(filepath, false);
    if (hashStr.empty()) {
        return false;
    }

    // 将十六进制字符串转换为字节数组
    for (int i = 0; i < 32; i++) {
        std::string byteStr = hashStr.substr(i * 2, 2);
        hash[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
    }

    return true;
}

/**
 * 验证文件内容哈希
 */
bool verifyFileContentHash(const std::string& filepath, const uint8_t expectedHash[32]) {
    std::string currentHashStr = runPythonHashScript(filepath, true);
    if (currentHashStr.empty()) {
        return false;
    }

    // 将预期的哈希转换为字符串
    std::ostringstream expectedStr;
    expectedStr << std::hex << std::setfill('0');
    for (int i = 0; i < 32; i++) {
        expectedStr << std::setw(2) << static_cast<int>(expectedHash[i]);
    }

    return currentHashStr == expectedStr.str();
}

// ==================== 时间戳处理 ====================
uint64_t getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

std::string timestampToString(uint64_t timestamp) {
    time_t time = timestamp / 1000;
    char buffer[80];
    struct tm* timeinfo = localtime(&time);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);

    std::ostringstream ss;
    ss << buffer << "." << std::setfill('0') << std::setw(3) << (timestamp % 1000);
    return ss.str();
}

// ==================== 文件操作 ====================
bool isFileEncrypted(const std::string& filepath) {
    std::string fixedPath = fixFilePath(filepath);
    std::ifstream file(fixedPath, std::ios::binary);
    if (!file) return false;

    EncryptionHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    if (file.gcount() != sizeof(header)) {
        return false;
    }

    for (int i = 0; i < 4; i++) {
        if (header.magic[i] != MAGIC_SIGNATURE[i]) {
            return false;
        }
    }

    return verifyHeaderChecksum(header);
}

/**
 * 加密文件 - 创建副本版本
 */
bool encryptFile(const std::string& filepath) {
    std::string fixedPath = fixFilePath(filepath);

    if (!canAccessFile(fixedPath)) {
        std::cout << "[-] 无法打开文件: " << fixedPath << std::endl;
        return false;
    }

    if (isFileEncrypted(fixedPath)) {
        std::cout << "[-] 文件已被加密，不允许重复加密！" << std::endl;
        return false;
    }

    // 获取文件大小
    uint64_t fileSize = fs::file_size(fixedPath);
    if (fileSize == 0) {
        std::cout << "[-] 文件为空，无法加密！" << std::endl;
        return false;
    }

    // 计算文件哈希
    uint8_t fileHash[32];
    std::cout << "[+] 正在计算文件哈希..." << std::endl;
    if (!calculateFileHash(fixedPath, fileHash)) {
        std::cout << "[-] 无法计算文件哈希！" << std::endl;
        return false;
    }

    // 读取原始文件内容
    std::ifstream inFile(fixedPath, std::ios::binary);
    if (!inFile) {
        std::cout << "[-] 无法读取文件: " << fixedPath << std::endl;
        return false;
    }
    std::cout << "[+] 开始处理" << std::endl;

    std::vector<uint8_t> fileData(fileSize);
    inFile.read(reinterpret_cast<char*>(fileData.data()), fileSize);
    inFile.close();

    // 准备加密头
    EncryptionHeader header;
    std::memcpy(header.magic, MAGIC_SIGNATURE, 4);
    header.majorVersion = MAJOR_VERSION;
    header.minorVersion = MINOR_VERSION;
    header.algorithmId = ALGORITHM_ID;
    header.headerLength = HEADER_SIZE;
    std::memset(header.reserved, 0, 4);
    header.timestamp = getCurrentTimestamp();
    header.originalSize = fileSize;
    std::memcpy(header.fileHash, fileHash, 32);
    header.checksum = 0;

    // 计算头部校验码
    header.checksum = calculateHeaderChecksum(header);

    // 创建加密副本（保持原文件不变）
    std::string encryptedFile;
    size_t dotPos = fixedPath.find_last_of('.');
    if (dotPos != std::string::npos) {
        encryptedFile = fixedPath.substr(0, dotPos) + "_encrypted" + fixedPath.substr(dotPos);
    }
    else {
        encryptedFile = fixedPath + "_encrypted";
    }

    // 检查副本是否已存在
    if (fs::exists(encryptedFile)) {
        std::cout << "[-] 加密副本已存在: " << encryptedFile << std::endl;
        std::cout << "    是否覆盖？(y/n): ";
        char choice;
        std::cin >> choice;
        if (choice != 'y' && choice != 'Y') {
            return false;
        }
    }

    std::ofstream outFile(encryptedFile, std::ios::binary);
    if (!outFile) {
        std::cout << "[-] 无法创建加密文件: " << encryptedFile << std::endl;
        return false;
    }

    // 写入加密头和原始内容
    outFile.write(reinterpret_cast<const char*>(&header), sizeof(header));
    outFile.write(reinterpret_cast<const char*>(fileData.data()), fileData.size());
    outFile.close();

    // 验证加密文件的内容哈希
    std::cout << "[+] 验证加密文件完整性..." << std::endl;
    if (!verifyFileContentHash(encryptedFile, fileHash)) {
        std::cout << "[-] 加密文件验证失败！文件可能已损坏" << std::endl;
        fs::remove(encryptedFile);
        return false;
    }

    std::cout << "[+] 加密成功！" << std::endl;
    std::cout << "    原始文件: " << fixedPath << " (" << fileSize << " 字节)" << std::endl;
    std::cout << "    加密文件: " << encryptedFile << " (" << (fileSize + sizeof(header)) << " 字节)" << std::endl;
    std::cout << "    加密时间: " << timestampToString(header.timestamp) << std::endl;

    // 显示哈希值
    std::cout << "    文件哈希: ";
    std::cout << std::hex << std::setfill('0');
    for (int i = 0; i < 32; i++) {
        std::cout << std::setw(2) << static_cast<int>(header.fileHash[i]);
    }
    std::cout << std::dec << std::endl;

    return true;
}

/**
 * 解密文件 - 创建解密副本
 */
bool decryptFile(const std::string& filepath) {
    std::string fixedPath = fixFilePath(filepath);

    if (!canAccessFile(fixedPath)) {
        std::cout << "[-] 无法打开文件: " << fixedPath << std::endl;
        return false;
    }

    if (!isFileEncrypted(fixedPath)) {
        std::cout << "[-] 文件未被加密，无需解密！" << std::endl;
        return false;
    }

    std::ifstream inFile(fixedPath, std::ios::binary);
    if (!inFile) {
        std::cout << "[-] 无法打开加密文件: " << fixedPath << std::endl;
        return false;
    }

    // 读取加密头
    EncryptionHeader header;
    inFile.read(reinterpret_cast<char*>(&header), sizeof(header));

    // 获取总文件大小
    inFile.seekg(0, std::ios::end);
    uint64_t totalSize = inFile.tellg();
    uint64_t contentSize = totalSize - sizeof(header);
    inFile.seekg(sizeof(header), std::ios::beg);

    // 验证文件大小
    if (contentSize != header.originalSize) {
        std::cout << "[-] 文件大小不匹配！可能已损坏。" << std::endl;
        std::cout << "    期望大小: " << header.originalSize << " 字节" << std::endl;
        std::cout << "    实际大小: " << contentSize << " 字节" << std::endl;
        return false;
    }

    // 验证文件内容哈希
    std::cout << "[+] 验证文件完整性..." << std::endl;
    if (!verifyFileContentHash(fixedPath, header.fileHash)) {
        std::cout << "[-] 文件完整性验证失败！文件可能已被篡改" << std::endl;
        return false;
    }

    // 读取加密内容
    std::vector<uint8_t> contentData(contentSize);
    inFile.read(reinterpret_cast<char*>(contentData.data()), contentSize);
    inFile.close();

    // 创建解密副本
    std::string decryptedFile;
    std::string encryptedStr = "_encrypted";

    // 尝试移除 "_encrypted" 后缀
    size_t encPos = fixedPath.find(encryptedStr);
    if (encPos != std::string::npos) {
        // 文件名中包含 _encrypted
        decryptedFile = fixedPath.substr(0, encPos) + "_decrypted" + fixedPath.substr(encPos + encryptedStr.length());
    }
    else {
        // 普通解密，添加 _decrypted 后缀
        size_t dotPos = fixedPath.find_last_of('.');
        if (dotPos != std::string::npos) {
            decryptedFile = fixedPath.substr(0, dotPos) + "_decrypted" + fixedPath.substr(dotPos);
        }
        else {
            decryptedFile = fixedPath + "_decrypted";
        }
    }

    // 检查副本是否已存在
    if (fs::exists(decryptedFile)) {
        std::cout << "[-] 解密副本已存在: " << decryptedFile << std::endl;
        std::cout << "    是否覆盖？(y/n): ";
        char choice;
        std::cin >> choice;
        if (choice != 'y' && choice != 'Y') {
            return false;
        }
    }

    std::ofstream outFile(decryptedFile, std::ios::binary);
    if (!outFile) {
        std::cout << "[-] 无法创建解密文件: " << decryptedFile << std::endl;
        return false;
    }

    // 写入原始内容
    outFile.write(reinterpret_cast<const char*>(contentData.data()), contentData.size());
    outFile.close();

    std::cout << "[+] 解密成功！" << std::endl;
    std::cout << "    加密文件: " << fixedPath << " (" << totalSize << " 字节)" << std::endl;
    std::cout << "    解密文件: " << decryptedFile << " (" << contentSize << " 字节)" << std::endl;
    std::cout << "    加密时间: " << timestampToString(header.timestamp) << std::endl;
    std::cout << "    原始大小: " << header.originalSize << " 字节" << std::endl;
    std::cout << "    文件哈希: ";
    std::cout << std::hex << std::setfill('0');
    for (int i = 0; i < 32; i++) {
        std::cout << std::setw(2) << static_cast<int>(header.fileHash[i]);
    }
    std::cout << std::dec << std::endl;

    return true;
}

void showFileInfo(const std::string& filepath) {
    std::string fixedPath = fixFilePath(filepath);

    if (!isFileEncrypted(fixedPath)) {
        std::cout << "[-] 文件未被加密" << std::endl;
        return;
    }

    std::ifstream file(fixedPath, std::ios::binary);
    EncryptionHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    file.close();

    uint64_t currentSize = fs::file_size(fixedPath);

    std::cout << "[+] 加密信息:" << std::endl;
    std::cout << "    文件路径: " << fixedPath << std::endl;
    std::cout << "    版本: v" << (int)header.majorVersion << "." << (int)header.minorVersion << std::endl;
    std::cout << "    加密时间: " << timestampToString(header.timestamp) << std::endl;
    std::cout << "    原始大小: " << header.originalSize << " 字节" << std::endl;
    std::cout << "    当前大小: " << currentSize << " 字节" << std::endl;
    std::cout << "    头部开销: " << (currentSize - header.originalSize) << " 字节" << std::endl;
    std::cout << "    算法标识: 0x" << std::hex << (int)header.algorithmId << std::dec << std::endl;

    // 显示哈希值
    std::cout << "    文件哈希: ";
    std::cout << std::hex << std::setfill('0');
    for (int i = 0; i < 32; i++) {
        std::cout << std::setw(2) << static_cast<int>(header.fileHash[i]);
    }
    std::cout << std::dec << std::endl;

    // 验证文件完整性
    std::cout << "    完整性验证: ";
    if (verifyFileContentHash(fixedPath, header.fileHash)) {
        std::cout << "通过" << std::endl;
    }
    else {
        std::cout << "失败（文件可能已被篡改）" << std::endl;
    }

    // 计算加密时长
    uint64_t currentTime = getCurrentTimestamp();
    uint64_t durationMinutes = (currentTime - header.timestamp) / (1000 * 60);
    if (durationMinutes > 0) {
        std::cout << "    已加密时长: " << durationMinutes << " 分钟" << std::endl;
    }
}

// ==================== 高级命令：查看加密头详细信息 ====================
void showEncryptionHeaderDetails(const std::string& filepath) {
    std::string fixedPath = fixFilePath(filepath);

    if (!canAccessFile(fixedPath)) {
        std::cout << "[-] 无法打开文件: " << fixedPath << std::endl;
        return;
    }

    std::ifstream file(fixedPath, std::ios::binary);
    if (!file) {
        std::cout << "[-] 无法读取文件: " << fixedPath << std::endl;
        return;
    }
    if (!isFileEncrypted(fixedPath)) {
        std::cout << "[-] 文件未被加密" << std::endl;
        return;
    }

    // 读取文件前32字节（加密头大小）
    const size_t headerSize = sizeof(EncryptionHeader);
    std::vector<uint8_t> rawHeader(headerSize);
    file.read(reinterpret_cast<char*>(rawHeader.data()), headerSize);

    if (file.gcount() != headerSize) {
        std::cout << "[-] 文件太小，无法读取完整加密头" << std::endl;
        return;
    }

    // 解析为结构体
    EncryptionHeader header;
    std::memcpy(&header, rawHeader.data(), headerSize);

    std::cout << "\n[+] 文件: " << fixedPath << std::endl;
    std::cout << "    文件大小: " << fs::file_size(fixedPath) << " 字节" << std::endl;

    std::cout << "\n[加密头详细信息]" << std::endl;
    std::cout << "────────────────────────────────────" << std::endl;

    // 1. 魔数签名
    std::cout << "魔数签名 (4字节): ";
    std::cout << std::hex << std::setfill('0');
    for (int i = 0; i < 4; i++) {
        std::cout << "0x" << std::setw(2) << (int)header.magic[i] << " ";
    }
    std::cout << std::dec << "(";
    for (int i = 0; i < 4; i++) {
        if (header.magic[i] >= 32 && header.magic[i] <= 126) {
            std::cout << (char)header.magic[i];
        }
        else {
            std::cout << ".";
        }
    }
    std::cout << ")" << std::endl;

    // 2. 版本信息
    std::cout << "版本号: v" << (int)header.majorVersion << "." << (int)header.minorVersion << std::endl;

    // 3. 算法标识
    std::cout << "算法标识: 0x" << std::hex << (int)header.algorithmId << std::dec;
    switch (header.algorithmId) {
    case 0x01: std::cout << " (简单标记)"; break;
    case 0x02: std::cout << " (全文件哈希校验)"; break;
    default: std::cout << " (未知)"; break;
    }
    std::cout << std::endl;

    // 4. 标记长度
    std::cout << "标记长度: " << (int)header.headerLength << " 字节" << std::endl;

    // 5. 预留字段
    std::cout << "预留字段 (4字节): ";
    std::cout << std::hex;
    for (int i = 0; i < 4; i++) {
        std::cout << "0x" << std::setw(2) << (int)header.reserved[i] << " ";
    }
    std::cout << std::dec << std::endl;

    // 6. 时间戳
    std::cout << "时间戳 (8字节): " << header.timestamp << std::endl;
    std::cout << "加密时间: " << timestampToString(header.timestamp) << std::endl;

    // 7. 原始文件大小
    std::cout << "原始文件大小: " << header.originalSize << " 字节";
    if (header.originalSize > 0) {
        std::cout << " (";
        if (header.originalSize < 1024) {
            std::cout << header.originalSize << " B";
        }
        else if (header.originalSize < 1024 * 1024) {
            std::cout << std::fixed << std::setprecision(2) << header.originalSize / 1024.0 << " KB";
        }
        else if (header.originalSize < 1024 * 1024 * 1024) {
            std::cout << std::fixed << std::setprecision(2) << header.originalSize / (1024.0 * 1024.0) << " MB";
        }
        else {
            std::cout << std::fixed << std::setprecision(2) << header.originalSize / (1024.0 * 1024.0 * 1024.0) << " GB";
        }
        std::cout << ")" << std::dec;
    }
    std::cout << std::endl;

    // 8. 文件哈希
    std::cout << "文件哈希 (SHA-256): ";
    std::cout << std::hex << std::setfill('0');
    for (int i = 0; i < 32; i++) {
        if (i > 0 && i % 8 == 0) std::cout << " ";
        std::cout << std::setw(2) << (int)header.fileHash[i];
    }
    std::cout << std::dec << std::endl;

    // 9. 校验码
    std::cout << "头部校验码 (8字节): 0x" << std::hex << std::setw(16) << std::setfill('0')
        << header.checksum << std::dec << std::setfill(' ') << std::endl;

    // 10. 验证校验码
    std::cout << "头部校验码验证: ";
    if (verifyHeaderChecksum(header)) {
        std::cout << "通过" << std::endl;
    }
    else {
        std::cout << "失败 (头部可能损坏)" << std::endl;
    }

    // 11. 文件完整性验证
    std::cout << "文件完整性验证: ";
    if (verifyFileContentHash(fixedPath, header.fileHash)) {
        std::cout << "通过" << std::endl;
    }
    else {
        std::cout << "失败 (文件内容可能已被篡改)" << std::endl;
    }

    std::cout << "────────────────────────────────────" << std::endl;
}

// ==================== CLI交互界面 ====================
void showHelp() {
    std::cout << "文件加密/解密工具 v" << (int)MAJOR_VERSION << "." << (int)MINOR_VERSION << std::endl;
    std::cout << "说明: 本工具创建文件副本进行加密/解密，使用SHA-256全文件哈希验证完整性" << std::endl;
    std::cout << "注意: 需要Python环境支持哈希计算" << std::endl;
    std::cout << std::endl;
    std::cout << "参数模式:" << std::endl;
    std::cout << "  FakeCrypt help                   显示此帮助信息" << std::endl;
    std::cout << "  FakeCrypt version                显示版本信息" << std::endl;
    std::cout << "  FakeCrypt <文件路径>              自动加密/解密文件" << std::endl;
    std::cout << "  FakeCrypt                        进入交互模式" << std::endl;
    std::cout << std::endl;
    std::cout << "交互模式命令:" << std::endl;
    std::cout << "  enc <文件>      加密文件（创建 _encrypted 副本）" << std::endl;
    std::cout << "  dec <文件>      解密文件（创建 _decrypted 副本）" << std::endl;
    std::cout << "  check <文件>    检查文件状态" << std::endl;
    std::cout << "  info <文件>     显示加密信息" << std::endl;
    std::cout << "  header <文件>   分析加密文件头" << std::endl;
    std::cout << "  batch <目录>    批量处理目录" << std::endl;
    std::cout << "  help           显示帮助" << std::endl;
    std::cout << "  exit           退出程序" << std::endl;
}

void showVersion() {
    std::cout << "文件加密/解密工具 v" << (int)MAJOR_VERSION << "." << (int)MINOR_VERSION << std::endl;
    std::cout << "创建副本模式 - 不会修改原始文件" << std::endl;
    std::cout << "校验算法: SHA-256全文件哈希验证" << std::endl;
    std::cout << "需要: Python环境（用于哈希计算）" << std::endl;
}

void batchProcessDirectory(const std::string& dirpath) {
    std::string fixedPath = fixFilePath(dirpath);

    if (!fs::exists(fixedPath) || !fs::is_directory(fixedPath)) {
        std::cout << "[-] 目录不存在或无法访问: " << fixedPath << std::endl;
        return;
    }

    std::vector<std::string> allFiles;

    // 收集所有文件
    for (const auto& entry : fs::recursive_directory_iterator(fixedPath)) {
        if (fs::is_regular_file(entry)) {
            std::string filepath = entry.path().string();

            // 跳过临时文件和已处理的文件
            if (filepath.find("_encrypted") != std::string::npos ||
                filepath.find("_decrypted") != std::string::npos ||
                filepath.find(".tmp") != std::string::npos) {
                continue;
            }

            allFiles.push_back(filepath);
        }
    }

    if (allFiles.empty()) {
        std::cout << "[-] 目录中没有可处理的文件" << std::endl;
        return;
    }

    std::cout << "[+] 找到 " << allFiles.size() << " 个文件" << std::endl;
    std::cout << "    开始处理..." << std::endl;

    int successCount = 0;
    int skipCount = 0;
    int errorCount = 0;

    for (const auto& file : allFiles) {
        std::cout << "\n处理文件: " << fs::path(file).filename().string() << std::endl;

        if (isFileEncrypted(file)) {
            std::cout << "  状态: 已加密，执行解密..." << std::endl;
            if (decryptFile(file)) {
                successCount++;
            }
            else {
                errorCount++;
            }
        }
        else {
            std::cout << "  状态: 未加密，执行加密..." << std::endl;
            if (encryptFile(file)) {
                successCount++;
            }
            else {
                errorCount++;
            }
        }
    }

    std::cout << "\n[+] 批量处理完成！" << std::endl;
    std::cout << "    成功: " << successCount << " 个文件" << std::endl;
    std::cout << "    失败: " << errorCount << " 个文件" << std::endl;
    std::cout << "    跳过: " << skipCount << " 个文件" << std::endl;
}

// ==================== CLI交互界面 ====================
void runInteractiveMode() {
    std::cout << "FakeCrypt v" << (int)MAJOR_VERSION << "." << (int)MINOR_VERSION << std::endl;
    std::cout << "使用SHA-256全文件哈希验证，需要Python环境支持" << std::endl;
    std::cout << "输入 'help' 查看命令，'exit' 退出" << std::endl;

    std::string command;
    while (true) {
        std::cout << "\n> ";
        std::getline(std::cin, command);

        if (command.empty()) continue;

        // 处理带双引号的路径
        std::string trimmed = command;
        trimmed.erase(0, trimmed.find_first_not_of(" \t\n\r\f\v"));
        trimmed.erase(trimmed.find_last_not_of(" \t\n\r\f\v") + 1);

        // 移除路径两端的双引号
        if (trimmed.size() >= 2 && trimmed.front() == '"' && trimmed.back() == '"') {
            trimmed = trimmed.substr(1, trimmed.size() - 2);
        }

        // 分割命令和参数
        size_t spacePos = trimmed.find(' ');
        std::string cmd, arg;

        if (spacePos != std::string::npos) {
            cmd = trimmed.substr(0, spacePos);
            arg = trimmed.substr(spacePos + 1);

            // 处理参数中可能还有的双引号
            if (!arg.empty() && arg.front() == '"' && arg.back() == '"') {
                arg = arg.substr(1, arg.size() - 2);
            }
        }
        else {
            cmd = trimmed;
        }

        std::string cmdLower = cmd;
        std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::tolower);

        if (cmdLower == "exit" || cmdLower == "quit") {
            std::cout << "再见！" << std::endl;
            break;
        }
        else if (cmdLower == "help") {
            showHelp();
        }
        else if (cmdLower == "enc" && !arg.empty()) {
            // 检查是否为绝对路径
            if (!fs::path(arg).is_absolute()) {
                std::cout << "[-] 错误: 请使用绝对路径！" << std::endl;
                std::cout << "    当前路径: " << arg << std::endl;
                std::cout << "    示例: encrypt \"C:\\Users\\Name\\My Documents\\file.txt\"" << std::endl;
                continue;
            }
            encryptFile(arg);
        }
        else if (cmdLower == "dec" && !arg.empty()) {
            if (!fs::path(arg).is_absolute()) {
                std::cout << "[-] 错误: 请使用绝对路径！" << std::endl;
                std::cout << "    当前路径: " << arg << std::endl;
                continue;
            }
            decryptFile(arg);
        }
        else if (cmdLower == "check" && !arg.empty()) {
            if (!fs::path(arg).is_absolute()) {
                std::cout << "[-] 错误: 请使用绝对路径！" << std::endl;
                continue;
            }
            if (isFileEncrypted(arg)) {
                std::cout << "[+] 文件已被加密" << std::endl;
                // 验证完整性
                std::ifstream file(arg, std::ios::binary);
                EncryptionHeader header;
                file.read(reinterpret_cast<char*>(&header), sizeof(header));
                file.close();

                std::cout << "    完整性验证: ";
                if (verifyFileContentHash(arg, header.fileHash)) {
                    std::cout << "通过" << std::endl;
                }
                else {
                    std::cout << "失败（文件可能已被篡改）" << std::endl;
                }
            }
            else {
                std::cout << "[-] 文件未被加密" << std::endl;
            }
        }
        else if (cmdLower == "info" && !arg.empty()) {
            if (!fs::path(arg).is_absolute()) {
                std::cout << "[-] 错误: 请使用绝对路径！" << std::endl;
                continue;
            }
            showFileInfo(arg);
        }
        else if (cmdLower == "batch" && !arg.empty()) {
            if (!fs::path(arg).is_absolute()) {
                std::cout << "[-] 错误: 请使用绝对路径！" << std::endl;
                continue;
            }
            batchProcessDirectory(arg);
        }
        else if (cmdLower == "version" || cmdLower == "-v") {
            showVersion();
        }
        else if (cmdLower == "header" && !arg.empty()) {
            if (!fs::path(arg).is_absolute()) {
                std::cout << "[-] 错误: 请使用绝对路径！" << std::endl;
                continue;
            }
            showEncryptionHeaderDetails(arg);
        }
        else {
            std::cout << "未知命令或缺少参数，输入 'help' 查看可用命令" << std::endl;
            std::cout << "正确格式: command \"绝对路径\"" << std::endl;
        }
    }
}

// ==================== 主函数参数处理 ====================
int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleCP(65001);
#endif

    // 检查Python是否可用
    std::cout << "[+] 检查Python环境..." << std::endl;
    FILE* pipe = _popen("python --version", "r");
    if (!pipe) {
        std::cout << "[-] 错误: 未找到Python环境！" << std::endl;
        std::cout << "    请安装Python并将其添加到系统PATH中" << std::endl;
        system("pause");
        return 1;
    }
    _pclose(pipe);
    std::cout << "[+] Python环境检查通过" << std::endl;

    if (argc == 1) {
        runInteractiveMode();
    }
    else {
        // 处理带引号的参数
        std::vector<std::string> args;
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            // 如果参数以引号开头，尝试合并后续参数直到找到匹配的引号
            if (!arg.empty() && arg.front() == '"') {
                std::string combined = arg;
                for (int j = i + 1; j < argc; j++) {
                    combined += " " + std::string(argv[j]);
                    if (!std::string(argv[j]).empty() && std::string(argv[j]).back() == '"') {
                        i = j; // 跳过已合并的参数
                        break;
                    }
                }
                // 移除引号
                if (combined.size() >= 2 && combined.front() == '"' && combined.back() == '"') {
                    combined = combined.substr(1, combined.size() - 2);
                }
                args.push_back(combined);
            }
            else {
                args.push_back(arg);
            }
        }

        if (args.size() == 1) {
            std::string arg = args[0];
            std::transform(arg.begin(), arg.end(), arg.begin(), ::tolower);

            if (arg == "help" || arg == "-h" || arg == "--help") {
                showHelp();
            }
            else if (arg == "version" || arg == "-v" || arg == "--version") {
                showVersion();
            }
            else {
                std::string filepath = args[0];

                if (!fs::exists(filepath)) {
                    std::cout << "[-] 文件不存在: " << filepath << std::endl;
                    system("pause");
                    return 1;
                }

                if (fs::is_directory(filepath)) {
                    std::cout << "[+] 检测到目录，进入批量处理模式..." << std::endl;
                    batchProcessDirectory(filepath);
                    system("pause");
                }
                else {
                    if (isFileEncrypted(filepath)) {
                        std::cout << "[+] 检测到已加密文件，执行解密..." << std::endl;
                        decryptFile(filepath);
                        // 获取解密后的文件路径
                        std::string decPath;
                        std::string encryptedStr = "_encrypted";
                        std::string fixedPath = fixFilePath(filepath);

                        size_t encPos = fixedPath.find(encryptedStr);
                        if (encPos != std::string::npos) {
                            // 文件名中包含 _encrypted
                            decPath = fixedPath.substr(0, encPos) + "_decrypted" +
                                fixedPath.substr(encPos + encryptedStr.length());
                        }
                        else {
                            // 普通解密，添加 _decrypted 后缀
                            size_t dotPos = fixedPath.find_last_of('.');
                            if (dotPos != std::string::npos) {
                                decPath = fixedPath.substr(0, dotPos) + "_decrypted" +
                                    fixedPath.substr(dotPos);
                            }
                            else {
                                decPath = fixedPath + "_decrypted";
                            }
                        }

                        safeViewFile(decPath);
                        system("pause");
                    }
                    else {
                        std::cout << "[+] 检测到未加密文件，执行加密..." << std::endl;
                        encryptFile(filepath);
                        system("pause");
                    }
                }
            }
        }
        else {
            std::cout << "[-] 参数过多！使用 'FakeCrypt help' 查看帮助" << std::endl;
            system("pause");
            return 1;
        }
    }

    return 0;
}