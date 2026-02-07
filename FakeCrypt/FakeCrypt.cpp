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

// 只保留红、黄、绿三种颜色
#define ANSI_RED "\033[31m"
#define ANSI_GREEN "\033[32m"
#define ANSI_YELLOW "\033[33m"
#define ANSI_RESET "\033[0m"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

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
    uint64_t checksum;
};
#pragma pack(pop)

const uint8_t MAJOR_VERSION = 1;
const uint8_t MINOR_VERSION = 0;
const uint8_t ALGORITHM_ID = 0x01;
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

// ==================== 简单数学校验码计算 ====================
uint64_t calculateSimpleChecksum(const uint8_t* data, size_t length) {
    uint64_t checksum = 0x123456789ABCDEF0ULL;

    for (size_t i = 0; i < length; i++) {
        checksum = (checksum << 5) ^ (checksum >> 3) ^ static_cast<uint64_t>(data[i]);
        checksum = checksum * 0x9E3779B97F4A7C15ULL;
    }

    return checksum;
}

bool verifyChecksum(const EncryptionHeader& header) {
    EncryptionHeader tempHeader = header;
    tempHeader.checksum = 0;

    uint64_t calculated = calculateSimpleChecksum(
        reinterpret_cast<const uint8_t*>(&tempHeader),
        sizeof(EncryptionHeader) - sizeof(uint64_t)
    );

    return calculated == header.checksum;
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

    return verifyChecksum(header);
}

/**
 * 加密文件 - 创建副本版本
 */
bool encryptFile(const std::string& filepath) {
    std::string fixedPath = fixFilePath(filepath);

    if (!canAccessFile(fixedPath)) {
        std::cout << ANSI_RED << "[-] 无法打开文件: " << fixedPath << ANSI_RESET << std::endl;
        return false;
    }

    if (isFileEncrypted(fixedPath)) {
        std::cout << ANSI_YELLOW << "[-] 文件已被加密，不允许重复加密！" << ANSI_RESET << std::endl;
        return false;
    }

    // 获取文件大小
    uint64_t fileSize = fs::file_size(fixedPath);
    if (fileSize == 0) {
        std::cout << ANSI_RED << "[-] 文件为空，无法加密！" << ANSI_RESET << std::endl;
        return false;
    }

    // 读取原始文件内容
    std::ifstream inFile(fixedPath, std::ios::binary);
    if (!inFile) {
        std::cout << ANSI_RED << "[-] 无法读取文件: " << fixedPath << ANSI_RESET << std::endl;
        return false;
    }

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
    header.checksum = 0;

    // 计算校验码
    header.checksum = calculateSimpleChecksum(
        reinterpret_cast<const uint8_t*>(&header),
        sizeof(EncryptionHeader) - sizeof(uint64_t)
    );

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
        std::cout << ANSI_YELLOW << "[-] 加密副本已存在: " << encryptedFile << ANSI_RESET << std::endl;
        std::cout << "    是否覆盖？(y/n): ";
        char choice;
        std::cin >> choice;
        if (choice != 'y' && choice != 'Y') {
            return false;
        }
    }

    std::ofstream outFile(encryptedFile, std::ios::binary);
    if (!outFile) {
        std::cout << ANSI_RED << "[-] 无法创建加密文件: " << encryptedFile << ANSI_RESET << std::endl;
        return false;
    }

    // 写入加密头和原始内容
    outFile.write(reinterpret_cast<const char*>(&header), sizeof(header));
    outFile.write(reinterpret_cast<const char*>(fileData.data()), fileData.size());
    outFile.close();

    std::cout << ANSI_GREEN << "[+] 加密成功！" << ANSI_RESET << std::endl;
    std::cout << "    原始文件: " << fixedPath << " (" << fileSize << " 字节)" << std::endl;
    std::cout << "    加密文件: " << encryptedFile << " (" << (fileSize + sizeof(header)) << " 字节)" << std::endl;
    std::cout << "    加密时间: " << timestampToString(header.timestamp) << std::endl;

    return true;
}

/**
 * 解密文件 - 创建解密副本
 */
bool decryptFile(const std::string& filepath) {
    std::string fixedPath = fixFilePath(filepath);

    if (!canAccessFile(fixedPath)) {
        std::cout << ANSI_RED << "[-] 无法打开文件: " << fixedPath << ANSI_RESET << std::endl;
        return false;
    }

    if (!isFileEncrypted(fixedPath)) {
        std::cout << ANSI_YELLOW << "[-] 文件未被加密，无需解密！" << ANSI_RESET << std::endl;
        return false;
    }

    std::ifstream inFile(fixedPath, std::ios::binary);
    if (!inFile) {
        std::cout << ANSI_RED << "[-] 无法打开加密文件: " << fixedPath << ANSI_RESET << std::endl;
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
        std::cout << ANSI_RED << "[-] 文件大小不匹配！可能已损坏。" << ANSI_RESET << std::endl;
        std::cout << "    期望大小: " << header.originalSize << " 字节" << std::endl;
        std::cout << "    实际大小: " << contentSize << " 字节" << std::endl;
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
        std::cout << ANSI_YELLOW << "[-] 解密副本已存在: " << decryptedFile << ANSI_RESET << std::endl;
        std::cout << "    是否覆盖？(y/n): ";
        char choice;
        std::cin >> choice;
        if (choice != 'y' && choice != 'Y') {
            return false;
        }
    }

    std::ofstream outFile(decryptedFile, std::ios::binary);
    if (!outFile) {
        std::cout << ANSI_RED << "[-] 无法创建解密文件: " << decryptedFile << ANSI_RESET << std::endl;
        return false;
    }

    // 写入原始内容
    outFile.write(reinterpret_cast<const char*>(contentData.data()), contentData.size());
    outFile.close();

    std::cout << ANSI_GREEN << "[+] 解密成功！" << ANSI_RESET << std::endl;
    std::cout << "    加密文件: " << fixedPath << " (" << totalSize << " 字节)" << std::endl;
    std::cout << "    解密文件: " << decryptedFile << " (" << contentSize << " 字节)" << std::endl;
    std::cout << "    加密时间: " << timestampToString(header.timestamp) << std::endl;
    std::cout << "    原始大小: " << header.originalSize << " 字节" << std::endl;

    return true;
}

void showFileInfo(const std::string& filepath) {
    std::string fixedPath = fixFilePath(filepath);

    if (!isFileEncrypted(fixedPath)) {
        std::cout << ANSI_YELLOW << "[-] 文件未被加密" << ANSI_RESET << std::endl;
        return;
    }

    std::ifstream file(fixedPath, std::ios::binary);
    EncryptionHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    file.close();

    uint64_t currentSize = fs::file_size(fixedPath);

    std::cout << ANSI_GREEN << "[+] 加密信息:" << ANSI_RESET << std::endl;
    std::cout << "    文件路径: " << fixedPath << std::endl;
    std::cout << "    版本: v" << (int)header.majorVersion << "." << (int)header.minorVersion << std::endl;
    std::cout << "    加密时间: " << timestampToString(header.timestamp) << std::endl;
    std::cout << "    原始大小: " << header.originalSize << " 字节" << std::endl;
    std::cout << "    当前大小: " << currentSize << " 字节" << std::endl;
    std::cout << "    头部开销: " << (currentSize - header.originalSize) << " 字节" << std::endl;
    std::cout << "    算法标识: 0x" << std::hex << (int)header.algorithmId << std::dec << std::endl;

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
        std::cout << ANSI_RED << "[-] 无法打开文件: " << fixedPath << ANSI_RESET << std::endl;
        return;
    }

    std::ifstream file(fixedPath, std::ios::binary);
    if (!file) {
        std::cout << ANSI_RED << "[-] 无法读取文件: " << fixedPath << ANSI_RESET << std::endl;
        return;
    }
    if (!isFileEncrypted(fixedPath)) {
        std::cout << ANSI_YELLOW << "[-] 文件未被加密" << ANSI_RESET << std::endl;
        return;
    }

    // 读取文件前32字节（加密头大小）
    const size_t headerSize = sizeof(EncryptionHeader);
    std::vector<uint8_t> rawHeader(headerSize);
    file.read(reinterpret_cast<char*>(rawHeader.data()), headerSize);

    if (file.gcount() != headerSize) {
        std::cout << ANSI_RED << "[-] 文件太小，无法读取完整加密头" << ANSI_RESET << std::endl;
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
    case 0x00: std::cout << " (头部标记)"; break;
    case 0x01: std::cout << " (简单标记)"; break;
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
        std::cout << ")";
    }
    std::cout << std::endl;

    // 8. 校验码
    std::cout << "校验码 (8字节): 0x" << std::hex << std::setw(16) << std::setfill('0')
        << header.checksum << std::dec << std::setfill(' ') << std::endl;

    // 9. 验证校验码
    std::cout << "校验码验证: ";
    if (verifyChecksum(header)) {
        std::cout << ANSI_GREEN << "通过" << ANSI_RESET << std::endl;
    }
    else {
        std::cout << ANSI_RED << "失败 (文件可能损坏或被篡改)" << ANSI_RESET << std::endl;
    }

    // 10. 原始文件头预览
    std::cout << "\n[原始文件头预览 (前32字节)]" << std::endl;
    std::cout << "────────────────────────────────────" << std::endl;

    // 读取原始文件内容的前32字节
    file.seekg(headerSize, std::ios::beg);
    const size_t previewSize = 32;
    std::vector<uint8_t> previewData(previewSize);
    file.read(reinterpret_cast<char*>(previewData.data()), previewSize);
    size_t bytesRead = file.gcount();

    if (bytesRead > 0) {
        // 十六进制显示
        std::cout << "十六进制: ";
        std::cout << std::hex << std::setfill('0');
        for (size_t i = 0; i < bytesRead; i++) {
            if (i > 0 && i % 8 == 0) std::cout << "  ";
            std::cout << std::setw(2) << (int)previewData[i] << " ";
        }
        std::cout << std::dec << std::endl;

        // ASCII显示
        std::cout << "ASCII码:  ";
        for (size_t i = 0; i < bytesRead; i++) {
            if (i > 0 && i % 8 == 0) std::cout << "  ";
            if (previewData[i] >= 32 && previewData[i] <= 126) {
                std::cout << " " << (char)previewData[i] << " ";
            }
            else {
                std::cout << " . ";
            }
        }
        std::cout << std::endl;
    }

    // 11. 文件类型推测
    std::cout << "\n[文件类型推测]" << std::endl;
    std::cout << "────────────────────────────────────" << std::endl;

    if (bytesRead >= 8) {
        // 常见文件头检查
        if (previewData[0] == 0x89 && previewData[1] == 0x50 &&
            previewData[2] == 0x4E && previewData[3] == 0x47) {
            std::cout << "类型: PNG图像文件" << std::endl;
        }
        else if (previewData[0] == 0xFF && previewData[1] == 0xD8 &&
            previewData[2] == 0xFF) {
            std::cout << "类型: JPEG图像文件" << std::endl;
        }
        else if (previewData[0] == 0x47 && previewData[1] == 0x49 &&
            previewData[2] == 0x46 && previewData[3] == 0x38) {
            std::cout << "类型: GIF图像文件" << std::endl;
        }
        else if (previewData[0] == 0x42 && previewData[1] == 0x4D) {
            std::cout << "类型: BMP图像文件" << std::endl;
        }
        else if (previewData[0] == 0x25 && previewData[1] == 0x50 &&
            previewData[2] == 0x44 && previewData[3] == 0x46) {
            std::cout << "类型: PDF文档" << std::endl;
        }
        else if (previewData[0] == 0x50 && previewData[1] == 0x4B &&
            previewData[2] == 0x03 && previewData[3] == 0x04) {
            std::cout << "类型: ZIP压缩文件" << std::endl;
        }
        else if (previewData[0] == 0x7F && previewData[1] == 0x45 &&
            previewData[2] == 0x4C && previewData[3] == 0x46) {
            std::cout << "类型: ELF可执行文件" << std::endl;
        }
        else if (previewData[0] == 0x4D && previewData[1] == 0x5A) {
            std::cout << "类型: Windows可执行文件" << std::endl;
        }
        else {
            // 检查是否为文本文件
            bool isText = true;
            for (size_t i = 0; i < bytesRead; i++) {
                if (previewData[i] < 9 || (previewData[i] > 13 && previewData[i] < 32)) {
                    isText = false;
                    break;
                }
            }
            if (isText) {
                std::cout << "类型: 文本文件" << std::endl;
            }
            else {
                std::cout << "类型: 未知或二进制文件" << std::endl;
            }
        }
    }
    else {
        std::cout << ANSI_RED << "类型: 无法确定（文件太小）" << ANSI_RESET << std::endl;
    }

    std::cout << "────────────────────────────────────" << std::endl;
}

// ==================== CLI交互界面 ====================
void showHelp() {
    std::cout << "文件加密/解密工具 v" << (int)MAJOR_VERSION << "." << (int)MINOR_VERSION << std::endl;
    std::cout << "说明: 本工具创建文件副本进行加密/解密，不会修改原始文件" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    std::cout << "参数模式:" << std::endl;
    std::cout << "  FakeCrypt help                   显示此帮助信息" << std::endl;
    std::cout << "  FakeCrypt version                显示版本信息" << std::endl;
    std::cout << "  FakeCrypt <文件路径>              自动加密/解密文件" << std::endl;
    std::cout << "  FakeCrypt                        进入交互模式" << std::endl;

    std::cout << "\n交互模式命令:" << std::endl;
    std::cout << "  enc <文件>      加密文件（创建 _encrypted 副本）" << std::endl;
    std::cout << "  dec <文件>      解密文件（创建 _decrypted 副本）" << std::endl;
    std::cout << "  check <文件>    检查文件状态" << std::endl;
    std::cout << "  info <文件>     显示加密信息" << std::endl;
    std::cout << "  header <文件>   分析加密文件头" << std::endl;
    std::cout << "  batch <目录>    批量处理目录" << std::endl;
    std::cout << "  help           显示帮助" << std::endl;
    std::cout << "  exit           退出程序" << std::endl;

    std::cout << std::string(60, '=') << std::endl;
    std::cout << "注意: 所有路径都需要使用绝对路径" << std::endl;
}

void showVersion() {
    std::cout << "文件加密/解密工具 v" << (int)MAJOR_VERSION << "." << (int)MINOR_VERSION << std::endl;
    std::cout << "创建副本模式 - 不会修改原始文件" << std::endl;
    std::cout << "校验算法: 简单多项式滚动校验" << std::endl;
    std::cout << "签名: \"MYCR\" (0x4D 0x59 0x43 0x52)" << std::endl;
}

void batchProcessDirectory(const std::string& dirpath) {
    std::string fixedPath = fixFilePath(dirpath);

    if (!fs::exists(fixedPath) || !fs::is_directory(fixedPath)) {
        std::cout << ANSI_RED << "[-] 目录不存在或无法访问: " << fixedPath << ANSI_RESET << std::endl;
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
        std::cout << ANSI_YELLOW << "[-] 目录中没有可处理的文件" << ANSI_RESET << std::endl;
        return;
    }

    std::cout << ANSI_GREEN << "[+] 找到 " << allFiles.size() << " 个文件" << ANSI_RESET << std::endl;
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

    std::cout << ANSI_GREEN << "\n[+] 批量处理完成！" << ANSI_RESET << std::endl;
    std::cout << ANSI_GREEN << "    成功: " << successCount << " 个文件" << ANSI_RESET << std::endl;
    std::cout << ANSI_RED << "    失败: " << errorCount << " 个文件" << ANSI_RESET << std::endl;
    std::cout << ANSI_YELLOW << "    跳过: " << skipCount << " 个文件" << ANSI_RESET << std::endl;
}

// ==================== CLI交互界面 ====================
void runInteractiveMode() {
    std::cout << "FakeCrypt v" << (int)MAJOR_VERSION << "." << (int)MINOR_VERSION << std::endl;
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
                std::cout << ANSI_RED << "[-] 错误: 请使用绝对路径！" << ANSI_RESET << std::endl;
                std::cout << "    当前路径: " << arg << std::endl;
                std::cout << "    示例: encrypt \"C:\\Users\\Name\\My Documents\\file.txt\"" << std::endl;
                continue;
            }
            encryptFile(arg);
        }
        else if (cmdLower == "dec" && !arg.empty()) {
            if (!fs::path(arg).is_absolute()) {
                std::cout << ANSI_RED << "[-] 错误: 请使用绝对路径！" << ANSI_RESET << std::endl;
                std::cout << "    当前路径: " << arg << std::endl;
                continue;
            }
            decryptFile(arg);
        }
        else if (cmdLower == "check" && !arg.empty()) {
            if (!fs::path(arg).is_absolute()) {
                std::cout << ANSI_RED << "[-] 错误: 请使用绝对路径！" << ANSI_RESET << std::endl;
                continue;
            }
            if (isFileEncrypted(arg)) {
                std::cout << ANSI_GREEN << "[+] 文件已被加密" << ANSI_RESET << std::endl;
            }
            else {
                std::cout << ANSI_YELLOW << "[-] 文件未被加密" << ANSI_RESET << std::endl;
            }
        }
        else if (cmdLower == "info" && !arg.empty()) {
            if (!fs::path(arg).is_absolute()) {
                std::cout << ANSI_RED << "[-] 错误: 请使用绝对路径！" << ANSI_RESET << std::endl;
                continue;
            }
            showFileInfo(arg);
        }
        else if (cmdLower == "batch" && !arg.empty()) {
            if (!fs::path(arg).is_absolute()) {
                std::cout << ANSI_RED << "[-] 错误: 请使用绝对路径！" << ANSI_RESET << std::endl;
                continue;
            }
            batchProcessDirectory(arg);
        }
        else if (cmdLower == "version" || cmdLower == "-v") {
            showVersion();
        }
        else if (cmdLower == "header" && !arg.empty()) {
            if (!fs::path(arg).is_absolute()) {
                std::cout << ANSI_RED << "[-] 错误: 请使用绝对路径！" << ANSI_RESET << std::endl;
                continue;
            }
            showEncryptionHeaderDetails(arg);
        }
        else {
            std::cout << ANSI_RED << "[!] 未知命令或缺少参数，输入 'help' 查看可用命令" << ANSI_RESET << std::endl;
            std::cout << "    正确格式: command \"绝对路径\"" << std::endl;
        }
    }
}

// ==================== 主函数参数处理 ====================
int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleCP(65001);
#endif

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
                    std::cout << ANSI_RED << "[-] 文件不存在: " << filepath << ANSI_RESET << std::endl;
#ifdef _WIN32
                    system("pause");
#endif
                    return 1;
                }

                if (fs::is_directory(filepath)) {
                    std::cout << ANSI_GREEN << "[+] 检测到目录，进入批量处理模式..." << ANSI_RESET << std::endl;
                    batchProcessDirectory(filepath);
                }
                else {
                    if (isFileEncrypted(filepath)) {
                        std::cout << ANSI_GREEN << "[+] 检测到已加密文件，执行解密..." << ANSI_RESET << std::endl;
                        decryptFile(filepath);
                    }
                    else {
                        std::cout << ANSI_GREEN << "[+] 检测到未加密文件，执行加密..." << ANSI_RESET << std::endl;
                        encryptFile(filepath);
                    }
                }
            }
        }
        else {
            std::cout << ANSI_RED << "[-] 参数过多！使用 'FakeCrypt help' 查看帮助" << ANSI_RESET << std::endl;
            return 1;
        }
    }

    return 0;
}