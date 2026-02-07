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

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

// ==================== 加密头结构定义 ====================
#pragma pack(push, 1)  // 确保结构体紧凑，无填充字节
struct EncryptionHeader {
    // 魔数签名: "MYCR" (4字节)
    uint8_t magic[4];

    // 版本信息 (2字节: 主版本.副版本)
    uint8_t majorVersion;
    uint8_t minorVersion;

    // 算法标识 (1字节)
    uint8_t algorithmId;

    // 标记长度 (1字节)
    uint8_t headerLength;

    // 保留字段 (4字节)
    uint8_t reserved[4];

    // 时间戳 (8字节, Unix时间戳毫秒)
    uint64_t timestamp;

    // 原始文件大小 (8字节)
    uint64_t originalSize;

    // 校验码 (8字节，使用简单数学方法计算)
    uint64_t checksum;
};
#pragma pack(pop)  // 恢复默认对齐方式

// 版本信息
const uint8_t MAJOR_VERSION = 1;
const uint8_t MINOR_VERSION = 0;
const uint8_t ALGORITHM_ID = 0x01;  // 简单头部标记算法

// 魔数签名
const uint8_t MAGIC_SIGNATURE[4] = { 0x4D, 0x59, 0x43, 0x52 };  // "MYCR"

// 加密头总长度
const size_t HEADER_SIZE = sizeof(EncryptionHeader);

// ==================== 简单数学校验码计算 ====================
/**
 * 计算简单校验码（不使用哈希库）
 * 使用多项式滚动算法：类似CRC32但更简单
 */
uint64_t calculateSimpleChecksum(const uint8_t* data, size_t length) {
    uint64_t checksum = 0x123456789ABCDEF0ULL;  // 初始种子

    for (size_t i = 0; i < length; i++) {
        // 使用多项式运算: x^7 + x^3 + x^2 + 1 (简单版本)
        checksum = (checksum << 5) ^ (checksum >> 3) ^ static_cast<uint64_t>(data[i]);
        checksum = checksum * 0x9E3779B97F4A7C15ULL;  // 黄金比例乘数
    }

    return checksum;
}

/**
 * 验证校验码
 */
bool verifyChecksum(const EncryptionHeader& header) {
    // 临时复制头，将校验码字段置零
    EncryptionHeader tempHeader = header;
    tempHeader.checksum = 0;

    // 计算校验码
    uint64_t calculated = calculateSimpleChecksum(
        reinterpret_cast<const uint8_t*>(&tempHeader),
        sizeof(EncryptionHeader) - sizeof(uint64_t)  // 排除校验码字段
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
/**
 * 检查文件是否已加密
 */
bool isFileEncrypted(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return false;

    // 读取加密头
    EncryptionHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    if (file.gcount() != sizeof(header)) {
        return false;
    }

    // 检查魔数签名
    for (int i = 0; i < 4; i++) {
        if (header.magic[i] != MAGIC_SIGNATURE[i]) {
            return false;
        }
    }

    // 验证校验码
    return verifyChecksum(header);
}

/**
 * 加密文件
 */
bool encryptFile(const std::string& filepath) {
    // 检查文件是否已加密
    if (isFileEncrypted(filepath)) {
        std::cout << "[-] 文件已被加密，不允许重复加密！" << std::endl;
        return false;
    }

    // 读取原始文件内容
    std::ifstream inFile(filepath, std::ios::binary);
    if (!inFile) {
        std::cout << "[-] 无法打开文件: " << filepath << std::endl;
        return false;
    }

    // 获取文件大小
    inFile.seekg(0, std::ios::end);
    uint64_t fileSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);

    if (fileSize == 0) {
        std::cout << "[-] 文件为空，无法加密！" << std::endl;
        return false;
    }

    // 读取文件内容
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
    std::memset(header.reserved, 0, 4);  // 预留字段清零
    header.timestamp = getCurrentTimestamp();
    header.originalSize = fileSize;
    header.checksum = 0;  // 先置零，稍后计算

    // 计算校验码
    header.checksum = calculateSimpleChecksum(
        reinterpret_cast<const uint8_t*>(&header),
        sizeof(EncryptionHeader) - sizeof(uint64_t)
    );

    // 创建临时文件
    std::string tempFile = filepath + ".tmp";
    std::ofstream outFile(tempFile, std::ios::binary);
    if (!outFile) {
        std::cout << "[-] 无法创建临时文件！" << std::endl;
        return false;
    }

    // 写入加密头和原始内容
    outFile.write(reinterpret_cast<const char*>(&header), sizeof(header));
    outFile.write(reinterpret_cast<const char*>(fileData.data()), fileData.size());
    outFile.close();

    // 替换原文件
    try {
        fs::remove(filepath);  // 删除原文件
        fs::rename(tempFile, filepath);  // 重命名临时文件
    }
    catch (const fs::filesystem_error& e) {
        std::cout << "[-] 文件替换失败: " << e.what() << std::endl;
        return false;
    }

    std::cout << "[+] 加密成功！" << std::endl;
    std::cout << "    加密时间: " << timestampToString(header.timestamp) << std::endl;
    std::cout << "    原始大小: " << fileSize << " 字节" << std::endl;

    return true;
}

/**
 * 解密文件
 */
bool decryptFile(const std::string& filepath) {
    // 检查文件是否已加密
    if (!isFileEncrypted(filepath)) {
        std::cout << "[-] 文件未被加密，无需解密！" << std::endl;
        return false;
    }

    // 打开加密文件
    std::ifstream inFile(filepath, std::ios::binary);
    if (!inFile) {
        std::cout << "[-] 无法打开文件: " << filepath << std::endl;
        return false;
    }

    // 读取加密头
    EncryptionHeader header;
    inFile.read(reinterpret_cast<char*>(&header), sizeof(header));

    // 读取加密内容
    inFile.seekg(0, std::ios::end);
    uint64_t totalSize = inFile.tellg();
    uint64_t contentSize = totalSize - sizeof(header);
    inFile.seekg(sizeof(header), std::ios::beg);

    std::vector<uint8_t> contentData(contentSize);
    inFile.read(reinterpret_cast<char*>(contentData.data()), contentSize);
    inFile.close();

    // 验证文件大小
    if (contentSize != header.originalSize) {
        std::cout << "[-] 文件大小不匹配！可能已损坏。" << std::endl;
        return false;
    }

    // 创建临时文件
    std::string tempFile = filepath + ".tmp";
    std::ofstream outFile(tempFile, std::ios::binary);
    if (!outFile) {
        std::cout << "[-] 无法创建临时文件！" << std::endl;
        return false;
    }

    // 写入原始内容
    outFile.write(reinterpret_cast<const char*>(contentData.data()), contentData.size());
    outFile.close();

    // 替换原文件
    try {
        fs::remove(filepath);  // 删除原文件
        fs::rename(tempFile, filepath);  // 重命名临时文件
    }
    catch (const fs::filesystem_error& e) {
        std::cout << "[-] 文件替换失败: " << e.what() << std::endl;
        return false;
    }

    std::cout << "[+] 解密成功！" << std::endl;
    std::cout << "    恢复大小: " << contentSize << " 字节" << std::endl;

    return true;
}

/**
 * 显示文件加密信息
 */
void showFileInfo(const std::string& filepath) {
    if (!isFileEncrypted(filepath)) {
        std::cout << "[-] 文件未被加密" << std::endl;
        return;
    }

    std::ifstream file(filepath, std::ios::binary);
    EncryptionHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    file.close();

    std::cout << "[+] 加密信息:" << std::endl;
    std::cout << "    版本: v" << (int)header.majorVersion
        << "." << (int)header.minorVersion << std::endl;
    std::cout << "    时间: " << timestampToString(header.timestamp) << std::endl;
    std::cout << "    原始大小: " << header.originalSize << " 字节" << std::endl;
    std::cout << "    算法标识: 0x" << std::hex << (int)header.algorithmId << std::dec << std::endl;

    // 获取当前文件大小
    uint64_t currentSize = fs::file_size(filepath);
    std::cout << "    当前大小: " << currentSize << " 字节" << std::endl;
    std::cout << "    头部大小: " << (int)header.headerLength << " 字节" << std::endl;
}

// ==================== CLI交互界面 ====================
void showHelp() {
    std::cout << "文件加密/解密工具 v" << (int)MAJOR_VERSION << "." << (int)MINOR_VERSION << std::endl;
    std::cout << std::endl;
    std::cout << "使用方法:" << std::endl;
    std::cout << "  FakeCrypt help                   显示此帮助信息" << std::endl;
    std::cout << "  FakeCrypt version                显示版本信息" << std::endl;
    std::cout << "  FakeCrypt <文件路径>            自动加密/解密文件" << std::endl;
    std::cout << "  FakeCrypt                       进入交互模式" << std::endl;
    std::cout << std::endl;
    std::cout << "交互模式命令:" << std::endl;
    std::cout << "  encrypt <文件>      加密文件" << std::endl;
    std::cout << "  decrypt <文件>      解密文件" << std::endl;
    std::cout << "  check <文件>        检查文件状态" << std::endl;
    std::cout << "  info <文件>         显示加密信息" << std::endl;
    std::cout << "  batch <目录>        批量处理目录(递归)" << std::endl;
    std::cout << "  help               显示帮助" << std::endl;
    std::cout << "  exit               退出程序" << std::endl;
}

void showVersion() {
    std::cout << "文件加密/解密工具 v" << (int)MAJOR_VERSION << "." << (int)MINOR_VERSION << std::endl;
    std::cout << "使用简单头部标记算法，跨平台支持" << std::endl;
}

/**
 * 批量处理目录
 */
void batchProcessDirectory(const std::string& dirpath) {
    if (!fs::exists(dirpath) || !fs::is_directory(dirpath)) {
        std::cout << "[-] 目录不存在或无法访问: " << dirpath << std::endl;
        return;
    }

    std::vector<std::string> filesToEncrypt;
    std::vector<std::string> filesToDecrypt;

    // 遍历目录
    for (const auto& entry : fs::recursive_directory_iterator(dirpath)) {
        if (fs::is_regular_file(entry)) {
            std::string filepath = entry.path().string();

            // 跳过临时文件
            if (filepath.find(".tmp") != std::string::npos) {
                continue;
            }

            if (isFileEncrypted(filepath)) {
                filesToDecrypt.push_back(filepath);
            }
            else {
                filesToEncrypt.push_back(filepath);
            }
        }
    }

    std::cout << "[+] 找到 " << filesToEncrypt.size() << " 个未加密文件" << std::endl;
    std::cout << "[+] 找到 " << filesToDecrypt.size() << " 个已加密文件" << std::endl;

    char choice;
    std::cout << "是否处理这些文件？(y/n): ";
    std::cin >> choice;

    if (choice != 'y' && choice != 'Y') {
        return;
    }

    // 处理未加密文件
    if (!filesToEncrypt.empty()) {
        std::cout << "开始加密文件..." << std::endl;
        for (const auto& file : filesToEncrypt) {
            std::cout << "  处理: " << file << std::endl;
            encryptFile(file);
        }
    }

    // 处理已加密文件
    if (!filesToDecrypt.empty()) {
        std::cout << "开始解密文件..." << std::endl;
        for (const auto& file : filesToDecrypt) {
            std::cout << "  处理: " << file << std::endl;
            decryptFile(file);
        }
    }

    std::cout << "[+] 批量处理完成！" << std::endl;
}

/**
 * CLI交互模式
 */
void runInteractiveMode() {
    std::cout << "文件加密/解密工具 v" << (int)MAJOR_VERSION << "." << (int)MINOR_VERSION << std::endl;
    std::cout << "输入 'help' 查看命令，'exit' 退出" << std::endl;
    std::cout << std::endl;

    std::string command;
    while (true) {
        std::cout << "> ";
        std::getline(std::cin, command);

        if (command.empty()) continue;

        // 转换为小写
        std::string cmdLower = command;
        std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::tolower);

        if (cmdLower == "exit" || cmdLower == "quit") {
            std::cout << "再见！" << std::endl;
            break;
        }
        else if (cmdLower == "help") {
            showHelp();
        }
        else if (cmdLower.find("encrypt ") == 0) {
            std::string filepath = command.substr(8);
            encryptFile(filepath);
        }
        else if (cmdLower.find("decrypt ") == 0) {
            std::string filepath = command.substr(8);
            decryptFile(filepath);
        }
        else if (cmdLower.find("check ") == 0) {
            std::string filepath = command.substr(6);
            if (isFileEncrypted(filepath)) {
                std::cout << "[+] 文件已被加密" << std::endl;
            }
            else {
                std::cout << "[-] 文件未被加密" << std::endl;
            }
        }
        else if (cmdLower.find("info ") == 0) {
            std::string filepath = command.substr(5);
            showFileInfo(filepath);
        }
        else if (cmdLower.find("batch ") == 0) {
            std::string dirpath = command.substr(6);
            batchProcessDirectory(dirpath);
        }
        else {
            std::cout << "未知命令，输入 'help' 查看可用命令" << std::endl;
        }
    }
}

// ==================== 主函数 ====================
int main(int argc, char* argv[]) {
    // 设置控制台编码（Windows）
#ifdef _WIN32
    SetConsoleOutputCP(65001);  // UTF-8
#endif

    // 处理命令行参数
    if (argc == 1) {
        // 无参数：进入交互模式
        runInteractiveMode();
    }
    else if (argc == 2) {
        std::string arg = argv[1];
        std::transform(arg.begin(), arg.end(), arg.begin(), ::tolower);

        if (arg == "help" || arg == "-h" || arg == "--help") {
            showHelp();
        }
        else if (arg == "version" || arg == "-v" || arg == "--version") {
            showVersion();
        }
        else {
            // 文件路径：自动加密/解密
            std::string filepath = argv[1];

            if (!fs::exists(filepath)) {
                std::cout << "[-] 文件不存在: " << filepath << std::endl;
                return 1;
            }

            if (isFileEncrypted(filepath)) {
                std::cout << "[+] 检测到已加密文件，执行解密..." << std::endl;
                decryptFile(filepath);
            }
            else {
                std::cout << "[+] 检测到未加密文件，执行加密..." << std::endl;
                encryptFile(filepath);
            }
        }
    }
    else {
        std::cout << "[-] 参数过多！使用 'FakeCrypt help' 查看帮助" << std::endl;
        return 1;
    }

    return 0;
}