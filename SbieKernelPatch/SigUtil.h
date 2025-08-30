#pragma once
/*****************************************************************//**
 * \file   SigUtil.h
 * \brief  数字签名相关函数
 *********************************************************************/
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <memory>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace SigUtil {

    // 前向声明
    class HashContext;
    class SignatureVerifier;
    class KeyPairGenerator;

    // 哈希上下文类
    class HashContext {
    private:
        BCRYPT_ALG_HANDLE hAlgorithm;
        BCRYPT_HASH_HANDLE hHash;
        std::vector<BYTE> hashObject;
        BOOL initialized;

    public:
        HashContext();
        ~HashContext();

        // 初始化SHA-256哈希
        BOOL Initialize();

        // 哈希数据
        BOOL HashData(const void* data, ULONG dataSize);

        // 完成哈希并获取结果
        BOOL FinishHash(std::vector<BYTE>& hash);

        // 重置哈希上下文
        void Reset();

        // 检查是否已初始化
        BOOL IsInitialized() const { return initialized; }
    };

    // 签名验证器类
    class SignatureVerifier {
    private:
        BCRYPT_ALG_HANDLE hSignAlgorithm;
        BCRYPT_KEY_HANDLE hPublicKey;
        std::vector<BYTE> publicKeyData;
        BOOL initialized;

    public:
        SignatureVerifier();
        ~SignatureVerifier();

        // 初始化验证器
        BOOL Initialize();

        // 从内存导入公钥
        BOOL ImportPublicKey(const std::vector<BYTE>& publicKeyBlob);

        // 从文件导入公钥
        BOOL ImportPublicKeyFromFile(const std::string& filePath);

        // 验证签名
        BOOL VerifySignature(const std::vector<BYTE>& hash, const std::vector<BYTE>& signature);

        // 验证文件签名
        BOOL VerifyFileSignature(const std::string& filePath, const std::vector<BYTE>& signature);

        // 验证缓冲区签名
        BOOL VerifyBufferSignature(const void* buffer, ULONG bufferSize, const std::vector<BYTE>& signature);

        // 检查是否已初始化
        BOOL IsInitialized() const { return initialized; }
    };

    // 密钥对生成器类
    class KeyPairGenerator {
    private:
        BCRYPT_ALG_HANDLE hAlgorithm;
        BCRYPT_KEY_HANDLE hKeyPair;
        BOOL initialized;

    public:
        KeyPairGenerator();
        ~KeyPairGenerator();

        // 初始化生成器
        BOOL Initialize();

        // 生成新的ECDSA P-256密钥对
        BOOL GenerateKeyPair();

        // 导出公钥
        BOOL ExportPublicKey(std::vector<BYTE>& publicKeyBlob);

        // 导出私钥
        BOOL ExportPrivateKey(std::vector<BYTE>& privateKeyBlob);

        // 保存密钥对到文件
        BOOL SaveKeyPairToFiles(const std::string& publicKeyPath, const std::string& privateKeyPath);

        // 从文件加载密钥对
        BOOL LoadKeyPairFromFiles(const std::string& publicKeyPath, const std::string& privateKeyPath);

        // 检查是否已初始化
        BOOL IsInitialized() const { return initialized; }
    };

    // 证书签名器类
    class CertificateSigner {
    private:
        std::unique_ptr<HashContext> hashContext;
        std::unique_ptr<KeyPairGenerator> keyGenerator;
        std::vector<BYTE> privateKeyData;
        BOOL initialized;

    public:
        CertificateSigner();
        ~CertificateSigner();

        // 初始化签名器
        BOOL Initialize();

        // 从文件加载私钥
        BOOL LoadPrivateKey(const std::string& privateKeyPath);

        // 从内存加载私钥
        BOOL LoadPrivateKeyFromMemory(const std::vector<BYTE>& privateKeyBlob);

        // 生成证书签名
        BOOL GenerateCertificateSignature(const std::string& certificateContent, std::vector<BYTE>& signature);

        // 生成证书签名并返回Base64编码
        BOOL GenerateCertificateSignatureBase64(const std::string& certificateContent, std::string& base64Signature);

        // 给文件做签名
        BOOL SignFile(const std::string& filePath, std::vector<BYTE>& signature);

        // 检查是否已初始化
        BOOL IsInitialized() const { return initialized; }
    };

    // 工具函数
    namespace Utils {

        // 将二进制数据转换为Base64字符串
        std::string BinaryToBase64(const std::vector<BYTE>& data);

        // 将Base64字符串转换为二进制数据
        std::vector<BYTE> Base64ToBinary(const std::wstring& base64String);

        // 将宽字符串转换为UTF-8字节数组
        std::vector<BYTE> WideStringToUtf8(const std::wstring& wideString);

        // 将UTF-8字节数组转换为宽字符串
        std::wstring Utf8ToWideString(const std::vector<BYTE>& utf8Data);

        // 计算文件的SHA-256哈希
        BOOL CalculateFileHash(const std::string& filePath, std::vector<BYTE>& hash);

        // 计算缓冲区的SHA-256哈希
        BOOL CalculateBufferHash(const void* buffer, ULONG bufferSize, std::vector<BYTE>& hash);

        // 生成随机字节
        std::vector<BYTE> GenerateRandomBytes(ULONG count);

        // 安全的字符串比较
        BOOL SecureStringCompare(const std::wstring& str1, const std::wstring& str2);
    }

    // 常量定义
    namespace Constants {
        constexpr ULONG SIGNATURE_MAX_SIZE = 128 * 1024;  // 128 KB
        constexpr ULONG FILE_MAX_SIZE = 128 * 1024 * 1024;  // 128 MB
        constexpr ULONG FILE_BUFFER_SIZE = 2 * 4096;  // 8 KB

        // 算法标识符
        constexpr LPCWSTR HASH_ALGORITHM = BCRYPT_SHA256_ALGORITHM;
        constexpr LPCWSTR SIGN_ALGORITHM = BCRYPT_ECDSA_P256_ALGORITHM;
        constexpr ULONG SIGN_ALGORITHM_BITS = 256;

        // 密钥格式
        constexpr LPCWSTR PUBLIC_KEY_BLOB = BCRYPT_ECCPUBLIC_BLOB;
        constexpr LPCWSTR PRIVATE_KEY_BLOB = BCRYPT_ECCPRIVATE_BLOB;
    }

} // namespace SigUtil
