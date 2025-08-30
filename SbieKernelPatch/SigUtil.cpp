#define NOMINMAX 

#include "SigUtil.h"
#include <fstream>
#include <sstream>

#include <algorithm>
#include <winternl.h>

namespace SigUtil {

    //=============================================================================
    // HashContext 实现
    //=============================================================================

    HashContext::HashContext() : hAlgorithm(NULL), hHash(NULL), initialized(FALSE) {
    }

    HashContext::~HashContext() {
        Reset();
    }

    BOOL HashContext::Initialize() {
        Reset();

        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, Constants::HASH_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }

        ULONG hashObjectSize = 0;
        ULONG resultLength = 0;

        status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(ULONG), &resultLength, 0);
        if (!NT_SUCCESS(status)) {
            Reset();
            return FALSE;
        }

        hashObject.resize(hashObjectSize);

        status = BCryptCreateHash(hAlgorithm, &hHash, hashObject.data(), hashObjectSize, NULL, 0, 0);
        if (!NT_SUCCESS(status)) {
            Reset();
            return FALSE;
        }

        initialized = TRUE;
        return TRUE;
    }

    BOOL HashContext::HashData(const void* data, ULONG dataSize) {
        if (!initialized || !hHash) return FALSE;

        NTSTATUS status = BCryptHashData(hHash, (PUCHAR)data, dataSize, 0);
        return NT_SUCCESS(status);
    }

    BOOL HashContext::FinishHash(std::vector<BYTE>& hash) {
        if (!initialized || !hHash) return FALSE;

        ULONG hashSize = 0;
        ULONG resultLength = 0;

        NTSTATUS status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&hashSize, sizeof(ULONG), &resultLength, 0);
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }

        hash.resize(hashSize);

        status = BCryptFinishHash(hHash, hash.data(), hashSize, 0);
        if (!NT_SUCCESS(status)) {
            hash.clear();
            return FALSE;
        }

        return TRUE;
    }

    void HashContext::Reset() {
        if (hHash) {
            BCryptDestroyHash(hHash);
            hHash = NULL;
        }

        if (hAlgorithm) {
            BCryptCloseAlgorithmProvider(hAlgorithm, 0);
            hAlgorithm = NULL;
        }

        hashObject.clear();
        initialized = FALSE;
    }

    //=============================================================================
    // SignatureVerifier 实现
    //=============================================================================

    SignatureVerifier::SignatureVerifier() : hSignAlgorithm(NULL), hPublicKey(NULL), initialized(FALSE) {
    }

    SignatureVerifier::~SignatureVerifier() {
        if (hPublicKey) {
            BCryptDestroyKey(hPublicKey);
            hPublicKey = NULL;
        }

        if (hSignAlgorithm) {
            BCryptCloseAlgorithmProvider(hSignAlgorithm, 0);
            hSignAlgorithm = NULL;
        }

        publicKeyData.clear();
        initialized = FALSE;
    }

    BOOL SignatureVerifier::Initialize() {
        if (initialized) return TRUE;

        NTSTATUS status = BCryptOpenAlgorithmProvider(&hSignAlgorithm, Constants::SIGN_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }

        initialized = TRUE;
        return TRUE;
    }

    BOOL SignatureVerifier::ImportPublicKey(const std::vector<BYTE>& publicKeyBlob) {
        if (!initialized || !hSignAlgorithm) return FALSE;

        if (hPublicKey) {
            BCryptDestroyKey(hPublicKey);
            hPublicKey = NULL;
        }

        NTSTATUS status = BCryptImportKeyPair(hSignAlgorithm, NULL, Constants::PUBLIC_KEY_BLOB,
            &hPublicKey, (PUCHAR)publicKeyBlob.data(),
            (ULONG)publicKeyBlob.size(), 0);

        if (NT_SUCCESS(status)) {
            publicKeyData = publicKeyBlob;
            return TRUE;
        }

        return FALSE;
    }

    BOOL SignatureVerifier::ImportPublicKeyFromFile(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) return FALSE;

        file.seekg(0, std::ios::end);
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<BYTE> publicKeyBlob(size);
        file.read(reinterpret_cast<char*>(publicKeyBlob.data()), size);

        return ImportPublicKey(publicKeyBlob);
    }

    BOOL SignatureVerifier::VerifySignature(const std::vector<BYTE>& hash, const std::vector<BYTE>& signature) {
        if (!initialized || !hPublicKey) return FALSE;

        NTSTATUS status = BCryptVerifySignature(hPublicKey, NULL, (PUCHAR)hash.data(), (ULONG)hash.size(),
            (PUCHAR)signature.data(), (ULONG)signature.size(), 0);

        return NT_SUCCESS(status);
    }

    BOOL SignatureVerifier::VerifyFileSignature(const std::string& filePath, const std::vector<BYTE>& signature) {
        std::vector<BYTE> fileHash;
        if (!Utils::CalculateFileHash(filePath, fileHash)) {
            return FALSE;
        }

        return VerifySignature(fileHash, signature);
    }

    BOOL SignatureVerifier::VerifyBufferSignature(const void* buffer, ULONG bufferSize, const std::vector<BYTE>& signature) {
        std::vector<BYTE> bufferHash;
        if (!Utils::CalculateBufferHash(buffer, bufferSize, bufferHash)) {
            return FALSE;
        }

        return VerifySignature(bufferHash, signature);
    }

    //=============================================================================
    // KeyPairGenerator 实现
    //=============================================================================

    KeyPairGenerator::KeyPairGenerator() : hAlgorithm(NULL), hKeyPair(NULL), initialized(FALSE) {
    }

    KeyPairGenerator::~KeyPairGenerator() {
        if (hKeyPair) {
            BCryptDestroyKey(hKeyPair);
            hKeyPair = NULL;
        }

        if (hAlgorithm) {
            BCryptCloseAlgorithmProvider(hAlgorithm, 0);
            hAlgorithm = NULL;
        }

        initialized = FALSE;
    }

    BOOL KeyPairGenerator::Initialize() {
        if (initialized) return TRUE;

        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, Constants::SIGN_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }

        initialized = TRUE;
        return TRUE;
    }

    BOOL KeyPairGenerator::GenerateKeyPair() {
        if (!initialized || !hAlgorithm) return FALSE;

        if (hKeyPair) {
            BCryptDestroyKey(hKeyPair);
            hKeyPair = NULL;
        }

        NTSTATUS status = BCryptGenerateKeyPair(hAlgorithm, &hKeyPair, Constants::SIGN_ALGORITHM_BITS, 0);
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }

        status = BCryptFinalizeKeyPair(hKeyPair, 0);
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }

        return TRUE;
    }

    BOOL KeyPairGenerator::ExportPublicKey(std::vector<BYTE>& publicKeyBlob) {
        if (!hKeyPair) return FALSE;

        ULONG publicKeySize = 0;
        NTSTATUS status = BCryptExportKey(hKeyPair, NULL, Constants::PUBLIC_KEY_BLOB, NULL, 0, &publicKeySize, 0);
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }

        publicKeyBlob.resize(publicKeySize);

        status = BCryptExportKey(hKeyPair, NULL, Constants::PUBLIC_KEY_BLOB,
            publicKeyBlob.data(), publicKeySize, &publicKeySize, 0);
        if (!NT_SUCCESS(status)) {
            publicKeyBlob.clear();
            return FALSE;
        }

        return TRUE;
    }

    BOOL KeyPairGenerator::ExportPrivateKey(std::vector<BYTE>& privateKeyBlob) {
        if (!hKeyPair) return FALSE;

        ULONG privateKeySize = 0;
        NTSTATUS status = BCryptExportKey(hKeyPair, NULL, Constants::PRIVATE_KEY_BLOB, NULL, 0, &privateKeySize, 0);
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }

        privateKeyBlob.resize(privateKeySize);

        status = BCryptExportKey(hKeyPair, NULL, Constants::PRIVATE_KEY_BLOB,
            privateKeyBlob.data(), privateKeySize, &privateKeySize, 0);
        if (!NT_SUCCESS(status)) {
            privateKeyBlob.clear();
            return FALSE;
        }

        return TRUE;
    }

    BOOL KeyPairGenerator::SaveKeyPairToFiles(const std::string& publicKeyPath, const std::string& privateKeyPath) {
        std::vector<BYTE> publicKey, privateKey;

        if (!ExportPublicKey(publicKey) || !ExportPrivateKey(privateKey)) {
            return FALSE;
        }

        // 保存公钥
        std::ofstream pubFile(publicKeyPath, std::ios::binary);
        if (!pubFile.is_open()) return FALSE;
        pubFile.write(reinterpret_cast<const char*>(publicKey.data()), publicKey.size());
        pubFile.close();

        // 保存私钥
        std::ofstream privFile(privateKeyPath, std::ios::binary);
        if (!privFile.is_open()) return FALSE;
        privFile.write(reinterpret_cast<const char*>(privateKey.data()), privateKey.size());
        privFile.close();

        return TRUE;
    }

    BOOL KeyPairGenerator::LoadKeyPairFromFiles(const std::string& publicKeyPath, const std::string& privateKeyPath) {
        // 这里只是示例, 实际应用中通常只需要加载私钥进行签名
        // 公钥主要用于验证, 可以从其他地方获取

        std::ifstream privFile(privateKeyPath, std::ios::binary);
        if (!privFile.is_open()) return FALSE;

        privFile.seekg(0, std::ios::end);
        std::streamsize size = privFile.tellg();
        privFile.seekg(0, std::ios::beg);

        std::vector<BYTE> privateKey(size);
        privFile.read(reinterpret_cast<char*>(privateKey.data()), size);

        // 导入私钥
        NTSTATUS status = BCryptImportKeyPair(hAlgorithm, NULL, Constants::PRIVATE_KEY_BLOB,
            &hKeyPair, privateKey.data(), (ULONG)privateKey.size(), 0);

        return NT_SUCCESS(status);
    }

    //=============================================================================
    // CertificateSigner 实现
    //=============================================================================

    CertificateSigner::CertificateSigner() : initialized(FALSE) {
        hashContext = std::make_unique<HashContext>();
        keyGenerator = std::make_unique<KeyPairGenerator>();
    }

    CertificateSigner::~CertificateSigner() {
        privateKeyData.clear();
    }

    BOOL CertificateSigner::Initialize() {
        if (initialized) return TRUE;

        if (!hashContext->Initialize() || !keyGenerator->Initialize()) {
            return FALSE;
        }

        initialized = TRUE;
        return TRUE;
    }

    BOOL CertificateSigner::LoadPrivateKey(const std::string& privateKeyPath) {
        std::ifstream file(privateKeyPath, std::ios::binary);
        if (!file.is_open()) return FALSE;

        file.seekg(0, std::ios::end);
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        privateKeyData.resize(size);
        file.read(reinterpret_cast<char*>(privateKeyData.data()), size);

        return TRUE;
    }

    BOOL CertificateSigner::LoadPrivateKeyFromMemory(const std::vector<BYTE>& privateKeyBlob) {
        privateKeyData = privateKeyBlob;
        return TRUE;
    }

    BOOL CertificateSigner::GenerateCertificateSignature(const std::string& certificateContent, std::vector<BYTE>& signature) {
        if (!initialized || privateKeyData.empty()) return FALSE;

        // 重置哈希上下文
        hashContext->Reset();
        if (!hashContext->Initialize()) return FALSE;

        /*
        // 将证书内容转换为UTF-8并哈希
        //std::vector<BYTE> utf8Data = Utils::WideStringToUtf8(certificateContent);
        std::vector<BYTE> utf8Data(certificateContent.begin(), certificateContent.end());
        if (!hashContext->HashData(utf8Data.data(), (ULONG)utf8Data.size())) {
            return FALSE;
        }
        */
        // 按照KphValidateCertificate的逻辑解析证书内容并哈希
        // 分别哈希每个字段的name和value，跳过SIGNATURE字段
        std::istringstream stream(certificateContent);
        std::string line;
        while (std::getline(stream, line)) {
            // 跳过空行
            if (line.empty()) continue;

            // 查找冒号分隔符
            size_t colonPos = line.find(':');
            if (colonPos == std::string::npos) continue;

            // 提取name和value
            std::string name = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 1);

            // 去除name和value前后的空白字符
            name.erase(0, name.find_first_not_of(" \t"));
            name.erase(name.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);

            // 跳过SIGNATURE字段（不进行哈希）
            if (_stricmp("SIGNATURE", name.c_str()) == 0) {
                continue;
            }

            // 按照KphValidateCertificate的逻辑，分别哈希name和value
            // 转换为UTF-8并哈希name
            std::vector<BYTE> utf8Name(name.begin(), name.end());
            if (!hashContext->HashData(utf8Name.data(), (ULONG)utf8Name.size())) {
                return FALSE;
            }

            // 转换为UTF-8并哈希value
            std::vector<BYTE> utf8Value(value.begin(), value.end());
            if (!hashContext->HashData(utf8Value.data(), (ULONG)utf8Value.size())) {
                return FALSE;
            }
        }
        // 完成哈希
        std::vector<BYTE> hash;
        if (!hashContext->FinishHash(hash)) {
            return FALSE;
        }

        // 使用私钥签名
        BCRYPT_ALG_HANDLE hSignAlg = NULL;
        BCRYPT_KEY_HANDLE hPrivateKey = NULL;
        BOOL result = FALSE;

        do {
            NTSTATUS status = BCryptOpenAlgorithmProvider(&hSignAlg, Constants::SIGN_ALGORITHM, NULL, 0);
            if (!NT_SUCCESS(status)) break;

            status = BCryptImportKeyPair(hSignAlg, NULL, Constants::PRIVATE_KEY_BLOB,
                &hPrivateKey, privateKeyData.data(), (ULONG)privateKeyData.size(), 0);
            if (!NT_SUCCESS(status)) break;

            ULONG signatureSize = 0;
            status = BCryptSignHash(hPrivateKey, NULL, hash.data(), (ULONG)hash.size(),
                NULL, 0, &signatureSize, 0);
            if (!NT_SUCCESS(status)) break;

            signature.resize(signatureSize);

            status = BCryptSignHash(hPrivateKey, NULL, hash.data(), (ULONG)hash.size(),
                signature.data(), signatureSize, &signatureSize, 0);
            if (!NT_SUCCESS(status)) {
                signature.clear();
                break;
            }

            result = TRUE;

        } while (0);

        if (hPrivateKey) BCryptDestroyKey(hPrivateKey);
        if (hSignAlg) BCryptCloseAlgorithmProvider(hSignAlg, 0);

        return result;
    }

    BOOL CertificateSigner::GenerateCertificateSignatureBase64(const std::string& certificateContent, std::string& base64Signature) {
        std::vector<BYTE> signature;
        if (!GenerateCertificateSignature(certificateContent, signature)) {
            return FALSE;
        }

        base64Signature = Utils::BinaryToBase64(signature);
        return TRUE;
    }

    BOOL CertificateSigner::SignFile(const std::string& filePath, std::vector<BYTE>& signature)
    {
        if (!initialized || privateKeyData.empty()) return FALSE;

        // 计算文件的SHA-256哈希
        std::vector<BYTE> fileHash;
        if (!Utils::CalculateFileHash(filePath, fileHash)) {
            return FALSE;
        }

        // 使用私钥签名文件哈希
        BCRYPT_ALG_HANDLE hSignAlg = NULL;
        BCRYPT_KEY_HANDLE hPrivateKey = NULL;
        BOOL result = FALSE;

        do {
            NTSTATUS status = BCryptOpenAlgorithmProvider(&hSignAlg, Constants::SIGN_ALGORITHM, NULL, 0);
            if (!NT_SUCCESS(status)) break;

            status = BCryptImportKeyPair(hSignAlg, NULL, Constants::PRIVATE_KEY_BLOB,
                &hPrivateKey, privateKeyData.data(), (ULONG)privateKeyData.size(), 0);
            if (!NT_SUCCESS(status)) break;

            ULONG signatureSize = 0;
            status = BCryptSignHash(hPrivateKey, NULL, fileHash.data(), (ULONG)fileHash.size(),
                NULL, 0, &signatureSize, 0);
            if (!NT_SUCCESS(status)) break;

            signature.resize(signatureSize);

            status = BCryptSignHash(hPrivateKey, NULL, fileHash.data(), (ULONG)fileHash.size(),
                signature.data(), signatureSize, &signatureSize, 0);
            if (!NT_SUCCESS(status)) {
                signature.clear();
                break;
            }

            result = TRUE;

        } while (0);

        if (hPrivateKey) BCryptDestroyKey(hPrivateKey);
        if (hSignAlg) BCryptCloseAlgorithmProvider(hSignAlg, 0);

        return result;
    }

    //=============================================================================
    // Utils 命名空间实现
    //=============================================================================

    std::string Utils::BinaryToBase64(const std::vector<BYTE>& data) {
        if (data.empty()) return "";

        DWORD base64Length = 0;
        if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64Length)) {
            return "";
        }

        std::string base64String(base64Length, 0);
        if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            (LPSTR)base64String.data(), &base64Length)) {
            return "";
        }

        // 去掉结尾的 '\0'
        if (!base64String.empty() && base64String.back() == '\0') {
            base64String.pop_back();
        }
        return base64String;
        /*
        // 转换为宽字符串
        int wideLength = MultiByteToWideChar(CP_UTF8, 0, base64String.c_str(), -1, NULL, 0);
        if (wideLength <= 0) return L"";

        std::wstring wideString(wideLength - 1, 0);
        if (MultiByteToWideChar(CP_UTF8, 0, base64String.c_str(), -1, &wideString[0], wideLength) <= 0) {
            return L"";
        }

        return wideString;
        */
    }

    std::vector<BYTE> Utils::Base64ToBinary(const std::wstring& base64String) {
        if (base64String.empty()) return std::vector<BYTE>();

        // 转换为多字节字符串
        int multiByteLength = WideCharToMultiByte(CP_UTF8, 0, base64String.c_str(), -1, NULL, 0, NULL, NULL);
        if (multiByteLength <= 0) return std::vector<BYTE>();

        std::string multiByteString(multiByteLength - 1, 0);
        if (WideCharToMultiByte(CP_UTF8, 0, base64String.c_str(), -1, &multiByteString[0], multiByteLength, NULL, NULL) <= 0) {
            return std::vector<BYTE>();
        }

        DWORD binaryLength = 0;
        if (!CryptStringToBinaryA(multiByteString.c_str(), 0, CRYPT_STRING_BASE64, NULL, &binaryLength, NULL, NULL)) {
            return std::vector<BYTE>();
        }

        std::vector<BYTE> binaryData(binaryLength);
        if (!CryptStringToBinaryA(multiByteString.c_str(), 0, CRYPT_STRING_BASE64,
            binaryData.data(), &binaryLength, NULL, NULL)) {
            return std::vector<BYTE>();
        }

        binaryData.resize(binaryLength);
        return binaryData;
    }

    std::vector<BYTE> Utils::WideStringToUtf8(const std::wstring& wideString) {
        if (wideString.empty()) return std::vector<BYTE>();

        int utf8Length = WideCharToMultiByte(CP_UTF8, 0, wideString.c_str(), -1, NULL, 0, NULL, NULL);
        if (utf8Length <= 0) return std::vector<BYTE>();

        std::vector<BYTE> utf8Data(utf8Length - 1);
        if (WideCharToMultiByte(CP_UTF8, 0, wideString.c_str(), -1,
            reinterpret_cast<LPSTR>(utf8Data.data()), utf8Length, NULL, NULL) <= 0) {
            return std::vector<BYTE>();
        }

        return utf8Data;
    }

    std::wstring Utils::Utf8ToWideString(const std::vector<BYTE>& utf8Data) {
        if (utf8Data.empty()) return L"";

        int wideLength = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<LPCCH>(utf8Data.data()),
            (int)utf8Data.size(), NULL, 0);
        if (wideLength <= 0) return L"";

        std::wstring wideString(wideLength, 0);
        if (MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<LPCCH>(utf8Data.data()),
            (int)utf8Data.size(), &wideString[0], wideLength) <= 0) {
            return L"";
        }

        return wideString;
    }

    BOOL Utils::CalculateFileHash(const std::string& filePath, std::vector<BYTE>& hash) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) return FALSE;

        file.seekg(0, std::ios::end);
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        if (size > Constants::FILE_MAX_SIZE) return FALSE;

        std::vector<BYTE> buffer(Constants::FILE_BUFFER_SIZE);
        HashContext hashContext;

        if (!hashContext.Initialize()) return FALSE;

        std::streamsize remaining = size;
        while (remaining > 0) {
            std::streamsize toRead = std::min(remaining, (std::streamsize)Constants::FILE_BUFFER_SIZE);
            file.read(reinterpret_cast<char*>(buffer.data()), toRead);

            if (!hashContext.HashData(buffer.data(), (ULONG)toRead)) {
                return FALSE;
            }

            remaining -= toRead;
        }

        return hashContext.FinishHash(hash);
    }

    BOOL Utils::CalculateBufferHash(const void* buffer, ULONG bufferSize, std::vector<BYTE>& hash) {
        if (!buffer || bufferSize == 0) return FALSE;

        HashContext hashContext;
        if (!hashContext.Initialize()) return FALSE;

        if (!hashContext.HashData(buffer, bufferSize)) return FALSE;

        return hashContext.FinishHash(hash);
    }

    std::vector<BYTE> Utils::GenerateRandomBytes(ULONG count) {
        std::vector<BYTE> randomBytes(count);

        BCRYPT_ALG_HANDLE hRng = NULL;
        if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0))) {
            BCryptGenRandom(hRng, randomBytes.data(), count, 0);
            BCryptCloseAlgorithmProvider(hRng, 0);
        }

        return randomBytes;
    }

    BOOL Utils::SecureStringCompare(const std::wstring& str1, const std::wstring& str2) {
        if (str1.length() != str2.length()) return FALSE;

        // 使用常量时间比较防止时序攻击
        BYTE result = 0;
        for (size_t i = 0; i < str1.length(); i++) {
            result |= str1[i] ^ str2[i];
        }

        return result == 0;
    }

} // namespace SigUtil
