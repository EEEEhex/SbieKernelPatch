#pragma once
/*****************************************************************//**
 * \file   SigUtil.h
 * \brief  ����ǩ����غ���
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

    // ǰ������
    class HashContext;
    class SignatureVerifier;
    class KeyPairGenerator;

    // ��ϣ��������
    class HashContext {
    private:
        BCRYPT_ALG_HANDLE hAlgorithm;
        BCRYPT_HASH_HANDLE hHash;
        std::vector<BYTE> hashObject;
        BOOL initialized;

    public:
        HashContext();
        ~HashContext();

        // ��ʼ��SHA-256��ϣ
        BOOL Initialize();

        // ��ϣ����
        BOOL HashData(const void* data, ULONG dataSize);

        // ��ɹ�ϣ����ȡ���
        BOOL FinishHash(std::vector<BYTE>& hash);

        // ���ù�ϣ������
        void Reset();

        // ����Ƿ��ѳ�ʼ��
        BOOL IsInitialized() const { return initialized; }
    };

    // ǩ����֤����
    class SignatureVerifier {
    private:
        BCRYPT_ALG_HANDLE hSignAlgorithm;
        BCRYPT_KEY_HANDLE hPublicKey;
        std::vector<BYTE> publicKeyData;
        BOOL initialized;

    public:
        SignatureVerifier();
        ~SignatureVerifier();

        // ��ʼ����֤��
        BOOL Initialize();

        // ���ڴ浼�빫Կ
        BOOL ImportPublicKey(const std::vector<BYTE>& publicKeyBlob);

        // ���ļ����빫Կ
        BOOL ImportPublicKeyFromFile(const std::string& filePath);

        // ��֤ǩ��
        BOOL VerifySignature(const std::vector<BYTE>& hash, const std::vector<BYTE>& signature);

        // ��֤�ļ�ǩ��
        BOOL VerifyFileSignature(const std::string& filePath, const std::vector<BYTE>& signature);

        // ��֤������ǩ��
        BOOL VerifyBufferSignature(const void* buffer, ULONG bufferSize, const std::vector<BYTE>& signature);

        // ����Ƿ��ѳ�ʼ��
        BOOL IsInitialized() const { return initialized; }
    };

    // ��Կ����������
    class KeyPairGenerator {
    private:
        BCRYPT_ALG_HANDLE hAlgorithm;
        BCRYPT_KEY_HANDLE hKeyPair;
        BOOL initialized;

    public:
        KeyPairGenerator();
        ~KeyPairGenerator();

        // ��ʼ��������
        BOOL Initialize();

        // �����µ�ECDSA P-256��Կ��
        BOOL GenerateKeyPair();

        // ������Կ
        BOOL ExportPublicKey(std::vector<BYTE>& publicKeyBlob);

        // ����˽Կ
        BOOL ExportPrivateKey(std::vector<BYTE>& privateKeyBlob);

        // ������Կ�Ե��ļ�
        BOOL SaveKeyPairToFiles(const std::string& publicKeyPath, const std::string& privateKeyPath);

        // ���ļ�������Կ��
        BOOL LoadKeyPairFromFiles(const std::string& publicKeyPath, const std::string& privateKeyPath);

        // ����Ƿ��ѳ�ʼ��
        BOOL IsInitialized() const { return initialized; }
    };

    // ֤��ǩ������
    class CertificateSigner {
    private:
        std::unique_ptr<HashContext> hashContext;
        std::unique_ptr<KeyPairGenerator> keyGenerator;
        std::vector<BYTE> privateKeyData;
        BOOL initialized;

    public:
        CertificateSigner();
        ~CertificateSigner();

        // ��ʼ��ǩ����
        BOOL Initialize();

        // ���ļ�����˽Կ
        BOOL LoadPrivateKey(const std::string& privateKeyPath);

        // ���ڴ����˽Կ
        BOOL LoadPrivateKeyFromMemory(const std::vector<BYTE>& privateKeyBlob);

        // ����֤��ǩ��
        BOOL GenerateCertificateSignature(const std::string& certificateContent, std::vector<BYTE>& signature);

        // ����֤��ǩ��������Base64����
        BOOL GenerateCertificateSignatureBase64(const std::string& certificateContent, std::string& base64Signature);

        // ���ļ���ǩ��
        BOOL SignFile(const std::string& filePath, std::vector<BYTE>& signature);

        // ����Ƿ��ѳ�ʼ��
        BOOL IsInitialized() const { return initialized; }
    };

    // ���ߺ���
    namespace Utils {

        // ������������ת��ΪBase64�ַ���
        std::string BinaryToBase64(const std::vector<BYTE>& data);

        // ��Base64�ַ���ת��Ϊ����������
        std::vector<BYTE> Base64ToBinary(const std::wstring& base64String);

        // �����ַ���ת��ΪUTF-8�ֽ�����
        std::vector<BYTE> WideStringToUtf8(const std::wstring& wideString);

        // ��UTF-8�ֽ�����ת��Ϊ���ַ���
        std::wstring Utf8ToWideString(const std::vector<BYTE>& utf8Data);

        // �����ļ���SHA-256��ϣ
        BOOL CalculateFileHash(const std::string& filePath, std::vector<BYTE>& hash);

        // ���㻺������SHA-256��ϣ
        BOOL CalculateBufferHash(const void* buffer, ULONG bufferSize, std::vector<BYTE>& hash);

        // ��������ֽ�
        std::vector<BYTE> GenerateRandomBytes(ULONG count);

        // ��ȫ���ַ����Ƚ�
        BOOL SecureStringCompare(const std::wstring& str1, const std::wstring& str2);
    }

    // ��������
    namespace Constants {
        constexpr ULONG SIGNATURE_MAX_SIZE = 128 * 1024;  // 128 KB
        constexpr ULONG FILE_MAX_SIZE = 128 * 1024 * 1024;  // 128 MB
        constexpr ULONG FILE_BUFFER_SIZE = 2 * 4096;  // 8 KB

        // �㷨��ʶ��
        constexpr LPCWSTR HASH_ALGORITHM = BCRYPT_SHA256_ALGORITHM;
        constexpr LPCWSTR SIGN_ALGORITHM = BCRYPT_ECDSA_P256_ALGORITHM;
        constexpr ULONG SIGN_ALGORITHM_BITS = 256;

        // ��Կ��ʽ
        constexpr LPCWSTR PUBLIC_KEY_BLOB = BCRYPT_ECCPUBLIC_BLOB;
        constexpr LPCWSTR PRIVATE_KEY_BLOB = BCRYPT_ECCPRIVATE_BLOB;
    }

} // namespace SigUtil
