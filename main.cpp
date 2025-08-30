#include <fstream>
#include "args.hxx"             //命令行解析

#include "Utils.h"              //工具函数
#include "SigUtil.h"            //签名相关函数
#include "SbieUtil.h"           //Sbie相关函数
#include "DriverUtil.h"         //驱动操作相关函数
#include "DriverInterface.h"    //echo驱动接口

#pragma comment(lib, "ntdll.lib")

#define INSTANCE_NAME "SbieKernelPatch"
#define ECHO_DRV_NAME "EchoDrv"

#define CERTIFICATE_FILE "Certificate.dat"
#define PUBLIC_KEY_FILE "skp_public_key.blob"
#define PRIVATE_KEY_FILE "skp_private_key.blob"

#define SBIEDRV_NAME "SbieDrv.sys"
#define SBIEPDB_NAME "SbieDrv.pdb"
#define SANDMAN_EXE "SandMan.exe"
#define SANDMAN_SIG "SandMan.exe.sig"
#define SANDMAN_SIG_BAK "SandMan.exe.sig.bak"

#define SKP_VERSION "1.0.0"
#define SKP_VERSION_NAME "SbieKernelPatch v" SKP_VERSION

//HWID
std::string g_hwid;

//默认的公钥和私钥
std::vector<uint8_t> default_private_key = {
    0x45, 0x43, 0x53, 0x32, 0x20, 0x00, 0x00, 0x00, 0xE7, 0x9F, 0x30, 0x17, 0x88, 0x6A, 0x5C, 0x27,
    0xBD, 0x93, 0xCE, 0xA7, 0xE7, 0xD3, 0xE2, 0x2C, 0x2D, 0x90, 0xF6, 0x13, 0xAC, 0x19, 0x32, 0x36,
    0xA5, 0x0B, 0xFB, 0x9B, 0x53, 0x86, 0x8B, 0xFD, 0x67, 0x9A, 0x7B, 0x8F, 0x8D, 0x4F, 0x94, 0xA8,
    0xCF, 0xD0, 0x10, 0x99, 0x84, 0x3C, 0x77, 0xAD, 0xA1, 0xF7, 0xF0, 0x6A, 0xB5, 0xF3, 0x1F, 0x75,
    0x2E, 0x5C, 0xF5, 0x4F, 0x88, 0x01, 0x24, 0x92, 0x98, 0x43, 0x11, 0xCA, 0xF5, 0x75, 0x03, 0xB4,
    0xA3, 0x16, 0xD7, 0x6F, 0x4D, 0x06, 0xE0, 0xC8, 0xF0, 0x04, 0xCA, 0xF5, 0xF0, 0x16, 0x8F, 0xD5,
    0xC2, 0x89, 0x12, 0xFA, 0xA5, 0x90, 0x1E, 0xE6
}; //104
std::vector<uint8_t> default_publick_key = {
    0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00, 0xE7, 0x9F, 0x30, 0x17, 0x88, 0x6A, 0x5C, 0x27,
    0xBD, 0x93, 0xCE, 0xA7, 0xE7, 0xD3, 0xE2, 0x2C, 0x2D, 0x90, 0xF6, 0x13, 0xAC, 0x19, 0x32, 0x36,
    0xA5, 0x0B, 0xFB, 0x9B, 0x53, 0x86, 0x8B, 0xFD, 0x67, 0x9A, 0x7B, 0x8F, 0x8D, 0x4F, 0x94, 0xA8,
    0xCF, 0xD0, 0x10, 0x99, 0x84, 0x3C, 0x77, 0xAD, 0xA1, 0xF7, 0xF0, 0x6A, 0xB5, 0xF3, 0x1F, 0x75,
    0x2E, 0x5C, 0xF5, 0x4F, 0x88, 0x01, 0x24, 0x92
}; //72

bool GenerateNewKeyPair() {
    SigUtil::KeyPairGenerator keyGen;
    if (!keyGen.Initialize()) {
        std::cout << "[!] Init KeyPairGenerator failed!" << std::endl;
        return false;
    }

    if (!keyGen.GenerateKeyPair()) {
        std::cout << "[!] Genrate key pair failed!" << std::endl;
        return false;
    }

    // 保存密钥对到文件
    if (keyGen.SaveKeyPairToFiles(PUBLIC_KEY_FILE, PRIVATE_KEY_FILE)) {
        std::cout << "[+] Save key pair to " << PUBLIC_KEY_FILE << " & " << PRIVATE_KEY_FILE << std::endl;
        return true;
    }
    else {
        std::cout << "[!] Save key pair failed!" << std::endl;
        return false;
    }

    return true;
}

bool GenerateCertificateFile(std::string cert_txt = "", std::string hwid = "") {
    SigUtil::CertificateSigner signer;
    if (!signer.Initialize()) {
        std::cout << "[!] Init signer failed!" << std::endl;
        return false;
    }

    // 加载私钥
    if (!signer.LoadPrivateKeyFromMemory(default_private_key)) {
        std::cout << "[!] Load private key from mem failed!" << std::endl;
        return false;
    }

    // 没有用户输入cert, 使用默认模板
    std::string certificateContent;
    if (cert_txt.empty()) {
        if (hwid.empty()) {
            std::cout << "[!] Need arg hwid!" << std::endl;
            return false; // 默认模板需要hwid信息
        }

        // 默认证书内容, ETERNAL为最高权限, 没有过期日期
        std::string certDefaultTemplate =
            "DATE: %s\n"
            "TYPE: ETERNAL\n"
            "OPTIONS: SBOX,EBOX,NETI,DESK\n"
            "HWID: %s\n";
        std::string curDate = Utils::GetCurrentDateString();

        char buffer[512]; //格式化模板字符串
        snprintf(buffer, sizeof(buffer), certDefaultTemplate.c_str(), curDate.c_str(), hwid.c_str());
        certificateContent = buffer;   
    }
    else {
        certificateContent = cert_txt;
        Utils::RemoveLineWithPrefix(certificateContent, "SIGNATURE"); //删掉SIGNATURE行
    }

    // 生成签名
    std::string base64Signature;
    if (signer.GenerateCertificateSignatureBase64(certificateContent, base64Signature)) {
        std::cout << "[+] Base64 Sig: " << base64Signature << std::endl;

        // 保存完整的证书文件
        std::ofstream certFile(CERTIFICATE_FILE, std::ios::out | std::ios::trunc | std::ios::binary); //已存在则覆盖
        if (certFile.is_open()) {
            certFile << certificateContent;
            certFile << "SIGNATURE: " << base64Signature; //<< std::endl;
            certFile.close();
            std::cout << "[+] Save Cert info to " << CERTIFICATE_FILE << std::endl;
        }
    }
    else {
        std::cout << "[!] Genrate cert sig failed!" << std::endl;
        return false;
    }
    return true;
}

bool SignSandMan(std::vector<uint8_t>& sig_bytes) {
    SigUtil::CertificateSigner signer;
    if (!signer.Initialize()) {
        std::cout << "[!] Init signer failed!" << std::endl;
        return false;
    }

    // 加载私钥
    if (!signer.LoadPrivateKeyFromMemory(default_private_key)) {
        std::cout << "[!] Load private key from mem failed!" << std::endl;
        return false;
    }

    if (!signer.SignFile(SANDMAN_EXE, sig_bytes)) {
        std::cout << "[!] Sign fle " << SANDMAN_EXE << " failed!" << std::endl;
        return false;
    }
    return true;
}

int main(int argc, char* argv[])
{
    args::ArgumentParser parser("Crack Sandboxie-Plus by patch sbiedrv.sys's public key.", SKP_VERSION_NAME);
    args::HelpFlag help(parser, "help", "Display this help menu", { 'h', "help" });
    args::Flag new_key(parser, "new_key", "Use new ECDSA key", { 'n', "new" });
    args::ValueFlag<std::string> cert_file(parser, "cert_file", "Replace the signature field in the specified Cert file", { 'c', "cert"});
    args::Flag keep_echodrv(parser, "keep_ehcodrv", "Keep Echo drv running after patch", { 'k', "keep" });
    args::Flag set_autorun(parser, "set_autorun", "Set autorun", { 'a', "autor" });
    args::Flag unset_autorun(parser, "unset_autorun", "Unset autorun", { 'u', "uautor" });
    args::Flag readonly_key(parser, "readonly_key", "Only read KphpTrustedPublicKey", {'r', "read"});
    args::Flag silent_run(parser, "silent_run", "Run silently without console", {'s', "silent"});
    try
    {
        parser.ParseCLI(argc, argv);
    }
    catch (const args::Completion& e)
    {
        std::cout << e.what();
        return 0;
    }
    catch (const args::Help&)
    {
        std::cout << parser;
        return 0;
    }
    catch (const args::ParseError& e)
    {
        std::cerr << e.what() << std::endl;
        std::cerr << parser;
        return 1;
    }
    if (silent_run) Utils::HideConsoleWindow();
    Utils::SetWorkDirToExeDir(); //设置工作目录

    // 设置/取消程序开机自启
    if (set_autorun) {
        if (Utils::SetAutoRun(INSTANCE_NAME)) {
            std::cout << "[+] Set " << INSTANCE_NAME << " autorun success!" << std::endl;
        }
        else {
            std::cout << "[!] Error: Utils::SetAutoRun Failed!" << std::endl;
        }
    }
    else if (unset_autorun) {
        if (Utils::CancelAutoRun(INSTANCE_NAME)) {
            std::cout << "[+] Cancel " << INSTANCE_NAME << " autorun success!" << std::endl;
        }
        else {
            std::cout << "[!] Error: Utils::CancelAutoRun Failed!" << std::endl;
        }
    }

    // 生成新的密钥对
    if (new_key) {
        std::cout << "[+] Begin genrate new ECDSA P-256 pair key..." << std::endl;
        if (!GenerateNewKeyPair()) {
            std::cout << "[!] Error: GenerateNewKeyPair Failed!" << std::endl;
            return -1;
        }
    }
    
    // 如果存在public_key.blob和private_key.blob则使用这个公钥进行Patch
    if (Utils::FileExists(PUBLIC_KEY_FILE) && Utils::FileExists(PRIVATE_KEY_FILE)) {
        std::cout << "[+] Read public/private key from " PUBLIC_KEY_FILE << "/" << PRIVATE_KEY_FILE << std::endl;
        if (!Utils::ReadFileToMem(PUBLIC_KEY_FILE, default_publick_key) ||
            !Utils::ReadFileToMem(PRIVATE_KEY_FILE, default_private_key)) {
            std::cout << "[!] Error: ReadFileToMem Failed!" << std::endl;
            return -1;
        }
    }

    // 如果要重新签名证书内容
    if (cert_file) {
        std::string cert_file_path = args::get(cert_file);
        if (!Utils::FileExists(cert_file_path)) {
            std::cout << "[!] Error: Can't find cert file!" << std::endl;
            return -1;
        }
        std::string cert_txt;
        if (!Utils::ReadFileToString(cert_file_path, cert_txt)) {
            std::cout << "[!] Error: Can't read cert file!" << std::endl;
            return -1;
        }
        if (!GenerateCertificateFile(cert_txt, g_hwid)) {
            std::cout << "[!] Error: GenerateCertificateFile Failed!" << std::endl;
            return -1;
        }
        std::cout << "[+] Re-signing certificate content completed!" << std::endl;
        return 0;
    }
    
    // 如果不存在Certificate.dat, 则生成一个默认的, 或者有-n参数也要重新生成
    if (!Utils::FileExists(CERTIFICATE_FILE) || new_key) {
        std::cout << "[=] Begin genrate and write \'Certificate.dat\'..." << std::endl;
        g_hwid = SbieUtil::InitFwUuid();
        if (g_hwid.empty()) {
            std::cout << "[!] Error: SbieUtil::InitFwUuid Failed!" << std::endl;
            return -1;
        }
        std::cout << "[+] Get HWID: " << g_hwid << std::endl;
        if (!GenerateCertificateFile("", g_hwid)) {
            std::cout << "[!] Error: GenerateCertificateFile Failed!" << std::endl;
            return -1;
        }
        std::cout << "[+] Genrate and write default \'" << CERTIFICATE_FILE << "\' over!" << std::endl;
    }
    
    // 安装/启动EchoDrv驱动
    std::string cur_path = Utils::GetCurrentProcessDir();
    std::cout << "[=] Begin Reg and Start \'echo.sys\'(EchoDrv)..." << std::endl;

    std::string echodrv_path = cur_path + "\\echo.sys";
    bool result = DriverUtil::InstallDriver(ECHO_DRV_NAME, echodrv_path);
    if (!result) {
        std::cout << "[!] Error: can't install echo driver!" << std::endl;
        return -1;
    }

    result = DriverUtil::StartDriver(ECHO_DRV_NAME);
    if (!result) {
        std::cout << "[!] Error: can't start echo driver!" << std::endl;
        return -1;
    }

    // 获取SbieDrv.sys的基址
    std::cout << "[=] Begin search \'SbieDrv.sys\'..." << std::endl;
    DriverInterface Driver; // Instantiate our driver
    HANDLE processHandle = Driver.get_handle_for_pid(GetCurrentProcessId()); // Fetch a HANDLE for our own program.

    NTSTATUS status; // Status variable
    PRTL_PROCESS_MODULES ModuleInfo; // Store modules
    uintptr_t SbieDrvBaseAddress = NULL;   // SbieDrv.sys base address

    // Leak SbieDrv.sys base address using NtQuerySystemInformation
    ModuleInfo = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!ModuleInfo) {
        printf("[!] Error allocating module memory! Error Code: %lu", GetLastError());
        Driver.Shutdown();
        return -1;
    }

    // Call NtQuerySystemInformation and ask for the System module list.
    if (!NT_SUCCESS(status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, ModuleInfo, 1024 * 1024,
        NULL))) // 11 = SystemModuleInformation
    {
        printf("\n[!] Error: Unable to query module list (%#x)\n", status);

        VirtualFree(ModuleInfo, 0, MEM_RELEASE);
        Driver.Shutdown();
        return -1;
    }

    // Iterate through module list till we find the Kernel base address.
    // We do this by iterating through the list till we find a module named "ntoskrnl.exe" - this is the Kernel.
    for (int i = 0; i < ModuleInfo->NumberOfModules; i++) {
#ifdef _DEBUG
        std::cout << "[D] ModuleName: " << ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName << std::endl;
#endif // 输出模块信息
        if (!strcmp((const char*)ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName,
            "SbieDrv.sys")) {
            SbieDrvBaseAddress = (uintptr_t)ModuleInfo->Modules[i].ImageBase;
            break;
        }
    }

    // Clear that buffer now we don't need it.
    VirtualFree(ModuleInfo, 0, MEM_RELEASE);

    if (SbieDrvBaseAddress == 0) {
        std::cout << "[!] Error: Can't find SbieDrv.sys base address!" << std::endl;
        return -1;
    }

    std::cout << "[+] SbieDrv.sys base address: 0x" << std::hex << SbieDrvBaseAddress << std::dec << std::endl;
    
    // 读取KphpTrustedPublicKey公钥, 利用pdb信息获取变量偏移
    std::cout << "[=] Begin get KphpTrustedPublicKey offset from pdb..." << std::endl;
    uint64_t KphpTrustedPublicKeyOffset = SbieUtil::GetSymbolOffset(SBIEDRV_NAME, SBIEPDB_NAME, "KphpTrustedPublicKey"),
        KphpTrustedPublicKeyAddress = SbieDrvBaseAddress + KphpTrustedPublicKeyOffset;
    if (KphpTrustedPublicKeyOffset < 0) {
        std::cout << "[!] Error: GetSymbolOffset KphpTrustedPublicKeyOffset from " << SBIEPDB_NAME << " Failed!" << std::endl;
        return -1;
    }
    std::cout << "[+] KphpTrustedPublicKey offset: 0x" << std::hex << KphpTrustedPublicKeyOffset << std::dec << std::endl;
    
    uint8_t KphpTrustedPublicKey[72] = { 0 };
    BOOL bResult = Driver.read_memory_raw((void*)KphpTrustedPublicKeyAddress, KphpTrustedPublicKey, 72, processHandle);
    if (!bResult) {
        std::cout << "[!] Error: Driver.read_memory_raw Failed!" << std::endl;
        goto CLEAN;
    }

    std::cout << "[+] KphpTrustedPublicKey: [ " << std::endl;
    for (size_t i = 0; i < 72; i++)
    {
        printf("0x%02X ", KphpTrustedPublicKey[i]);
    }
    std::cout << " ]" << std::endl;
    //  如果没有只读取public key参数, 进行Patch
    if (!readonly_key) {
        std::cout << "[=] Begin Patch KphpTrustedPublicKey to self own key..." << std::endl;
        bResult = Driver.read_memory_raw((void*)(default_publick_key.data()), (void*)KphpTrustedPublicKeyAddress, 72, processHandle);
        if (bResult) {
            std::cout << "[+] Patch SbieDrv.sys Public Key Over!" << std::endl;
            bResult = Driver.read_memory_raw((void*)KphpTrustedPublicKeyAddress, KphpTrustedPublicKey, 72, processHandle);
            std::cout << "[+] New KphpTrustedPublicKey: [ " << std::endl;
            for (size_t i = 0; i < 72; i++)
            {
                printf("0x%02X ", KphpTrustedPublicKey[i]);
            }
            std::cout << " ]" << std::endl;
            std::cout << "\033[31m" << "[@] Enjoy the Sandboxie-Plus..." << "\033[0m" << std::endl;
        }
        else {
            std::cout << "[!] Patch Failed!" << std::endl;
        }

        //开始修改SandMan.exe.sig
        if (!Utils::FileExists(SANDMAN_SIG_BAK)) {
            //备份SandMax.exe.sig
            if (rename(SANDMAN_SIG, SANDMAN_SIG_BAK) ！= 0) {
				std::cout << "[!] Warning: Rename " << SANDMAN_SIG << " to " << SANDMAN_SIG_BAK << " failed!" << std::endl;
            }
        }
        std::vector<uint8_t> sig_bytes;
        if (!SignSandMan(sig_bytes)) {
            std::cout << "[!] Error: SignSandMan failed!" << std::endl;
            goto CLEAN;
        }
        if (!Utils::WriteMemToFile(SANDMAN_SIG, sig_bytes)) {
            std::cout << "[!] Error: write new sign to " << SANDMAN_SIG << " failed!" << std::endl;
            goto CLEAN;
        }
        std::cout << "[+] Write new sign to " << SANDMAN_SIG << " success!" << std::endl;
    }

CLEAN:
    //运行完卸载EchoDrv驱动
    if (!keep_echodrv) { 
        std::cout << "[=] Begin Stop and Delete \'EchoDrv\'..." << std::endl;
        bool result = DriverUtil::StopDriver(ECHO_DRV_NAME);
        if (result) {
            result = DriverUtil::DeleteDriver(ECHO_DRV_NAME);
            if (!result)
                std::cout << "[!] Error: can't delete echo driver!" << std::endl;
        }
        else {
            std::cout << "[!] Error: can't stop echo driver!" << std::endl;
        }
    }

    return 0;
}
