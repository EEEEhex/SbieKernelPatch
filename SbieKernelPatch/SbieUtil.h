#pragma once
/*****************************************************************//**
 * \file   SbieUtil.h
 * \brief  Sbie相关函数, 获取HWID, 获取pdb中变量偏移等
 *********************************************************************/
#include <windows.h>
#include <string>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

namespace SbieUtil {
    // SMBIOS Structure header
    typedef struct _dmi_header {
        UCHAR type;
        UCHAR length;
        USHORT handle;
        UCHAR data[1];
    } dmi_header;

    // Raw SMBIOS data returned by GetSystemFirmwareTable
    typedef struct _RawSMBIOSData {
        UCHAR  Used20CallingMethod;
        UCHAR  SMBIOSMajorVersion;
        UCHAR  SMBIOSMinorVersion;
        UCHAR  DmiRevision;
        DWORD  Length;
        UCHAR  SMBIOSTableData[1];
    } RawSMBIOSData;

    // 将单字节转为 HEX 字符串（宽字符）
    wchar_t* hexbyte(UCHAR b, wchar_t* ptr)
    {
        static const wchar_t* digits = L"0123456789ABCDEF";
        *ptr++ = digits[b >> 4];
        *ptr++ = digits[b & 0x0F];
        return ptr;
    }

    // 获取固件UUID, 成功返回 TRUE
    BOOL GetFwUuid(UCHAR* uuid)
    {
        BOOL result = FALSE;

        // 第一次调用获取所需缓冲大小
        UINT bufferSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
        if (bufferSize == 0)
            return FALSE;

        BYTE* buffer = (BYTE*)malloc(bufferSize);
        if (!buffer)
            return FALSE;

        if (GetSystemFirmwareTable('RSMB', 0, buffer, bufferSize) != bufferSize) {
            free(buffer);
            return FALSE;
        }

        RawSMBIOSData* smb = (RawSMBIOSData*)buffer;

        for (UCHAR* data = smb->SMBIOSTableData;
            data < smb->SMBIOSTableData + smb->Length;)
        {
            dmi_header* h = (dmi_header*)data;
            if (h->length < 4)
                break;

            // Type 0x01 = System Information
            if (h->type == 0x01 && h->length >= 0x19)
            {
                UCHAR* uuidField = data + 0x08; // UUID 偏移

                BOOL all_zero = TRUE, all_one = TRUE;
                for (int i = 0; i < 16 && (all_zero || all_one); i++)
                {
                    if (uuidField[i] != 0x00) all_zero = FALSE;
                    if (uuidField[i] != 0xFF) all_one = FALSE;
                }

                if (!all_zero && !all_one)
                {
                    // SMBIOS 2.6+ UUID 前3个字段是小端
                    uuid[0] = uuidField[3];
                    uuid[1] = uuidField[2];
                    uuid[2] = uuidField[1];
                    uuid[3] = uuidField[0];
                    uuid[4] = uuidField[5];
                    uuid[5] = uuidField[4];
                    uuid[6] = uuidField[7];
                    uuid[7] = uuidField[6];
                    for (int i = 8; i < 16; i++)
                        uuid[i] = uuidField[i];

                    result = TRUE;
                }
                break;
            }

            // 跳过 formatted area
            UCHAR* next = data + h->length;
            // 跳过 unformatted strings 区域（以 0x0000 结束）
            while (next < smb->SMBIOSTableData + smb->Length &&
                (next[0] != 0 || next[1] != 0))
                next++;
            next += 2;
            data = next;
        }

        free(buffer);
        return result;
    }

    // 转换 wchar_t* 到 std::string (UTF-8 编码)
    std::string WcharToString(const wchar_t* wstr)
    {
        if (!wstr) return std::string();

        int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
        if (len <= 0) return std::string();

        std::string str(len - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &str[0], len, NULL, NULL);
        return str;
    }

    // 初始化并格式化为 UUID 字符串
    std::string InitFwUuid()
    {
        wchar_t g_uuid_str[40] = { 0 };
        UCHAR uuid[16];
        if (GetFwUuid(uuid))
        {
            wchar_t* ptr = g_uuid_str;
            int i;
            for (i = 0; i < 4; i++)
                ptr = hexbyte(uuid[i], ptr);
            *ptr++ = '-';
            for (; i < 6; i++)
                ptr = hexbyte(uuid[i], ptr);
            *ptr++ = '-';
            for (; i < 8; i++)
                ptr = hexbyte(uuid[i], ptr);
            *ptr++ = '-';
            for (; i < 10; i++)
                ptr = hexbyte(uuid[i], ptr);
            *ptr++ = '-';
            for (; i < 16; i++)
                ptr = hexbyte(uuid[i], ptr);
            *ptr++ = 0;
        }
        else {
            wcscpy_s(g_uuid_str, L"00000000-0000-0000-0000-000000000000");
        }
        return WcharToString(g_uuid_str);
    }

    /**
     * @brief 从模块文件 + PDB 中获取符号的模块内偏移.
     * 
     * @param modulePath 文件路径
     * @param pdbSearchPath PDB路径
     * @param symbolName 符号名
     * @param baseAddress 基址
     * @return 
     */
    long long GetSymbolOffset(
        const std::string& modulePath,
        const std::string& pdbSearchPath,
        const std::string& symbolName,
        DWORD64 baseAddress = 0x10000000)
    {
        HANDLE hProcess = GetCurrentProcess();

        if (!SymInitialize(hProcess, NULL, FALSE)) {
            return -1;
        }

        // 加载模块
        DWORD64 moduleBase = SymLoadModuleEx(hProcess, NULL,
            modulePath.c_str(), NULL, baseAddress, 0, NULL, 0);

        if (!moduleBase) {
            SymCleanup(hProcess);
            return -1;
        }

        // 设置符号搜索路径
        if (!SymSetSearchPath(hProcess, pdbSearchPath.c_str())) {
            SymUnloadModule64(hProcess, moduleBase);
            SymCleanup(hProcess);
            return -1;
        }

        // 查找符号
        BYTE buffer[sizeof(SYMBOL_INFO) + 512];
        PSYMBOL_INFO symbol = reinterpret_cast<PSYMBOL_INFO>(buffer);
        ZeroMemory(symbol, sizeof(buffer));
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = 512;

        if (!SymFromName(hProcess, symbolName.c_str(), symbol)) {
            SymUnloadModule64(hProcess, moduleBase);
            SymCleanup(hProcess);
            return -1;
        }

        DWORD64 address = symbol->Address;
        long long offset = static_cast<long long>(address - moduleBase);

        // 卸载模块 & 清理
        SymUnloadModule64(hProcess, moduleBase);
        SymCleanup(hProcess);

        return offset;
    }
}