#pragma once
/*****************************************************************//**
 * \file   SbieUtil.h
 * \brief  Sbie��غ���, ��ȡHWID, ��ȡpdb�б���ƫ�Ƶ�
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

    // �����ֽ�תΪ HEX �ַ��������ַ���
    wchar_t* hexbyte(UCHAR b, wchar_t* ptr)
    {
        static const wchar_t* digits = L"0123456789ABCDEF";
        *ptr++ = digits[b >> 4];
        *ptr++ = digits[b & 0x0F];
        return ptr;
    }

    // ��ȡ�̼�UUID, �ɹ����� TRUE
    BOOL GetFwUuid(UCHAR* uuid)
    {
        BOOL result = FALSE;

        // ��һ�ε��û�ȡ���軺���С
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
                UCHAR* uuidField = data + 0x08; // UUID ƫ��

                BOOL all_zero = TRUE, all_one = TRUE;
                for (int i = 0; i < 16 && (all_zero || all_one); i++)
                {
                    if (uuidField[i] != 0x00) all_zero = FALSE;
                    if (uuidField[i] != 0xFF) all_one = FALSE;
                }

                if (!all_zero && !all_one)
                {
                    // SMBIOS 2.6+ UUID ǰ3���ֶ���С��
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

            // ���� formatted area
            UCHAR* next = data + h->length;
            // ���� unformatted strings ������ 0x0000 ������
            while (next < smb->SMBIOSTableData + smb->Length &&
                (next[0] != 0 || next[1] != 0))
                next++;
            next += 2;
            data = next;
        }

        free(buffer);
        return result;
    }

    // ת�� wchar_t* �� std::string (UTF-8 ����)
    std::string WcharToString(const wchar_t* wstr)
    {
        if (!wstr) return std::string();

        int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
        if (len <= 0) return std::string();

        std::string str(len - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &str[0], len, NULL, NULL);
        return str;
    }

    // ��ʼ������ʽ��Ϊ UUID �ַ���
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
     * @brief ��ģ���ļ� + PDB �л�ȡ���ŵ�ģ����ƫ��.
     * 
     * @param modulePath �ļ�·��
     * @param pdbSearchPath PDB·��
     * @param symbolName ������
     * @param baseAddress ��ַ
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

        // ����ģ��
        DWORD64 moduleBase = SymLoadModuleEx(hProcess, NULL,
            modulePath.c_str(), NULL, baseAddress, 0, NULL, 0);

        if (!moduleBase) {
            SymCleanup(hProcess);
            return -1;
        }

        // ���÷�������·��
        if (!SymSetSearchPath(hProcess, pdbSearchPath.c_str())) {
            SymUnloadModule64(hProcess, moduleBase);
            SymCleanup(hProcess);
            return -1;
        }

        // ���ҷ���
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

        // ж��ģ�� & ����
        SymUnloadModule64(hProcess, moduleBase);
        SymCleanup(hProcess);

        return offset;
    }
}