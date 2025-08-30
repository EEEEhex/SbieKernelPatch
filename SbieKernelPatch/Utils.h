#pragma once
#include <windows.h>
#include <string>

namespace Utils
{ 
    /**
     * @brief ��ȡ��ǰ��������Ŀ¼(�����ļ�����.
     * 
     * @param withBackslash ĩβ�Ƿ����б��\
     * @return string ·��
     */
    std::string GetCurrentProcessDir(bool withBackslash = false)
    {
        char path[MAX_PATH] = { 0 };
        // ��ȡ��ǰ����ģ������·������exe�ļ�����
        DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
        if (len == 0)
            return "";

        std::string fullPath(path);
        size_t pos = fullPath.find_last_of("\\/");
        if (pos == std::string::npos)
            return "";

        std::string dir = fullPath.substr(0, pos);
        if (withBackslash)
            dir.push_back('\\'); // ��ӷ�б��
        return dir;
    }

    /**
     * @brief ��ȡ��ǰ��������·��.
     * 
     * @return ������������·��
     */
    std::string GetCurrentProcessPath()
    {
        char path[MAX_PATH] = { 0 };
        DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
        if (len == 0)
            return "";
        return std::string(path);
    }

    /**
     * @brief ���õ�ǰ������Ŀ¼Ϊ��������Ŀ¼.
     * 
     * @return �Ƿ�ɹ�
     */
    bool SetWorkDirToExeDir()
    {
        std::string dir = GetCurrentProcessDir(false); // ������б��
        if (dir.empty())
            return false;
        return SetCurrentDirectoryA(dir.c_str()) == TRUE;
    }

    /**
     * @brief ���ÿ�������.
     * 
     * @param name ��ע����еļ���
     * @param path Ҫ�����ĳ���·��, ���Ϊ����ʹ�õ�ǰ����
     * @return �Ƿ�ɹ�
     */
    bool SetAutoRun(const std::string& name, const std::string& path = "")
    {
        HKEY hKey;
        // ��ע���ָ��·��
        LONG ret = RegOpenKeyExA(
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0,
            KEY_SET_VALUE,
            &hKey
        );
        if (ret != ERROR_SUCCESS)
            return false;

        std::string exePath = path.empty() ? GetCurrentProcessPath() : path;

        // ��˫���ŷ�ֹ·�����пո�
        std::string value = "\"" + exePath + "\" -s"; //silent

        ret = RegSetValueExA(
            hKey,
            name.c_str(),
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(value.c_str()),
            static_cast<DWORD>(value.size() + 1)
        );
        RegCloseKey(hKey);

        return ret == ERROR_SUCCESS;
    }

    /**
     * @brief ȡ����������.
     * 
     * @param name ����
     * @return �Ƿ�ɹ�
     */
    bool CancelAutoRun(const std::string& name)
    {
        HKEY hKey;
        LONG ret = RegOpenKeyExA(
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0,
            KEY_SET_VALUE,
            &hKey
        );
        if (ret != ERROR_SUCCESS)
            return false;

        ret = RegDeleteValueA(hKey, name.c_str());
        RegCloseKey(hKey);

        return ret == ERROR_SUCCESS || ret == ERROR_FILE_NOT_FOUND;
    }

    /**
     * @brief �ж��ļ��Ƿ����(���Ҳ���Ŀ¼).
     * 
     * @param path �ļ�·��
     * @return �Ƿ����
     */
    bool FileExists(const std::string& path)
    {
        DWORD attr = GetFileAttributesA(path.c_str());
        return (attr != INVALID_FILE_ATTRIBUTES &&
            !(attr & FILE_ATTRIBUTE_DIRECTORY));
    }

    /**
     * @brief ��ȡ��ǰ����, ��ʽΪDD.MM.YYYY, ����"17.08.2025".
     * 
     * @return DD.MM.YYYY�ַ���
     */
    std::string GetCurrentDateString()
    {
        SYSTEMTIME st;
        GetLocalTime(&st);

        char buf[11]; // "DD.MM.YYYY" + ��ֹ��
        // %02d ��ʾ������λ���֣����㲹 0
        sprintf_s(buf, "%02d.%02d.%04d", st.wDay, st.wMonth, st.wYear);

        return std::string(buf);
    }

    /**
     * @brief ��ȡ�ļ����ݵ�string��
     * 
     * @param path �ļ�·��
     * @param outContent std::string
     * @return �Ƿ�ɹ�
     */
    bool ReadFileToString(const std::string & path, std::string & outContent)
    {
        outContent.clear();

        std::ifstream file(path, std::ios::binary);
        if (!file.is_open())
        {
            return false; // �򲻿��ļ�
        }

        file.seekg(0, std::ios::end);
        std::streamsize size = file.tellg();
        if (size < 0)
        {
            return false;
        }
        outContent.resize(static_cast<size_t>(size));
        file.seekg(0, std::ios::beg);

        if (!file.read(&outContent[0], size))
        {
            outContent.clear();
            return false; // ��ȡʧ��
        }

        return true;
    }

    /**
     * @brief ��ȡ�������ļ����ڴ���.
     * 
     * @param path �ļ�·��
     * @param outData ����������
     * @return �Ƿ�ɹ�
     */
    bool ReadFileToMem(const std::string& path, std::vector<uint8_t>& outData)
    {
        outData.clear();

        HANDLE hFile = CreateFileA(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE)
            return false;

        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize == INVALID_FILE_SIZE || fileSize == 0)
        {
            CloseHandle(hFile);
            return false;
        }

        outData.resize(fileSize);
        DWORD bytesRead = 0;
        BOOL success = ReadFile(hFile, outData.data(), fileSize, &bytesRead, nullptr);
        CloseHandle(hFile);

        if (!success || bytesRead != fileSize)
        {
            outData.clear();
            return false;
        }

        return true;
    }

    /**
     * @brief ���ڴ��еĶ���������д���ļ�
     *
     * @param path �ļ�·��
     * @param data ����������
     * @return �Ƿ�ɹ�
     */
    bool WriteMemToFile(const std::string& path, const std::vector<uint8_t>& data)
    {
        // �������Ϊ�գ�����ѡ��ֱ�ӷ��� false �򴴽����ļ�
        HANDLE hFile = CreateFileA(
            path.c_str(),
            GENERIC_WRITE,
            0,              // ��ռд��
            nullptr,
            CREATE_ALWAYS,  // �����½�(��������򸲸�)
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE)
            return false;

        DWORD bytesWritten = 0;
        BOOL success = TRUE;

        if (!data.empty())
        {
            success = WriteFile(
                hFile,
                data.data(),
                static_cast<DWORD>(data.size()),
                &bytesWritten,
                nullptr
            );

            if (!success || bytesWritten != data.size())
            {
                CloseHandle(hFile);
                return false;
            }
        }

        CloseHandle(hFile);
        return true;
    }

    /**
     * @brief ��text��ɾ����һ����prefix��ͷ����.
     * 
     * @param text �ı�
     * @param prefix ��ͷ
     */
    void RemoveLineWithPrefix(std::string& text, const std::string& prefix)
    {
        size_t pos = 0;
        while (pos < text.size())
        {
            // �ҵ�һ�еĿ�ͷ
            size_t lineStart = pos;
            // �ҵ���ǰ�н�β(\n ��ĩβ)
            size_t lineEnd = text.find('\n', lineStart);
            if (lineEnd == std::string::npos)
            {
                lineEnd = text.size();
            }

            // �ж��Ƿ���prefix��ͷ
            if (text.compare(lineStart, prefix.size(), prefix) == 0)
            {
                // ɾ����һ�У�����������һ�У��������з�
                if (lineEnd < text.size())
                    text.erase(lineStart, lineEnd - lineStart + 1);
                else
                    text.erase(lineStart, lineEnd - lineStart);
                break; // ֻɾ��һ��ƥ�����
            }

            // ������һ�п�ͷ
            if (lineEnd == text.size())
                break;
            pos = lineEnd + 1;
        }
    }

    /**
     * @brief ���ص�ǰ����̨����.
     */
    void HideConsoleWindow()
    {
        HWND hWnd = GetConsoleWindow();
        if (hWnd != NULL)
        {
            ShowWindow(hWnd, SW_HIDE);
        }
    }
}