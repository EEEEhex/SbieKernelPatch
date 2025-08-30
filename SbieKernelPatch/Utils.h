#pragma once
#include <windows.h>
#include <string>

namespace Utils
{ 
    /**
     * @brief 获取当前程序运行目录(不含文件名）.
     * 
     * @param withBackslash 末尾是否带反斜杠\
     * @return string 路径
     */
    std::string GetCurrentProcessDir(bool withBackslash = false)
    {
        char path[MAX_PATH] = { 0 };
        // 获取当前进程模块完整路径（含exe文件名）
        DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
        if (len == 0)
            return "";

        std::string fullPath(path);
        size_t pos = fullPath.find_last_of("\\/");
        if (pos == std::string::npos)
            return "";

        std::string dir = fullPath.substr(0, pos);
        if (withBackslash)
            dir.push_back('\\'); // 添加反斜杠
        return dir;
    }

    /**
     * @brief 获取当前进程完整路径.
     * 
     * @return 包含程序名的路径
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
     * @brief 设置当前程序工作目录为程序所在目录.
     * 
     * @return 是否成功
     */
    bool SetWorkDirToExeDir()
    {
        std::string dir = GetCurrentProcessDir(false); // 不带反斜杠
        if (dir.empty())
            return false;
        return SetCurrentDirectoryA(dir.c_str()) == TRUE;
    }

    /**
     * @brief 设置开机自启.
     * 
     * @param name 在注册表中的键名
     * @param path 要自启的程序路径, 如果为空则使用当前程序
     * @return 是否成功
     */
    bool SetAutoRun(const std::string& name, const std::string& path = "")
    {
        HKEY hKey;
        // 打开注册表指定路径
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

        // 加双引号防止路径中有空格
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
     * @brief 取消开机自启.
     * 
     * @param name 键名
     * @return 是否成功
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
     * @brief 判断文件是否存在(并且不是目录).
     * 
     * @param path 文件路径
     * @return 是否存在
     */
    bool FileExists(const std::string& path)
    {
        DWORD attr = GetFileAttributesA(path.c_str());
        return (attr != INVALID_FILE_ATTRIBUTES &&
            !(attr & FILE_ATTRIBUTE_DIRECTORY));
    }

    /**
     * @brief 获取当前日期, 格式为DD.MM.YYYY, 例如"17.08.2025".
     * 
     * @return DD.MM.YYYY字符串
     */
    std::string GetCurrentDateString()
    {
        SYSTEMTIME st;
        GetLocalTime(&st);

        char buf[11]; // "DD.MM.YYYY" + 终止符
        // %02d 表示至少两位数字，不足补 0
        sprintf_s(buf, "%02d.%02d.%04d", st.wDay, st.wMonth, st.wYear);

        return std::string(buf);
    }

    /**
     * @brief 读取文件内容到string中
     * 
     * @param path 文件路径
     * @param outContent std::string
     * @return 是否成功
     */
    bool ReadFileToString(const std::string & path, std::string & outContent)
    {
        outContent.clear();

        std::ifstream file(path, std::ios::binary);
        if (!file.is_open())
        {
            return false; // 打不开文件
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
            return false; // 读取失败
        }

        return true;
    }

    /**
     * @brief 读取二进制文件到内存中.
     * 
     * @param path 文件路径
     * @param outData 二进制数据
     * @return 是否成功
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
     * @brief 将内存中的二进制数据写入文件
     *
     * @param path 文件路径
     * @param data 二进制数据
     * @return 是否成功
     */
    bool WriteMemToFile(const std::string& path, const std::vector<uint8_t>& data)
    {
        // 如果数据为空，可以选择直接返回 false 或创建空文件
        HANDLE hFile = CreateFileA(
            path.c_str(),
            GENERIC_WRITE,
            0,              // 独占写入
            nullptr,
            CREATE_ALWAYS,  // 总是新建(如果存在则覆盖)
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
     * @brief 从text中删除第一个以prefix开头的行.
     * 
     * @param text 文本
     * @param prefix 开头
     */
    void RemoveLineWithPrefix(std::string& text, const std::string& prefix)
    {
        size_t pos = 0;
        while (pos < text.size())
        {
            // 找到一行的开头
            size_t lineStart = pos;
            // 找到当前行结尾(\n 或末尾)
            size_t lineEnd = text.find('\n', lineStart);
            if (lineEnd == std::string::npos)
            {
                lineEnd = text.size();
            }

            // 判断是否以prefix开头
            if (text.compare(lineStart, prefix.size(), prefix) == 0)
            {
                // 删除这一行，如果不是最后一行，包含换行符
                if (lineEnd < text.size())
                    text.erase(lineStart, lineEnd - lineStart + 1);
                else
                    text.erase(lineStart, lineEnd - lineStart);
                break; // 只删第一个匹配的行
            }

            // 跳到下一行开头
            if (lineEnd == text.size())
                break;
            pos = lineEnd + 1;
        }
    }

    /**
     * @brief 隐藏当前控制台窗口.
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