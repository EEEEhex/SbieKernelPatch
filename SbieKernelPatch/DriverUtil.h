#pragma once
/*****************************************************************//**
 * \file   DriverUtil.h
 * \brief  驱动控制相关函数
 *********************************************************************/
#include <windows.h>
#include <string>
#include <iostream>

namespace DriverUtil
{
    bool InstallDriver(const std::string& driverName, const std::string& driverPath)
    {
        SC_HANDLE hSCManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!hSCManager)
        {
            std::cerr << "[!] OpenSCManager failed: " << GetLastError() << std::endl;
            return false;
        }

        SC_HANDLE hService = CreateServiceA(
            hSCManager,
            driverName.c_str(),
            driverName.c_str(),
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            driverPath.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr);

        if (!hService)
        {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_EXISTS)
            {
                std::cout << "[+] Service \'" << driverName << "\' already exists." << std::endl;
            }
            else
            {
                std::cerr << "[!] CreateService \'"<< driverName << "\' failed: " << err << std::endl;
                CloseServiceHandle(hSCManager);
                return false;
            }
        }
        else
        {
            std::cout << "[+] Service \'" << driverName << "\' created successfully." << std::endl;
            CloseServiceHandle(hService);
        }

        CloseServiceHandle(hSCManager);
        return true;
    }

    bool StartDriver(const std::string& driverName)
    {
        SC_HANDLE hSCManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCManager)
        {
            std::cerr << "[!] OpenSCManager failed: " << GetLastError() << std::endl;
            return false;
        }

        SC_HANDLE hService = OpenServiceA(hSCManager, driverName.c_str(), SERVICE_START);
        if (!hService)
        {
            std::cerr << "[!] OpenService \'" << driverName << "\' failed: " << GetLastError() << std::endl;
            CloseServiceHandle(hSCManager);
            return false;
        }

        if (!StartServiceA(hService, 0, nullptr))
        {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_ALREADY_RUNNING)
            {
                std::cout << "[+] Service \'" << driverName << "\' is already running." << std::endl;
            }
            else
            {
                std::cerr << "[!] StartService \'" << driverName << "\' failed: " << err << std::endl;
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return false;
            }
        }
        else
        {
            std::cout << "[+] Service \'" << driverName  << "\' started successfully." << std::endl;
        }

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return true;
    }

    bool StopDriver(const std::string& driverName)
    {
        SC_HANDLE hSCManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCManager)
        {
            std::cerr << "[!] OpenSCManager failed: " << GetLastError() << std::endl;
            return false;
        }

        SC_HANDLE hService = OpenServiceA(hSCManager, driverName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!hService)
        {
            std::cerr << "[!] OpenService \'" << driverName << "\' failed: " << GetLastError() << std::endl;
            CloseServiceHandle(hSCManager);
            return false;
        }

        SERVICE_STATUS status = {};
        if (!ControlService(hService, SERVICE_CONTROL_STOP, &status))
        {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_NOT_ACTIVE)
            {
                std::cout << "[!] Service \'" << driverName << "\' is not running." << std::endl;
            }
            else
            {
                std::cerr << "[!] ControlService (STOP) failed: " << err << std::endl;
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return false;
            }
        }
        else
        {
            std::cout << "[-] Service \'" << driverName << "\' stopped successfully." << std::endl;
        }

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return true;
    }

    bool DeleteDriver(const std::string& driverName)
    {
        SC_HANDLE hSCManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCManager)
        {
            std::cerr << "[!] OpenSCManager failed: " << GetLastError() << std::endl;
            return false;
        }

        SC_HANDLE hService = OpenServiceA(hSCManager, driverName.c_str(), DELETE);
        if (!hService)
        {
            std::cerr << "[!] OpenService \'" << driverName << "\' failed: " << GetLastError() << std::endl;
            CloseServiceHandle(hSCManager);
            return false;
        }

        if (!DeleteService(hService))
        {
            std::cerr << "[!] DeleteService \'" << driverName << "\' failed: " << GetLastError() << std::endl;
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return false;
        }

        std::cout << "[-] Service \'" << driverName << "\' deleted successfully." << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return true;
    }
}
