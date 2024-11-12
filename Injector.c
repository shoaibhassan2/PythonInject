#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <stdbool.h>

#define RED     "\033[1;31m"  
#define YELLOW  "\033[1;33m"  
#define GREEN   "\033[2;32m"  
#define WHITE   "\x1b[1;37m"  
#define ORANGE  "\x1b[38;5;208m"  
#define RESET   "\033[0m"
DWORD GetProcessID() {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("%sFailed to take process snapshot.\n%s",RED,RESET);
        return 0;
    }
    const char* python_exes[] = {
        "python313.exe",
        "python312.exe",
        "python311.exe",
        "python310.exe",
        "python39.exe",
        "python38.exe",
        "python37.exe",
        "python.exe"
    };
    if (Process32First(hSnapshot, &pe32)) {
        do {
            for (size_t i = 0; i < sizeof(python_exes) / sizeof(python_exes[0]); ++i) {
                if (strcmp(pe32.szExeFile, python_exes[i]) == 0) {
                    DWORD pid = pe32.th32ProcessID;
                    CloseHandle(hSnapshot);
                    return pid;
                }
            }        
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return 0;
}

int InjectDLL(DWORD processID, const char* dllName) {
    char dllPath[MAX_PATH];
    if (!GetModuleFileName(NULL, dllPath, MAX_PATH)) {
        printf("%sFailed to get executable path. Error: %lu\n%s",RED,GetLastError(),RESET);
        return -1;
    }

    char* lastSlash = strrchr(dllPath, '\\');
    if (lastSlash != NULL) {
        strcpy(lastSlash + 1, dllName);
    } else {
        printf("%sFailed to determine the DLL path.\n%s",RED,RESET);
        return -1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, processID);
    if (hProcess == NULL) {
        printf("%sFailed to open process. Error: %lu\n%s",RED,GetLastError(),RESET);
        return -1;
    }

    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pDllPath == NULL) {
        printf("%sFailed to allocate memory in target process. Error: %lu\n%s",RED,GetLastError(),RESET);
        CloseHandle(hProcess);
        return -1;
    }

    if (!WriteProcessMemory(hProcess, pDllPath, dllPath, strlen(dllPath) + 1, NULL)) {
        printf("%sFailed to write DLL path to target process. Error: %lu\n%s",RED,GetLastError(),RESET);
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    FARPROC loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr) {
        printf("%sFailed to get address of LoadLibraryA. Error: %lu\n%s",RED,GetLastError(),RESET);
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
        (LPTHREAD_START_ROUTINE)loadLibraryAddr, pDllPath, 0, NULL);
    if (hThread == NULL) {
        printf("%sFailed to create remote thread. Error: %lu\n%s",RED,GetLastError(),RESET);
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    printf("DLL injected successfully.\n");
    return 0;
}

int main() {
    system("cls");
    printf("%sCreated by shoaib hassan...%s\n",GREEN,RESET);
    DWORD processID = 0;

    while(true){
        printf("%sWaiting for python process to start...%s\n",ORANGE,RESET);
        while ((processID = GetProcessID()) == 0) {
            Sleep(1000); 
        }
        const char* dllName = "PyInjector.dll";
        if (InjectDLL(processID, dllName) == 0) {
            printf("%sInjection successful!\n%s",GREEN,RESET);
        } else {
            printf("%sInjection failed.\n%s",RED,RESET);
        }
        printf("%sPress any key to inject again\n\n%s",ORANGE,RESET);
        getch();
    }
    return 0;
}
