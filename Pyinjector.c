#include <Windows.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { PyGILState_LOCKED, PyGILState_UNLOCKED } PyGILState_STATE;

typedef struct {
    int cf_flags;
    int cf_feature_version;
} PyCompilerFlags;

#define PyRun_SimpleString(s) PyRun_SimpleStringFlags(s, NULL)

typedef void (__stdcall * _Py_SetProgramName)(const wchar_t*);
typedef void (__stdcall * _PyEval_InitThreads)(void);
typedef PyGILState_STATE (__stdcall * _PyGILState_Ensure)(void);
typedef void (__stdcall * _PyGILState_Release)(PyGILState_STATE);
typedef int (__stdcall * _PyRun_SimpleStringFlags)(const char*, PyCompilerFlags*);

_Py_SetProgramName Py_SetProgramName = NULL;
_PyEval_InitThreads PyEval_InitThreads = NULL;
_PyGILState_Ensure PyGILState_Ensure = NULL;
_PyGILState_Release PyGILState_Release = NULL;
_PyRun_SimpleStringFlags PyRun_SimpleStringFlags = NULL;

int InitCPython(void) {
    HMODULE hPython = NULL;
    const char* python_mods[] = {
        "Python313.dll",
        "Python312.dll",
        "Python311.dll",
        "Python310.dll",
        "Python39.dll",
        "Python38.dll",
        "Python37.dll"
    };
    for (size_t i = 0; !hPython && i < sizeof(python_mods) / sizeof(python_mods[0]); ++i) {
        hPython = GetModuleHandleA(python_mods[i]);
    }
    if (!hPython) {
        return 0; 
    }
    return
        NULL != (Py_SetProgramName = (_Py_SetProgramName)GetProcAddress(hPython, "Py_SetProgramName")) &&
        NULL != (PyEval_InitThreads = (_PyEval_InitThreads)GetProcAddress(hPython, "PyEval_InitThreads")) &&
        NULL != (PyGILState_Ensure = (_PyGILState_Ensure)GetProcAddress(hPython, "PyGILState_Ensure")) &&
        NULL != (PyGILState_Release = (_PyGILState_Release)GetProcAddress(hPython, "PyGILState_Release")) &&
        NULL != (PyRun_SimpleStringFlags = (_PyRun_SimpleStringFlags)GetProcAddress(hPython, "PyRun_SimpleStringFlags"));
}

#ifdef MODE_EXEC_CODE_PY
static const char code[] =
    "import os\n"
    "with open(\"pycode.py\", \"r\") as file:\n"
    "    data = file.read()\n"
    "exec(data)\n";
#elif defined(MODE_SPAWN_PYSHELL)
static const char code[] = 
    "import traceback\n"
    "import sys\n"
    "while True:\n"
    "    s = input('pyshell >>> ')\n"
    "    cs = s\n"
    "    while cs.endswith(':') or cs.startswith(' '):\n"
    "        cs = input('pyshell ... ')\n"
    "        s += '\\n' + cs\n"
    "    if not s.strip(): continue\n"
    "    try:\n"
    "        code = compile(s, '<string>', 'single')\n"
    "        eval(code)\n"
    "    except:\n"
    "        traceback.print_exception(*sys.exc_info())\n";
#else
#error "Please define MODE_XXX macro or write python code to inject in the 'code' variable"
#endif

void run_python_code(void) {
    if (!InitCPython()) {
        MessageBoxW(0, L"Unable to initialize Python (Python3x.dll was not found)", L"Error", 0);
        return;
    }
    Py_SetProgramName(L"PyInjector");
    PyEval_InitThreads();
    
    PyGILState_STATE state = PyGILState_Ensure();
    PyRun_SimpleString(code);
    PyGILState_Release(state);
}

#ifdef MODE_SPAWN_PYSHELL
int show_hidden_console_window(void) {
    AllocConsole();
    HWND hWnd = GetConsoleWindow();

    if (!hWnd) {
        FreeConsole();
        AllocConsole();
        hWnd = GetConsoleWindow();
    }

    if (!hWnd) {
        char command[] = "cmd.exe";
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        si.wShowWindow = SW_SHOWNORMAL;
        si.dwFlags = STARTF_USESHOWWINDOW;

        BOOL success = CreateProcessA(
            NULL, command, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi
        );
        if (success) {
            WaitForSingleObject(pi.hProcess, 1000);
            AttachConsole(pi.dwProcessId);
            hWnd = GetConsoleWindow();
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    if (hWnd) {
        SetConsoleTitleA("PyShell");
        ShowWindow(hWnd, SW_SHOWNORMAL);
        return 1;
    } else {
        MessageBoxW(0, L"Unable to attach console", L"Error", 0);
        return 0;
    }
}
#else
#define show_hidden_console_window(...) 1
#endif

DWORD WINAPI MainThread(HMODULE hModule) {
    if (!show_hidden_console_window()) {
#ifdef MODE_SPAWN_PYSHELL
        return 1;
#endif
    }
    run_python_code();
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            CloseHandle(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, NULL));
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

#ifdef __cplusplus
}
#endif
