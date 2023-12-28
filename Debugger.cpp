
#include <iostream>
#include <windows.h>
#include <psapi.h>
#include "DebugLoop.h"
#pragma comment(lib, "Psapi.lib")
int main(int argc, char *argv[])
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DEBUG_EVENT dbgEvent;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&dbgEvent, sizeof(dbgEvent));
    if (argc < 2)
    {
        printf("Usage: %s [module] [cmdline]\n", argv[0]);
        return 1;
    }
    if (argc == 3) {
        // Start the child process. 
        if (!CreateProcessA(argv[1],                     // No module name (use command line)
            argv[2],                                     // Command line
            NULL,                                        // Process handle not inheritable
            NULL,                                        // Thread handle not inheritable
            FALSE,                                       // Set handle inheritance to FALSE
            DEBUG_PROCESS | CREATE_NEW_CONSOLE,          // No creation flags
            NULL,                                        // Use parent's environment block
            NULL,                                        // Use parent's starting directory 
            &si,                                         // Pointer to STARTUPINFO structure
            &pi)                                         // Pointer to PROCESS_INFORMATION structure
            )
        {
            printf("CreateProcess failed (%d).\n", GetLastError());
            return 1;
        }
    }
    else {
        // Start the child process. 
        if (!CreateProcessA(NULL,                        // No module name (use command line)
            argv[1],                                     // Command line
            NULL,                                        // Process handle not inheritable
            NULL,                                        // Thread handle not inheritable
            FALSE,                                       // Set handle inheritance to FALSE
            DEBUG_PROCESS | CREATE_NEW_CONSOLE,          // No creation flags
            NULL,                                        // Use parent's environment block
            NULL,                                        // Use parent's starting directory 
            &si,                                         // Pointer to STARTUPINFO structure
            &pi)                                         // Pointer to PROCESS_INFORMATION structure
            )
        {
            printf("CreateProcess failed (%d).\n", GetLastError());
            return 1;
        }
    }
    DebugActiveProcess(pi.dwProcessId);
    // Wait until child process exits.
    EnterDebugLoop(&dbgEvent);
    DebugActiveProcessStop(pi.dwProcessId);
    TerminateProcess(pi.hProcess, 0);
    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
