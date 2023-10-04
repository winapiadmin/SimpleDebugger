#include "DebugLoop.h"

void EnterDebugLoop(const LPDEBUG_EVENT DebugEv,const __int64 timeBegin)
{
    DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation 

    for (;;)
    {
        // Wait for a debugging event to occur. The second parameter indicates
        // that the function does not return until a debugging event occurs. 

        WaitForDebugEvent(DebugEv, INFINITE);

        // Process the debugging event code. 

        switch (DebugEv->dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT:
            // Process the exception code. When handling 
            // exceptions, remember to set the continuation 
            // status parameter (dwContinueStatus). This value 
            // is used by the ContinueDebugEvent function. 

            switch (DebugEv->u.Exception.ExceptionRecord.ExceptionCode)
            {
            case EXCEPTION_ACCESS_VIOLATION:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                if (DebugEv->u.Exception.dwFirstChance) dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                if (!DebugEv->u.Exception.dwFirstChance) {
                    std::cout << "Exception: Access Violation" << std::endl;
                }
                break;

            case EXCEPTION_BREAKPOINT:
                // First chance: Display the current 
                // instruction and register values. 
                break;

            case EXCEPTION_DATATYPE_MISALIGNMENT:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                if (DebugEv->u.Exception.dwFirstChance) dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                if (!DebugEv->u.Exception.dwFirstChance)
                    std::cout << "Data type misalignment" << std::endl;
                break;

            case EXCEPTION_SINGLE_STEP:
                // First chance: Update the display of the 
                // current instruction and register values. 
                break;

            case DBG_CONTROL_C:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                if (DebugEv->u.Exception.dwFirstChance) dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                if (!DebugEv->u.Exception.dwFirstChance)
                    std::cout << "Control-C occoured" << std::endl;
                    
                break;
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                if (DebugEv->u.Exception.dwFirstChance) dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                if (!DebugEv->u.Exception.dwFirstChance)
                    std::cout << "Array Exception: Out of Bounds" << std::endl;
                break;
            case EXCEPTION_FLT_DIVIDE_BY_ZERO:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                if (DebugEv->u.Exception.dwFirstChance) dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                if (!DebugEv->u.Exception.dwFirstChance)
                    std::cout << "Floating Point Exception: Divide by Zero, a/0" << std::endl;
                break;
            case EXCEPTION_FLT_INEXACT_RESULT:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                if (DebugEv->u.Exception.dwFirstChance) dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                if (!DebugEv->u.Exception.dwFirstChance)
                    std::cout << "Floating Point Exception: Inexact result, for example, Pi calculation" << std::endl;
                break;
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                if (DebugEv->u.Exception.dwFirstChance) dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                if (!DebugEv->u.Exception.dwFirstChance)
                    std::cout << "Integer Exception: Divide by Zero, a/0" << std::endl;
                break;
            default:
                // Handle other exceptions. 
                std::cout << "Exception code: " << DebugEv->u.Exception.ExceptionRecord.ExceptionCode << std::endl;
                break;
            }

            break;

        case CREATE_THREAD_DEBUG_EVENT:
            // As needed, examine or change the thread's registers 
            // with the GetThreadContext and SetThreadContext functions; 
            // and suspend and resume thread execution with the 
            // SuspendThread and ResumeThread functions. 

            dwContinueStatus = OnCreateThreadDebugEvent(DebugEv);
            break;

        case CREATE_PROCESS_DEBUG_EVENT:
            // As needed, examine or change the registers of the
            // process's initial thread with the GetThreadContext and
            // SetThreadContext functions; read from and write to the
            // process's virtual memory with the ReadProcessMemory and
            // WriteProcessMemory functions; and suspend and resume
            // thread execution with the SuspendThread and ResumeThread
            // functions. Be sure to close the handle to the process image
            // file with CloseHandle.

            dwContinueStatus = OnCreateProcessDebugEvent(DebugEv);
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            // Display the thread's exit code. 

            dwContinueStatus = OnExitThreadDebugEvent(DebugEv);
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            // Display the process's exit code. 

            dwContinueStatus = OnExitProcessDebugEvent(DebugEv);
            return;
            break;

        case LOAD_DLL_DEBUG_EVENT:
            // Read the debugging information included in the newly 
            // loaded DLL. Be sure to close the handle to the loaded DLL 
            // with CloseHandle.

            dwContinueStatus = OnLoadDllDebugEvent(DebugEv);
            break;

        case UNLOAD_DLL_DEBUG_EVENT:
            // Display a message that the DLL has been unloaded. 

            dwContinueStatus = OnUnloadDllDebugEvent(DebugEv);
            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            // Display the output debugging string. 

            dwContinueStatus = OnOutputDebugStringEvent(DebugEv);
            break;

        case RIP_EVENT:
            dwContinueStatus = OnRipEvent(DebugEv);
            break;
        }

        // Resume executing the thread that reported the debugging event. 
        ////////std::cout << "Timestamp " << (GetTickCount64() - timeBegin) << std::endl;
        ContinueDebugEvent(DebugEv->dwProcessId,
            DebugEv->dwThreadId,
            dwContinueStatus);
    }
}

DWORD OnOutputDebugStringEvent(const LPDEBUG_EVENT event) {
    LPSTR  address = event->u.DebugString.lpDebugStringData;
    LPVOID string;
    if (event->u.DebugString.fUnicode)
        string = new wchar_t[event->u.DebugString.nDebugStringLength];
    else
        string = new char[event->u.DebugString.nDebugStringLength];
    size_t read;
    ZeroMemory(&read, sizeof(read));
    HANDLE hPID = OpenProcess(PROCESS_ALL_ACCESS, FALSE, event->dwProcessId);
    ReadProcessMemory(hPID, address, string, event->u.DebugString.nDebugStringLength, &read);
    if (event->u.DebugString.fUnicode)
        std::wcout << (wchar_t*)string << std::endl;
    else
        std::cout << (char*)string << std::endl;
    CloseHandle(hPID);
    return DBG_CONTINUE;
}

DWORD OnLoadDllDebugEvent(const LPDEBUG_EVENT event) {
    if (event->u.LoadDll.lpImageName == NULL)
        std::cout << "Loaded DLL name ''" << std::endl;
    else {
        char path[MAX_PATH];
        HMODULE hModule=NULL;
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPSTR)event->u.LoadDll.lpBaseOfDll, &hModule);
        GetModuleFileName(hModule, path, MAX_PATH);
        std::cout << "Loaded DLL name '" << path << "'" << std::endl;
    }
    return DBG_CONTINUE;
}
DWORD OnUnloadDllDebugEvent(const LPDEBUG_EVENT event) {
    char path[MAX_PATH];
    HMODULE hModule = NULL;
    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPSTR)event->u.UnloadDll.lpBaseOfDll, &hModule);
    GetModuleFileName(hModule, path, MAX_PATH);
    std::cout << "Unloaded DLL name '" << path << "'" << std::endl;
    return DBG_CONTINUE;
}

DWORD OnCreateThreadDebugEvent(const LPDEBUG_EVENT event) {
    std::cout << "Thread Address `" << std::hex << event->u.CreateThread.lpStartAddress << "` created" << std::endl;
    return DBG_CONTINUE;
}
DWORD OnCreateProcessDebugEvent(const LPDEBUG_EVENT event) {
    std::cout << "Process created." << std::endl;
    CloseHandle(event->u.CreateProcessInfo.hFile);
    return DBG_CONTINUE;
}
DWORD OnExitThreadDebugEvent(const LPDEBUG_EVENT event) {
    std::cout << "Thread ID `" << std::hex << event->dwThreadId << "` is exited with return value " << std::hex << event->u.ExitThread.dwExitCode << std::endl;
    return DBG_CONTINUE;
}
DWORD OnExitProcessDebugEvent(const LPDEBUG_EVENT event) {
    std::cout << "Process exited with return value " << std::hex << event->u.ExitProcess.dwExitCode << std::endl;
    return DBG_TERMINATE_PROCESS;
}
DWORD OnRipEvent(const LPDEBUG_EVENT event) {
    switch (event->u.RipInfo.dwType)
    {
    case SLE_ERROR:
        std::cout << "Error" << std::endl;
        break;
    case SLE_WARNING:
        std::cout << "Warning" << std::endl;
        break;
    case SLE_MINORERROR:
        std::cout << "Minor error" << std::endl;
        break;
    default:
        break;
    }
    return DBG_CONTINUE;
}