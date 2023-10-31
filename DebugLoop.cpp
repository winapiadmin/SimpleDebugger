#include "DebugLoop.h"

void EnterDebugLoop(const LPDEBUG_EVENT DebugEv,const __int64 timeBegin)
{
    DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation 
    CONTEXT ctx = { 0 };
    HANDLE hTID;
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
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                std::cout << "Exception: Access Violation" << std::endl;
                break;

            case EXCEPTION_BREAKPOINT:
                // First chance: Display the current 
                // instruction and register values. 
                break;

            case EXCEPTION_DATATYPE_MISALIGNMENT:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                std::cout << "Data type misalignment" << std::endl;
                break;

            case EXCEPTION_SINGLE_STEP:
                // First chance: Update the display of the 
                // current instruction and register values.
                break;

            case DBG_CONTROL_C:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                std::cout << "Control-C occoured" << std::endl;
                break;
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                std::cout << "Array Exception: Out of Bounds" << std::endl;
                break;
            case EXCEPTION_FLT_DIVIDE_BY_ZERO:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                std::cout << "Floating Point Exception: Divide by Zero, a/0" << std::endl;
                break;
            case EXCEPTION_FLT_INEXACT_RESULT:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                std::cout << "Floating Point Exception: Inexact result, for example, Pi calculation" << std::endl;
                break;
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                std::cout << "Integer Exception: Divide by Zero, a/0" << std::endl;
                break;
            default:
                // Handle other exceptions. 
                std::cout << "Exception code: " << std::hex << DebugEv->u.Exception.ExceptionRecord.ExceptionCode << std::endl;
                break;
            }


            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_INTEGER;
            ctx.Dr7 = 0x00000001;
            hTID = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEv->dwThreadId);
            if (!hTID || hTID == INVALID_HANDLE_VALUE) break;
            SetThreadContext(hTID, &ctx);
            GetThreadContext(hTID, &ctx);
            std::cout << "rax\t\t" << ctx.Rax << std::endl; // eax get
            std::cout << "rbx\t\t" << ctx.Rbx << std::endl; // ebx get
            std::cout << "rcx\t\t" << ctx.Rcx << std::endl; // ecx get
            std::cout << "rdx\t\t" << ctx.Rdx << std::endl; // ebx get
            std::cout << "rdi\t\t" << ctx.Rdi << std::endl; // edi get
            std::cout << "rsi\t\t" << ctx.Rsi << std::endl; // esi get
            std::cout << "rbp\t\t" << ctx.Rbp << std::endl; // ebp get
            std::cout << "rsp\t\t" << ctx.Rsp << std::endl; // esp get
            std::cout << "rip\t\t" << ctx.Rip << std::endl; // eip get
            std::cout << "gs\t\t" << ctx.SegGs << std::endl; // gs get
            std::cout << "fs\t\t" << ctx.SegFs << std::endl; // fs get
            std::cout << "es\t\t" << ctx.SegEs << std::endl; // es get
            std::cout << "ds\t\t" << ctx.SegDs << std::endl; // ds get
            std::cout << "ss\t\t" << ctx.SegSs << std::endl; // ss get
            CloseHandle(hTID);
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
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_INTEGER;
            ctx.Dr7 = 0x00000001;
            hTID = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEv->dwThreadId);
            if (!hTID || hTID == INVALID_HANDLE_VALUE) break;
            SetThreadContext(hTID, &ctx);
            GetThreadContext(hTID, &ctx);
            std::cout << "rax\t\t" << ctx.Rax << std::endl; // eax get
            std::cout << "rbx\t\t" << ctx.Rbx << std::endl; // ebx get
            std::cout << "rcx\t\t" << ctx.Rcx << std::endl; // ecx get
            std::cout << "rdx\t\t" << ctx.Rdx << std::endl; // ebx get
            std::cout << "rdi\t\t" << ctx.Rdi << std::endl; // edi get
            std::cout << "rsi\t\t" << ctx.Rsi << std::endl; // esi get
            std::cout << "rbp\t\t" << ctx.Rbp << std::endl; // ebp get
            std::cout << "rsp\t\t" << ctx.Rsp << std::endl; // esp get
            std::cout << "rip\t\t" << ctx.Rip << std::endl; // eip get
            std::cout << "gs\t\t" << ctx.SegGs << std::endl; // gs get
            std::cout << "fs\t\t" << ctx.SegFs << std::endl; // fs get
            std::cout << "es\t\t" << ctx.SegEs << std::endl; // es get
            std::cout << "ds\t\t" << ctx.SegDs << std::endl; // ds get
            std::cout << "ss\t\t" << ctx.SegSs << std::endl; // ss get
            CloseHandle(hTID);
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
    unsigned __int64 read;
    ZeroMemory(&read, sizeof(read));
    HANDLE hPID = OpenProcess(PROCESS_ALL_ACCESS, FALSE, event->dwProcessId);
    ReadProcessMemory(hPID, address, string, event->u.DebugString.nDebugStringLength, &read);
    if (event->u.DebugString.fUnicode)
        std::wcout << (wchar_t*)string;// << std::endl;
    else
        std::cout << (char*)string;// << std::endl;

    CloseHandle(hPID);
    return DBG_CONTINUE;
}

DWORD OnLoadDllDebugEvent(const LPDEBUG_EVENT event) {
    //if (event->u.LoadDll.lpImageName == NULL)
    //    std::cout << "Loaded DLL name ''" << std::endl;
    //else {
    	char *path = new char[MAX_PATH];
        HMODULE hModule=NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPSTR)event->u.LoadDll.lpBaseOfDll, &hModule);
        GetModuleFileNameA(hModule, path, MAX_PATH);
        std::cout << "Loaded DLL name '" << path << "'" << std::endl;
    //}
    CloseHandle(event->u.LoadDll.hFile);
    return DBG_CONTINUE;
}
DWORD OnUnloadDllDebugEvent(const LPDEBUG_EVENT event) {
    char *path = new char[MAX_PATH];
    HMODULE hModule = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPSTR)event->u.UnloadDll.lpBaseOfDll, &hModule);
    GetModuleFileNameA(hModule, path, MAX_PATH);
    std::cout << "Unloaded DLL name '" << path << "'" << std::endl;
    return DBG_CONTINUE;
}

DWORD OnCreateThreadDebugEvent(const LPDEBUG_EVENT event) {
    std::cout << "Thread Address `0x" << std::hex << event->u.CreateThread.lpStartAddress << "` created" << std::endl;
    return DBG_CONTINUE;
}
DWORD OnCreateProcessDebugEvent(const LPDEBUG_EVENT event) {
    LPSTR filePath = new char[256];
    GetFinalPathNameByHandleA(event->u.CreateProcessInfo.hFile, filePath, 256, NULL);
    std::cout << "Process created. Path 1" << filePath << "`" << std::endl;
    CloseHandle(event->u.CreateProcessInfo.hFile);
    return DBG_CONTINUE;
}
DWORD OnExitThreadDebugEvent(const LPDEBUG_EVENT event) {
    std::cout << "Thread ID `0x" << std::hex << event->dwThreadId << "` is exited with return value " << std::hex << event->u.ExitThread.dwExitCode << std::endl;
    return DBG_CONTINUE;
}
DWORD OnExitProcessDebugEvent(const LPDEBUG_EVENT event) {
    std::cout << "Process exited with return value 0x" << std::hex << event->u.ExitProcess.dwExitCode << "(" << event->u.ExitProcess.dwExitCode << ")" << std::endl;
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