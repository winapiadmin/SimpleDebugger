#include "DebugLoop.h"

// Converts a character to its hexadecimal representation.
static char* charToHex(unsigned char c)
{
    char* s = (char*)malloc(3);

    if (c < 0x10) sprintf_s(s, 3, "0%x", c); else sprintf_s(s, 3, "%x", c);
    return s;
}

static void dump(unsigned char* buffer, size_t BYTES_PER_LINE,size_t SIZE, DWORD64 startAddress)
{
    size_t byteIndex = 0;
	size_t NUMBER_OF_LINES = SIZE / BYTES_PER_LINE;
    for (size_t i = 0; i < NUMBER_OF_LINES; i++) {
        char* text=(char*) malloc(SIZE * 6);
        sprintf_s(text, SIZE * 6, "\n%8x ", (DWORD)(BYTES_PER_LINE * i + startAddress));
        for (size_t j = 0; j < BYTES_PER_LINE; j++) {
            char* ch = charToHex((unsigned char)buffer[byteIndex++]);
            sprintf_s(text, SIZE * 6, "%s %s", text, ch);
            free(ch);
        }

        sprintf_s(text, SIZE * 6, "%s ", text);

        for (size_t j = 0; j < BYTES_PER_LINE; j++) {
            char c = buffer[byteIndex - BYTES_PER_LINE + j];
            sprintf_s(text, SIZE * 6, "%s%c", text, isprint((unsigned int) c) ? c : '.');
        }
        fwrite((void*)text, strlen(text), 1, stdout); //Used instead of printf() for performance

        free(text);
    }
    putchar('\n');
}

void EnterDebugLoop(const LPDEBUG_EVENT DebugEv)
{
    DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation 
    CONTEXT ctx = { 0 };
    HANDLE hTID;
    std::string a;
    LPSTR  address;
    LPVOID string;
    unsigned __int64 read;
    HANDLE hPID;
    for (;;)
    {
        dwContinueStatus = DBG_CONTINUE;
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
                std::cout << "Exception: Access Violation" << std::endl;
                dwContinueStatus = DebugEv->u.Exception.dwFirstChance == TRUE ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
                break;

            case EXCEPTION_BREAKPOINT:
                // First chance: Display the current 
                // instruction and register values. 
                std::cout << "Breakpoint" << std::endl;
                break;

            case EXCEPTION_DATATYPE_MISALIGNMENT:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                std::cout << "Data type misalignment" << std::endl;
                dwContinueStatus = DebugEv->u.Exception.dwFirstChance == TRUE ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
                break;

            case EXCEPTION_SINGLE_STEP:
                // First chance: Update the display of the 
                // current instruction and register values.
                std::cout << "Single Step" << std::endl;
                break;

            case DBG_CONTROL_C:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                std::cout << "Control-C occoured" << std::endl;
                dwContinueStatus = DebugEv->u.Exception.dwFirstChance == TRUE ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
                break;
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                std::cout << "Array Exception: Out of Bounds" << std::endl;
                dwContinueStatus = DebugEv->u.Exception.dwFirstChance == TRUE ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
                break;
            case EXCEPTION_FLT_DIVIDE_BY_ZERO:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                std::cout << "Floating Point Exception: Divide by Zero, a/0" << std::endl;
                dwContinueStatus = DebugEv->u.Exception.dwFirstChance == TRUE ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
                break;
            case EXCEPTION_FLT_INEXACT_RESULT:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                std::cout << "Floating Point Exception: Inexact result, for example, Pi calculation" << std::endl;
                dwContinueStatus = DebugEv->u.Exception.dwFirstChance == TRUE ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
                break;
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                std::cout << "Integer Exception: Divide by Zero, a/0" << std::endl;
                dwContinueStatus = DebugEv->u.Exception.dwFirstChance == TRUE ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
                break;
            case EXCEPTION_PRIV_INSTRUCTION:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                std::cout << "Execution Exception: Privileged instruction" << std::endl;
                dwContinueStatus = DebugEv->u.Exception.dwFirstChance == TRUE ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
                break;
            case EXCEPTION_ILLEGAL_INSTRUCTION:
                // First chance: Pass this on to the system. 
                // Last chance: Display an appropriate error. 
                std::cout << "Execution Exception: Illegal instruction" << std::endl;
                dwContinueStatus = DebugEv->u.Exception.dwFirstChance == TRUE ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
                break;
            default:
                // Handle other exceptions. 
                std::cout << "Exception code: 0x" << std::hex << DebugEv->u.Exception.ExceptionRecord.ExceptionCode << std::endl;
                break;
            }
            ctx.ContextFlags = CONTEXT_FULL;
            hTID = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEv->dwThreadId);
            if (!hTID || hTID == INVALID_HANDLE_VALUE) break;
            SuspendThread(hTID);
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

            std::cout << "As the exception did, do you want to resume?" << std::endl;
            std::cin >> a;
            if (a == "Yes") {
                ResumeThread(hTID);
                CloseHandle(hTID);
            }
            if (a == "No") {
                switch (DebugEv->u.Exception.ExceptionRecord.ExceptionCode)
                {
                case EXCEPTION_BREAKPOINT:
                    // First chance: Display the current 
                    // instruction and register values. 
                    dwContinueStatus = DBG_CONTINUE;
                    break;

                case EXCEPTION_SINGLE_STEP:
                    // First chance: Update the display of the 
                    // current instruction and register values.
                    dwContinueStatus = DBG_CONTINUE;
                    break;
                case STATUS_WX86_SINGLE_STEP:
                    // First chance: Update the display of the 
                    // current instruction and register values.
                    dwContinueStatus = DBG_CONTINUE;
                    break;
                default:
                    dwContinueStatus = DebugEv->u.Exception.dwFirstChance == TRUE ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
                    break;
                }
                CloseHandle(hTID);
            }
            std::cout << "First 1KB dump" << std::endl;
    	    address = (LPSTR)ctx.Rip;
    	    string = new unsigned char[1024*1];
    	    unsigned __int64 read;
    	    ZeroMemory(&read, sizeof(read));
    	    hPID = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEv->dwProcessId);
    	    ReadProcessMemory(hPID, address, string, 1024*1, &read);
	        dump ((unsigned char*)((DWORD64)string), 40, 1024*1, ctx.Rip);
	        delete[] ((unsigned char*)string);
    	    CloseHandle(hPID);
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
        std::wcout << L"> " << (wchar_t*)string << std::endl;
    else
        std::cout << "> " << (char*)string << std::endl;

    CloseHandle(hPID);
    return DBG_CONTINUE;
}

DWORD OnLoadDllDebugEvent(const LPDEBUG_EVENT event) {
    //if (event->u.LoadDll.lpImageName == NULL)
    //    std::cout << "Loaded DLL name ''" << std::endl;
    //else {
        LPSTR filePath = new char[256];
        GetFinalPathNameByHandleA(event->u.LoadDll.hFile, filePath, 256, NULL);
        std::cout << "Process created. Path 1" << filePath << "`" << std::endl;
        CloseHandle(event->u.CreateProcessInfo.hFile);
        std::cout << "Loaded DLL name '" << filePath << "'" << std::endl;
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
    std::cout << "Process created. Path " << filePath << "`" << std::endl;
    CloseHandle(event->u.CreateProcessInfo.hFile);
    return DBG_CONTINUE;
}
DWORD OnExitThreadDebugEvent(const LPDEBUG_EVENT event) {
    std::cout << "Thread ID `0x" << std::hex << event->dwThreadId << "` is exited with return value " << std::hex << event->u.ExitThread.dwExitCode << std::endl;
    return DBG_CONTINUE;
}
DWORD OnExitProcessDebugEvent(const LPDEBUG_EVENT event) {
    std::cout << "Process exited with return value 0x" << std::hex << event->u.ExitProcess.dwExitCode << " (" << event->u.ExitProcess.dwExitCode << ")" << std::endl;
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