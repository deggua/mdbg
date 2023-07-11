#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static void DumpThreadState(HANDLE thread)
{
    CONTEXT ctx = (CONTEXT){
        .ContextFlags = CONTEXT_FULL,
    };

    if (!GetThreadContext(thread, &ctx)) {
        DWORD err = GetLastError();
        printf("Failed to get thread context!\n");
        printf("ErrorCode = %lu\n", err);
        exit(EXIT_FAILURE);
    }

    printf(
        "RIP = 0x%016llx\n"
        "RAX = 0x%016llx\tRBX = 0x%016llx\tRCX = 0x%016llx\tRDX = 0x%016llx\n"
        "RSI = 0x%016llx\tRDI = 0x%016llx\tRBP = 0x%016llx\tRSP = 0x%016llx\n"
        "R8  = 0x%016llx\tR9  = 0x%016llx\tR10 = 0x%016llx\tR11 = 0x%016llx\n"
        "R12 = 0x%016llx\tR13 = 0x%016llx\tR14 = 0x%016llx\tR15 = 0x%016llx\n",
        ctx.Rip,
        ctx.Rax,
        ctx.Rbx,
        ctx.Rcx,
        ctx.Rdx,
        ctx.Rsi,
        ctx.Rdi,
        ctx.Rbp,
        ctx.Rsp,
        ctx.R8,
        ctx.R9,
        ctx.R10,
        ctx.R11,
        ctx.R12,
        ctx.R13,
        ctx.R14,
        ctx.R15);
}

static void DebugLoop(LPSTARTUPINFO startup_info, LPPROCESS_INFORMATION process_info)
{
    DEBUG_EVENT dbg_event = {0};

    while (true) {
        DWORD continue_status = DBG_EXCEPTION_NOT_HANDLED;

        printf("Waiting for debug event...\n");
        if (!WaitForDebugEvent(&dbg_event, INFINITE)) {
            continue;
        }

        printf("Debug event received!\n");
        switch (dbg_event.dwDebugEventCode) {
            case EXCEPTION_DEBUG_EVENT: {
                switch (dbg_event.u.Exception.ExceptionRecord.ExceptionCode) {
                    case EXCEPTION_ACCESS_VIOLATION: {
                        printf("EXCEPTION_ACCESS_VIOLATION\n");
                    } break;

                    case EXCEPTION_BREAKPOINT: {
                        printf("EXCEPTION_BREAKPOINT\n");
                        continue_status = DBG_CONTINUE;
                    } break;

                    case EXCEPTION_DATATYPE_MISALIGNMENT: {
                        printf("EXCEPTION_DATATYPE_MISALIGNMENT\n");
                    } break;

                    case EXCEPTION_SINGLE_STEP: {
                        printf("EXCEPTION_SINGLE_STEP\n");
                    } break;

                    case DBG_CONTROL_C: {
                        printf("DBG_CONTROL_C\n");
                        SuspendThread(process_info->hThread);
                        DumpThreadState(process_info->hThread);
                        ResumeThread(process_info->hThread);
                        continue_status = DBG_CONTINUE;
                    } break;

                    default: {
                        printf("EXCEPTION_OTHER\n");
                    } break;
                }
            } break;

            case CREATE_THREAD_DEBUG_EVENT: {
                printf("CREATE_THREAD_DEBUG_EVENT\n");
            } break;

            case CREATE_PROCESS_DEBUG_EVENT: {
                printf("CREATE_PROCESS_DEBUG_EVENT\n");
            } break;

            case EXIT_THREAD_DEBUG_EVENT: {
                printf("EXIT_THREAD_DEBUG_EVENT\n");
            } break;

            case EXIT_PROCESS_DEBUG_EVENT: {
                printf("EXIT_PROCESS_DEBUG_EVENT\n");
            } break;

            case LOAD_DLL_DEBUG_EVENT: {
                printf("LOAD_DLL_DEBUG_EVENT\n");
            } break;

            case UNLOAD_DLL_DEBUG_EVENT: {
                printf("UNLOAD_DLL_DEBUG_EVENT\n");
            } break;

            case OUTPUT_DEBUG_STRING_EVENT: {
                printf("OUTPUT_DEBUG_STRING_EVENT\n");
            } break;

            case RIP_EVENT: {
                printf("RIP_EVENT\n");
            } break;

            default: {
                printf("EVENT_OTHER\n");
            } break;
        }

        ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, continue_status);
    }
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        printf(
            "Launch with:\n"
            "\tmdbg.exe app.exe \"[args]\" \"[workdir]\"\n");
        exit(EXIT_FAILURE);
    }

    printf(
        "Process: %s\n"
        "Args: %s\n"
        "Workdir: %s\n",
        argv[1],
        argc > 2 ? argv[2] : "[default]",
        argc > 3 ? argv[3] : "[default]");

    STARTUPINFO         startup_info = {0};
    PROCESS_INFORMATION process_info = {0};

    BOOL proc_created = CreateProcess(
        argv[1],
        argc > 2 ? argv[2] : NULL,
        NULL,
        NULL,
        FALSE,
        DEBUG_PROCESS | CREATE_NEW_CONSOLE,
        NULL,
        argc > 3 ? argv[3] : NULL,
        &startup_info,
        &process_info);

    if (!proc_created) {
        printf("Failed to create inferior process!\n");
        exit(EXIT_FAILURE);
    }

    printf("Process created!\n");

    DebugLoop(&startup_info, &process_info);

    return EXIT_SUCCESS;
}
