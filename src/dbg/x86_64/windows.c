#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include <windows.h>

#include "dbg/dbg.h"
#include "dbg/dbg_internal.h"
#include "deps/zydis/Zydis.h"

#define MAX_BPS 16

typedef struct DBG_Thread {
    DWORD    id;
    HANDLE   handle;
    void*    ctx_buffer;
    CONTEXT* ctx;
} DBG_Thread;

typedef struct DBG_Process {
    DWORD  id;
    HANDLE handle;
} DBG_Process;

// TODO: HW breakpoints
typedef struct DBG_Breakpoint {
    uintptr_t address;
    size_t    hit_count;
    bool      enabled;
    bool      in_use;
    u8        original_byte;
} DBG_Breakpoint;

// TODO: Rework the BP API to return BPs from this array
static DBG_Breakpoint Breakpoints[MAX_BPS];

// TODO: Returning DBG_Thread* and DBG_Process* is problematic, we easily leak memory and requiring
// the API to return these objects is unintuitive, need to think about how to handle this

static DBG_Process* MakeProcess(DWORD id, HANDLE handle)
{
    DBG_Process* proc = malloc(sizeof(*proc));
    if (proc == NULL) {
        return NULL;
    }

    proc->id     = id;
    proc->handle = handle;
    return proc;
}

static DBG_Thread* MakeThread(DWORD id, HANDLE* handle)
{
    DBG_Thread* thread = malloc(sizeof(*thread));
    if (thread == NULL) {
        return NULL;
    }

    thread->id     = id;
    thread->handle = handle;
    return thread;
}

static DBG_Breakpoint* LocateActiveBP(DBG_Address bp_addr)
{
    for (size_t ii = 0; ii < lengthof(Breakpoints); ii++) {
        DBG_Breakpoint* bp = &Breakpoints[ii];
        if (bp->in_use && bp->enabled && bp->address == bp_addr) {
            return bp;
        }
    }

    return NULL;
}

DBG_Event DBG_Process_DebugWait(DBG_Process* proc)
{
    while (true) {
        DEBUG_EVENT e = {0};
        WaitForDebugEvent(&e, INFINITE);

        if (e.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
            && e.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
            // TODO: don't leak the thread instance
            // TODO: error handling

            HANDLE* thread = OpenThread(THREAD_ALL_ACCESS, FALSE, e.dwThreadId);

            CONTEXT ctx = {.ContextFlags = CONTEXT_FULL};
            GetThreadContext(thread, &ctx);

            DBG_Address     bp_addr = ctx.Rip - 1;
            DBG_Breakpoint* bp      = LocateActiveBP(bp_addr);
            if (bp != NULL) {
                // rewind and set singlestep flag so that we can re-enable the breakpoint on
                // continue
                ctx.Rip -= 1;
                ctx.ContextFlags = CONTEXT_FULL;
                SetThreadContext(thread, &ctx);

                bp->hit_count += 1;
            }

            return (DBG_Event){
                .process          = proc,
                .thread           = MakeThread(e.dwThreadId, thread),
                .type             = DBG_EventType_Breakpoint,
                .event_breakpoint = bp,
            };
        } else {
            // TODO: handle other exception types
            ContinueDebugEvent(e.dwProcessId, e.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
        }
    }
}

void DBG_Process_DebugContinue(DBG_Event* e)
{
    if (e->type == DBG_EventType_Breakpoint && e->event_breakpoint.bp) {
        DBG_Process_DisableBP(e->process, e->event_breakpoint.bp);

        CONTEXT ctx = {.ContextFlags = CONTEXT_FULL};
        GetThreadContext(e->thread->handle, &ctx);

        // single step flag so we can re-enable the breakpoint
        ctx.EFlags |= FLAG_MASK(FLAG_TF);
        ctx.ContextFlags = CONTEXT_FULL;
        SetThreadContext(e->thread->handle, &ctx);
    }

    ContinueDebugEvent(e->process->id, e->thread->id, DBG_CONTINUE);

    if (e->type == DBG_EventType_Breakpoint && e->event_breakpoint.bp) {
        DEBUG_EVENT e_step = {0};
        WaitForDebugEvent(&e_step, INFINITE);

        // TODO: what about back to back breakpoints?
        if (!(e_step.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
              && e_step.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)) {
            ABORT(
                "Unexpected debug event raised when expecting single step event.\n"
                "EventCode = %lu\n"
                "ExceptionCode = %lu\n",
                e_step.dwDebugEventCode,
                e_step.u.Exception.ExceptionRecord.ExceptionCode);
        }

        DBG_Process_EnableBP(e->process, e->event_breakpoint.bp);

        ContinueDebugEvent(e->process->id, e->thread->id, DBG_CONTINUE);
    }
}

bool DBG_HasCpuFeature(DBG_CpuFeature feature)
{
    DWORD64 features = GetEnabledXStateFeatures();

    switch (feature) {
        case DBG_CpuFeature_MMX: {
            // TODO: I think this is always available on x86_64 CPUs, but might not exist on
            // i386 CPUs
            return true;
        } break;

        case DBG_CpuFeature_X87: {
            return !!(features & XSTATE_MASK_LEGACY_FLOATING_POINT);
        } break;

        case DBG_CpuFeature_SSE: {
            return !!(features & XSTATE_MASK_LEGACY_SSE);
        } break;

        case DBG_CpuFeature_AVX: {
            return !!(features & XSTATE_MASK_AVX);
        } break;

        case DBG_CpuFeature_AVX512: {
            return !!(features & XSTATE_MASK_AVX512);
        } break;
    }

    return false;
}

// TODO: basically we need to do the following
// 1. Figure out what features are available
// 2. Setup a CONTEXT to request all the registers for all features
// 3. Get the CONTEXT with all features
// 4. Save the pointers/etc to the DBG_Thread object
// 5. When we actually want to read registers we refer to the cached CONTEXT object
// 5a. If a feature doesn't exist then we return 0
// 6. When we actually want to write registers we write to the cached CONTEXT object (might need to
// 6a. If a feature doesn't exist we return a failure
// track what registers were modified)
// 7. When we want to update a thread's context we call SetContext which uses the cached, modified
// CONTEXT to update the thread's registers

// Figuring out the byte layout for these opaque layouts is confusing, what a terrible API
// It's also slightly more tricky because we want to support all the sub-registers in x86
// e.g. writes to EIP modify RIP, etc.
bool DBG_Thread_GetContext(DBG_Thread* thread)
{
    // TODO: error handling
    // see:
    // https://github.com/x64dbg/TitanEngine/blob/01d0d1854f2b16e60b4efc9f84476c67305d8f7c/TitanEngine/TitanEngine.Debugger.Context.cpp#L966

    DWORD ctx_size = 0;
    InitializeContext(NULL, CONTEXT_ALL | CONTEXT_XSTATE, NULL, &ctx_size);

    void*    buffer = malloc(ctx_size);
    CONTEXT* ctx;
    InitializeContext(buffer, CONTEXT_ALL | CONTEXT_XSTATE, &ctx, &ctx_size);

    SetXStateFeaturesMask(
        ctx,
        XSTATE_MASK_LEGACY_FLOATING_POINT | XSTATE_MASK_LEGACY_SSE | XSTATE_MASK_AVX
            | XSTATE_MASK_AVX512);
    GetThreadContext(thread->handle, ctx);

    thread->ctx_buffer = buffer;
    thread->ctx        = ctx;
}

bool DBG_Thread_SetContext(DBG_Thread* thread)
{
    // TODO: correct?
    thread->ctx->ContextFlags |= CONTEXT_ALL | CONTEXT_XSTATE;
    SetThreadContext(thread->handle, thread->ctx);
}

static DBG_RegisterValue ExtRegisterFromContext(CONTEXT* ctx, DBG_Register reg)
{
    if (REG_BEGIN_SSE < reg && reg < REG_END_SSE) {
        M128A* xmm = LocateXStateFeature(ctx, XSTATE_LEGACY_SSE, NULL);
        if (xmm == NULL) {
            return DBG_RV_NULL();
        }

        int index = reg - REG_XMM0;
        return DBG_RV_U128(xmm[index].Low, xmm[index].High);

    } else if (REG_BEGIN_AVX < reg && reg < REG_END_AVX) {
        M128A* ymm_upper = LocateXStateFeature(ctx, XSTATE_AVX, NULL);
        M128A* ymm_lower = LocateXStateFeature(ctx, XSTATE_LEGACY_SSE, NULL);
        if (ymm_upper == NULL || ymm_lower == NULL) {
            return DBG_RV_NULL();
        }

        int index = reg - REG_YMM0;
        return DBG_RV_U256(
            ymm_lower[index].Low,
            ymm_lower[index].High,
            ymm_upper[index].Low,
            ymm_upper[index].High);
    }
    // TODO: AVX512, X87, MMX

    return (DBG_RegisterValue){
        .type = DBG_RegisterValueType_NULL,
    };
}

DBG_RegisterValue DBG_Thread_ReadRegister(DBG_Thread* thread, DBG_Register reg)
{
    CONTEXT* ctx = thread->ctx;

    // clang-format off
    switch (reg) {
        /* flags */
        case REG_FLAGS:  return DBG_RV_U16(ctx->EFlags & 0xFFFF);
        case REG_EFLAGS: return DBG_RV_U32(ctx->EFlags & 0xFFFFFFFF);
        case REG_RFLAGS: return DBG_RV_U64(ctx->EFlags);

        /* instruction pointer */
        case REG_IP:  return DBG_RV_U16(ctx->Rip & 0xFFFF);
        case REG_EIP: return DBG_RV_U32(ctx->Rip & 0xFFFFFFFFF);
        case REG_RIP: return DBG_RV_U64(ctx->Rip);

        /* debug registers */
        case REG_DR0: return DBG_RV_U64(ctx->Dr0);
        case REG_DR1: return DBG_RV_U64(ctx->Dr1);
        case REG_DR2: return DBG_RV_U64(ctx->Dr2);
        case REG_DR3: return DBG_RV_U64(ctx->Dr3);
        case REG_DR4: return DBG_RV_U64(ctx->Dr6);
        case REG_DR5: return DBG_RV_U64(ctx->Dr7);
        case REG_DR6: return DBG_RV_U64(ctx->Dr6);
        case REG_DR7: return DBG_RV_U64(ctx->Dr7);

        /* segment registers */
        case REG_CS: return DBG_RV_U16(ctx->SegCs);
        case REG_SS: return DBG_RV_U16(ctx->SegSs);
        case REG_DS: return DBG_RV_U16(ctx->SegDs);
        case REG_ES: return DBG_RV_U16(ctx->SegEs);
        case REG_FS: return DBG_RV_U16(ctx->SegFs);
        case REG_GS: return DBG_RV_U16(ctx->SegGs);

        /* GPRs 8-bit */
        case REG_AH:   return DBG_RV_U8((ctx->Rax >> 8) & 0xFF);
        case REG_AL:   return DBG_RV_U8((ctx->Rax >> 0) & 0xFF);
        case REG_BH:   return DBG_RV_U8((ctx->Rbx >> 8) & 0xFF);
        case REG_BL:   return DBG_RV_U8((ctx->Rbx >> 0) & 0xFF);
        case REG_CH:   return DBG_RV_U8((ctx->Rcx >> 8) & 0xFF);
        case REG_CL:   return DBG_RV_U8((ctx->Rcx >> 0) & 0xFF);
        case REG_DH:   return DBG_RV_U8((ctx->Rdx >> 8) & 0xFF);
        case REG_DL:   return DBG_RV_U8((ctx->Rdx >> 0) & 0xFF);
        case REG_SIL:  return DBG_RV_U8((ctx->Rsi >> 0) & 0xFF);
        case REG_DIL:  return DBG_RV_U8((ctx->Rdi >> 0) & 0xFF);
        case REG_BPL:  return DBG_RV_U8((ctx->Rbp >> 0) & 0xFF);
        case REG_SPL:  return DBG_RV_U8((ctx->Rsp >> 0) & 0xFF);
        case REG_R8B:  return DBG_RV_U8((ctx->R8  >> 0) & 0xFF);
        case REG_R9B:  return DBG_RV_U8((ctx->R9  >> 0) & 0xFF);
        case REG_R10B: return DBG_RV_U8((ctx->R10 >> 0) & 0xFF);
        case REG_R11B: return DBG_RV_U8((ctx->R11 >> 0) & 0xFF);
        case REG_R12B: return DBG_RV_U8((ctx->R12 >> 0) & 0xFF);
        case REG_R13B: return DBG_RV_U8((ctx->R13 >> 0) & 0xFF);
        case REG_R14B: return DBG_RV_U8((ctx->R14 >> 0) & 0xFF);
        case REG_R15B: return DBG_RV_U8((ctx->R15 >> 0) & 0xFF);

        /* GPRs 16-bit */
        case REG_AX:   return DBG_RV_U16(ctx->Rax & 0xFFFF);
        case REG_BX:   return DBG_RV_U16(ctx->Rbx & 0xFFFF);
        case REG_CX:   return DBG_RV_U16(ctx->Rcx & 0xFFFF);
        case REG_DX:   return DBG_RV_U16(ctx->Rdx & 0xFFFF);
        case REG_SI:   return DBG_RV_U16(ctx->Rsi & 0xFFFF);
        case REG_DI:   return DBG_RV_U16(ctx->Rdi & 0xFFFF);
        case REG_BP:   return DBG_RV_U16(ctx->Rbp & 0xFFFF);
        case REG_SP:   return DBG_RV_U16(ctx->Rsp & 0xFFFF);
        case REG_R8W:  return DBG_RV_U16(ctx->R8  & 0xFFFF);
        case REG_R9W:  return DBG_RV_U16(ctx->R9  & 0xFFFF);
        case REG_R10W: return DBG_RV_U16(ctx->R10 & 0xFFFF);
        case REG_R11W: return DBG_RV_U16(ctx->R11 & 0xFFFF);
        case REG_R12W: return DBG_RV_U16(ctx->R12 & 0xFFFF);
        case REG_R13W: return DBG_RV_U16(ctx->R13 & 0xFFFF);
        case REG_R14W: return DBG_RV_U16(ctx->R14 & 0xFFFF);
        case REG_R15W: return DBG_RV_U16(ctx->R15 & 0xFFFF);

        /* GPRs 32-bit */
        case REG_EAX:  return DBG_RV_U32(ctx->Rax & 0xFFFFFFFF);
        case REG_EBX:  return DBG_RV_U32(ctx->Rbx & 0xFFFFFFFF);
        case REG_ECX:  return DBG_RV_U32(ctx->Rcx & 0xFFFFFFFF);
        case REG_EDX:  return DBG_RV_U32(ctx->Rdx & 0xFFFFFFFF);
        case REG_ESI:  return DBG_RV_U32(ctx->Rsi & 0xFFFFFFFF);
        case REG_EDI:  return DBG_RV_U32(ctx->Rdi & 0xFFFFFFFF);
        case REG_EBP:  return DBG_RV_U32(ctx->Rbp & 0xFFFFFFFF);
        case REG_ESP:  return DBG_RV_U32(ctx->Rsp & 0xFFFFFFFF);
        case REG_R8D:  return DBG_RV_U32(ctx->R8  & 0xFFFFFFFF);
        case REG_R9D:  return DBG_RV_U32(ctx->R9  & 0xFFFFFFFF);
        case REG_R10D: return DBG_RV_U32(ctx->R10 & 0xFFFFFFFF);
        case REG_R11D: return DBG_RV_U32(ctx->R11 & 0xFFFFFFFF);
        case REG_R12D: return DBG_RV_U32(ctx->R12 & 0xFFFFFFFF);
        case REG_R13D: return DBG_RV_U32(ctx->R13 & 0xFFFFFFFF);
        case REG_R14D: return DBG_RV_U32(ctx->R14 & 0xFFFFFFFF);
        case REG_R15D: return DBG_RV_U32(ctx->R15 & 0xFFFFFFFF);

        /* GPRs 64-bit */
        case REG_RAX: return DBG_RV_U64(ctx->Rax);
        case REG_RBX: return DBG_RV_U64(ctx->Rbx);
        case REG_RCX: return DBG_RV_U64(ctx->Rcx);
        case REG_RDX: return DBG_RV_U64(ctx->Rdx);
        case REG_RSI: return DBG_RV_U64(ctx->Rsi);
        case REG_RDI: return DBG_RV_U64(ctx->Rdi);
        case REG_RBP: return DBG_RV_U64(ctx->Rbp);
        case REG_RSP: return DBG_RV_U64(ctx->Rsp);
        case REG_R8:  return DBG_RV_U64(ctx->R8 );
        case REG_R9:  return DBG_RV_U64(ctx->R9 );
        case REG_R10: return DBG_RV_U64(ctx->R10);
        case REG_R11: return DBG_RV_U64(ctx->R11);
        case REG_R12: return DBG_RV_U64(ctx->R12);
        case REG_R13: return DBG_RV_U64(ctx->R13);
        case REG_R14: return DBG_RV_U64(ctx->R14);
        case REG_R15: return DBG_RV_U64(ctx->R15);

        // clang-format on

        /* others */
        default: {
            if ((REG_BEGIN_X87 < reg && reg < REG_END_X87)
                || (REG_BEGIN_MMX < reg && reg < REG_END_MMX)
                || (REG_BEGIN_SSE < reg && reg < REG_END_SSE)
                || (REG_BEGIN_AVX < reg && reg < REG_END_AVX)
                || (REG_BEGIN_AVX512_XMM < reg && reg < REG_END_AVX512_XMM)
                || (REG_BEGIN_AVX512_YMM < reg && reg < REG_END_AVX512_YMM)
                || (REG_BEGIN_AVX512_ZMM < reg && reg < REG_END_AVX512_ZMM)) {
                return ExtRegisterFromContext(ctx, reg);
            } else {
                // must be invalid
                return DBG_RV_NULL();
            }
        } break;
    }
}

void DBG_Thread_WriteRegister(DBG_Thread* thread, DBG_Register reg, DBG_RegisterValue value)
{
    // TODO
}

bool DBG_Process_WriteMemory(DBG_Process* proc, DBG_Address addr, const void* data, size_t len)
{
    bool result = WriteProcessMemory(proc->handle, (LPVOID)addr, data, len, NULL);
    if (!result) {
        return result;
    }

    for (size_t ii = 0; ii < lengthof(Breakpoints); ii++) {
        DBG_Breakpoint* bp = &Breakpoints[ii];
        if (!bp->enabled) {
            continue;
        }

        if (addr <= bp->address && bp->address < addr + len) {
            u8 bp_opcode = DBG_BREAKPOINT_INSTRUCTION;
            // TODO: check return value?
            WriteProcessMemory(
                proc->handle,
                (LPVOID)bp->address,
                &bp_opcode,
                sizeof(bp_opcode),
                NULL);
        }
    }

    return FlushInstructionCache(proc->handle, (LPCVOID)addr, len);
}

bool DBG_Process_ReadMemory(DBG_Process* proc, DBG_Address addr, void* data, size_t len)
{
    bool result = ReadProcessMemory(proc->handle, (LPCVOID)addr, data, len, NULL);
    if (!result) {
        return result;
    }

    // fake the read data for breakpoints so they are hidden from disas
    for (size_t ii = 0; ii < lengthof(Breakpoints); ii++) {
        DBG_Breakpoint* bp = &Breakpoints[ii];
        if (!bp->enabled) {
            continue;
        }

        if (addr <= bp->address && bp->address < addr + len) {
            size_t offset = bp->address - addr;
            char*  ptr    = data;
            ptr[offset]   = bp->original_byte;
        }
    }

    return result;
}

// TODO: we want the API to work like this for efficiency reasons
// DBG_Event e = DBG_WaitForDebugEvent(...) -- actually suspends threads
// DBG_
// DBG_ReadRegister(...)
// DBG_WriteRegister(...)
// DBG_ContinueDebugEvent(...) -- actually resumes threads

// DBG_SetBreakpoint shouldn't require SuspendThread/ResumeThread even though it intuitively makes
// sense that it would be required, the reason it shouldn't is that it would be a pain to determine
// which thread can execute some code segment (and not feasible in general)

// I'm not sure if this currently works like this, I
// imagine that when the debugger receives a debug event the entire debugee is suspend (process +
// all threads) since other shit would be broken, but I'm not sure
bool DBG_Thread_Suspend(DBG_Thread* thread)
{
    if (SuspendThread(thread->handle) == (DWORD)-1) {
        return false;
    }
}

bool DBG_Thread_Resume(DBG_Thread* thread)
{
    ResumeThread(thread->handle);
}

bool DBG_Thread_Kill(DBG_Thread* thread)
{
    // TODO: do we even want this functionality?
    // TODO: what exit code?
    TerminateThread(thread->handle, 0);
}

DBG_Process* DBG_Process_AttachNew(const char* exe, const char* args, const char* workdir)
{
    DBG_Process* proc = malloc(sizeof(*proc));
    if (proc == NULL) {
        goto error_MallocProc;
    }

    // have to make a copy of args because Windows wants a writeable buffer
    // not ideal, but this makes the API better imo, and there isn't a signficiant performance
    // cost
    char* args_copy = NULL;
    if (args != NULL) {
        args_copy = malloc(strlen(args) + 1);
        if (args_copy == NULL) {
            goto error_MallocArgs;
        }

        strcpy(args_copy, args);
    }

    STARTUPINFO         startup_info = {0};
    PROCESS_INFORMATION proc_info    = {0};

    BOOL result = CreateProcess(
        exe,
        args_copy,
        NULL,
        NULL,
        FALSE,
        DEBUG_ONLY_THIS_PROCESS
            | CREATE_NEW_CONSOLE, // TODO: I want to eventually redirect I/O to the TUI
        NULL,
        workdir,
        &startup_info,
        &proc_info);

    if (!result) {
        goto error_CreateProcess;
    }

    proc->id     = proc_info.dwProcessId;
    proc->handle = proc_info.hProcess;
    return proc;

error_CreateProcess:
    free(args_copy);
error_MallocArgs:
    free(proc);
error_MallocProc:
    return NULL;
}

DBG_Process* DBG_Process_AttachPID(DBG_PID pid)
{
    DWORD proc_id = (DWORD)pid;

    DBG_Process* proc = malloc(sizeof(*proc));
    if (proc == NULL) {
        goto error_Malloc;
    }

    HANDLE proc_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id);
    if (proc_handle == NULL) {
        goto error_OpenProcess;
    }

    if (!DebugActiveProcess(proc_id)) {
        goto error_DebugActiveProcess;
    }

    proc->id     = proc_id;
    proc->handle = proc_handle;
    return proc;

error_DebugActiveProcess:
    CloseHandle(proc_handle);
error_OpenProcess:
    free(proc);
error_Malloc:
    return NULL;
}

bool DBG_Process_Detach(DBG_Process* proc)
{
    return DebugActiveProcessStop(proc->id);
}

// TODO: do we want to do DebugActiveProcess or DebugBreakProcess? Leaning towards the latter
bool DBG_Process_Suspend(DBG_Process* proc)
{
    return DebugActiveProcess(proc->id);
}

bool DBG_Process_Resume(DBG_Process* proc)
{
    // After DebugActiveProcess is called, the last debugger event Windows raises
    // is an a breakpoint exception, therefore waiting for a breakpoint event
    // and continuing resumes the process

    DBG_Event e = {0};

    do {
        e = DBG_Process_DebugWait(proc);
        DBG_Process_DebugContinue(&e);
    } while (e.type != DBG_EventType_Breakpoint);

    return true;
}

bool DBG_Process_Kill(DBG_Process* proc)
{
    // TODO: I think we have to wait for a debug event here otherwise the process won't exit

    // TODO: what exit code to use?
    if (!TerminateProcess(proc->handle, 1)) {
        return false;
    }

    WaitForSingleObject(proc->handle, INFINITE);
    return true;
}

// if >= 0, the operation succeeded and the return value is the byte replaced
// if < 0, the operation failed but was recoverable
// TODO: this isn't generic for archs where the BP instruction isn't a single byte (e.g. ARM)
// this is okay for now, currently have separate implementations for OS on different arch
// kind of a waste of effort, most code will be the same, the unique parts are the BP instruction,
// registers, and maybe microarch considerations
// TODO: resolve this when architectures are separated
static ssize_t ReplaceInstructionByte(HANDLE proc_handle, LPVOID addr, u8 new_byte)
{
    BOOL result;

    u8 orig_byte;
    result = ReadProcessMemory(proc_handle, addr, &orig_byte, sizeof(orig_byte), NULL);
    if (!result) {
        goto error_ReadProcessMemory;
    }

    result = WriteProcessMemory(proc_handle, addr, &new_byte, sizeof(new_byte), NULL);
    if (!result) {
        goto error_WriteProcessMemory;
    }

    result = FlushInstructionCache(proc_handle, addr, sizeof(new_byte));
    if (!result) {
        goto error_FlushInstructionCache;
    }

    return orig_byte;

error_FlushInstructionCache:
    ABORT("Failed to flush instruction cache");
error_WriteProcessMemory:
error_ReadProcessMemory:
    return -1;
}

static DBG_Breakpoint* ClaimBP(void)
{
    for (size_t ii = 0; ii < lengthof(Breakpoints); ii++) {
        if (!Breakpoints[ii].in_use) {
            Breakpoints[ii].in_use = true;
            return &Breakpoints[ii];
        }
    }

    return NULL;
}

static void ReleaseBP(DBG_Breakpoint* bp)
{
    bp->in_use = false;
}

DBG_Breakpoint* DBG_Process_SetBP(DBG_Process* proc, DBG_Address addr)
{
    // TODO: HW breakpoints
    DBG_Breakpoint* bp = ClaimBP();
    if (bp == NULL) {
        goto error_NextBP;
    }

    ssize_t ret = ReplaceInstructionByte(proc->handle, (LPVOID)addr, DBG_BREAKPOINT_INSTRUCTION);
    if (ret < 0) {
        goto error_ReplaceInstructionByte;
    }

    bp->address       = addr;
    bp->enabled       = true;
    bp->original_byte = (u8)ret;
    bp->hit_count     = 0;
    return bp;

error_ReplaceInstructionByte:
    ReleaseBP(bp);
error_NextBP:
    return NULL;
}

DBG_Breakpoint* DBG_Process_GetBP(DBG_Process* proc, DBG_Address address)
{
    (void)proc;
    return LocateActiveBP(address);
}

bool DBG_Process_DisableBP(DBG_Process* proc, DBG_Breakpoint* bp)
{
    if (!bp->enabled) {
        return true;
    }

    ssize_t ret = ReplaceInstructionByte(proc->handle, (LPVOID)bp->address, bp->original_byte);
    if (ret < 0) {
        return false;
    }

    bp->enabled = false;
    return true;
}

bool DBG_Process_EnableBP(DBG_Process* proc, DBG_Breakpoint* bp)
{
    if (bp->enabled) {
        return true;
    }

    ssize_t ret
        = ReplaceInstructionByte(proc->handle, (LPVOID)bp->address, DBG_BREAKPOINT_INSTRUCTION);
    if (ret < 0) {
        return false;
    }

    bp->enabled = true;
    return true;
}

bool DBG_Process_DeleteBP(DBG_Process* proc, DBG_Breakpoint* bp)
{
    bool result = DBG_Process_DisableBP(proc, bp);
    if (!result) {
        return result;
    }

    ReleaseBP(bp);
    return true;
}

DBG_BreakpointInfo DBG_Process_QueryBP(DBG_Process* proc, DBG_Breakpoint* breakpoint)
{
    (void)proc;
    return (DBG_BreakpointInfo){
        .address   = breakpoint->address,
        .enabled   = breakpoint->enabled,
        .hit_count = breakpoint->hit_count,
    };
}
