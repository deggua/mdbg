#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "common/types.h"

#if MDBG_TARGET_ARCH == MDBG_ARCH_X86_64
#    include "./x86_64/x86_64.h"
#elif MDBG_TARGET_ARCH == MDBG_ARCH_AARCH64
// TODO: when supporting ARM
#endif

#define REG_INVALID (-1)

typedef uintptr_t DBG_Address;
typedef u64       DBG_PID;

typedef struct DBG_Thread     DBG_Thread;
typedef struct DBG_Process    DBG_Process;
typedef struct DBG_Breakpoint DBG_Breakpoint;

typedef enum {
    DBG_EventType_Unknown         = 0,
    DBG_EventType_Breakpoint      = (1 << 0), // Indicates the process hit a breakpoint
    DBG_EventType_StepInstruction = (1 << 1), // Indicates an instruction was stepped
} DBG_EventType;

typedef struct {
    DBG_Process* process;
    DBG_Thread*  thread;

    DBG_EventType type;

    DBG_Breakpoint* breakpoint;
} DBG_Event;

typedef enum {
    DBG_RegisterType_NULL,
    DBG_RegisterType_U8,
    DBG_RegisterType_U16,
    DBG_RegisterType_U32,
    DBG_RegisterType_U64,
    DBG_RegisterType_U128,
    DBG_RegisterType_U256,
    DBG_RegisterType_U512,
    DBG_RegisterType_F32,
    DBG_RegisterType_F64,
    DBG_RegisterType_F80,
} DBG_RegisterType;

// rw -> Updated on read, used for writing
// r  -> Updated on read

typedef struct {
    u8 rw_val;
} DBG_RegisterValue_U8;

typedef struct {
    u16 rw_val;
} DBG_RegisterValue_U16;

typedef struct {
    u32 rw_val;
} DBG_RegisterValue_U32;

typedef struct {
    u64 rw_val;
} DBG_RegisterValue_U64;

typedef struct {
    u64 rw_val[2]; // [0] = bottom, [1] = top
} DBG_RegisterValue_U128;

typedef struct {
    u64 rw_val[4]; // [0] = lowest 64, [3] = highest 64
} DBG_RegisterValue_U256;

typedef struct {
    u64 rw_val[8]; // [0] = lowest 64, [7] = highest 64
} DBG_RegisterValue_U512;

typedef struct {
    double r_approx;
    u32    rw_val; // raw bits
} DBG_RegisterValue_F32;

typedef struct {
    double r_approx;
    u64    rw_val; // raw bits
} DBG_RegisterValue_F64;

typedef struct {
    double r_approx;
    u64    rw_val_lower64; // lower 64-bits
    u16    rw_val_upper16; // upper 16-bits
} DBG_RegisterValue_F80;

typedef struct {
    DBG_RegisterType type;

    union {
        DBG_RegisterValue_U8   U8;
        DBG_RegisterValue_U16  U16;
        DBG_RegisterValue_U32  U32;
        DBG_RegisterValue_U64  U64;
        DBG_RegisterValue_U128 U128;
        DBG_RegisterValue_U256 U256;
        DBG_RegisterValue_U512 U512;
        DBG_RegisterValue_F32  F32;
        DBG_RegisterValue_F64  F64;
        DBG_RegisterValue_F80  F80;
    };
} DBG_RegisterValue;

typedef struct {
    DBG_Address address;
    bool        enabled;
    size_t      hit_count;
} DBG_BreakpointInfo;

// Creates a debuggable process instance
DBG_Process* DBG_Process_AttachNew(const char* executable, const char* args, const char* workdir);
DBG_Process* DBG_Process_AttachPID(DBG_PID pid);

// Waits or continues after supported debug events
DBG_Event DBG_Begin(DBG_Process* proc);
DBG_Event DBG_Continue(DBG_Event event, DBG_Process* proc);
DBG_Event DBG_StepInstruction(DBG_Event event, DBG_Process* proc, DBG_Thread* thread);
DBG_Event DBG_NextInstruction(DBG_Event event, DBG_Process* proc, DBG_Thread* thread);

// Manipulate the debuggable process instance
bool DBG_Process_Detach(DBG_Process* proc);
bool DBG_Process_Suspend(DBG_Process* proc);
bool DBG_Process_Resume(DBG_Process* proc);
bool DBG_Process_Kill(DBG_Process* proc);
// TODO: get all threads in a process

// Read/write to a process's memory
bool DBG_Process_WriteMemory(DBG_Process* proc, DBG_Address addr, const void* data, size_t len);
bool DBG_Process_ReadMemory(DBG_Process* proc, DBG_Address addr, void* data, size_t len);

// Manipulate breakpoints in a process
DBG_Breakpoint*    DBG_Process_SetBP(DBG_Process* proc, DBG_Address address);
DBG_Breakpoint*    DBG_Process_GetBP(DBG_Process* proc, DBG_Address address);
bool               DBG_Process_DisableBP(DBG_Process* proc, DBG_Breakpoint* breakpoint);
bool               DBG_Process_EnableBP(DBG_Process* proc, DBG_Breakpoint* breakpoint);
bool               DBG_Process_DeleteBP(DBG_Process* proc, DBG_Breakpoint* breakpoint);
DBG_BreakpointInfo DBG_Process_QueryBP(DBG_Process* proc, DBG_Breakpoint* breakpoint);

// Enables the read/write of a thread's registers
// Getting a register that isn't supported by the host CPU returns 0
DBG_RegisterValue DBG_Thread_ReadRegister(DBG_Thread* thread, DBG_Register reg);
bool DBG_Thread_WriteRegister(DBG_Thread* thread, DBG_Register reg, DBG_RegisterValue value);

// Manipulate threads
bool DBG_Thread_Suspend(DBG_Thread* thread);
bool DBG_Thread_Resume(DBG_Thread* thread);
bool DBG_Thread_Kill(DBG_Thread* thread);

// Helper functions for interacting with registers
const char*      DBG_Register_Name(DBG_Register reg);
DBG_Register     DBG_Register_FromName(const char* name);
DBG_RegisterType DBG_Register_Type(DBG_Register reg);
bool             DBG_HasCpuFeature(DBG_CpuFeature feature);

// TODO: not sure about these
#if 0
// TODO: API for si/ni, shouldn't necessarily set a breakpoint
// but should have some way to tell if an instruction is a call instruction or not
// and get the next instruction to set a BP at
DBG_Address DBG_NextInstruction(DBG_Thread* thread);

// TODO: no idea how to implement this
// DBG_SetWatchpoint()

// TODO: HANDLEs on Windows and File Descriptors on Linux are useful to see
// TODO: Memory map of a process is useful

// these I'm less sure about
// TODO: callstack/stack operations (dumping stack, viewing backtrace, etc)?
// TODO: symbol handling?
#endif
