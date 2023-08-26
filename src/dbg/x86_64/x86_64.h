#pragma once

#include "common/types.h"

// NOTE: these are the respective flags bit positions
typedef enum {
    DBG_Flag_CF   = 0,  // CARRY FLAG
    DBG_Flag_PF   = 2,  // PARITY FLAG
    DBG_Flag_AF   = 4,  // AUX CARRY FLAG
    DBG_Flag_ZF   = 6,  // ZERO FLAG
    DBG_Flag_SF   = 7,  // SIGN FLAG
    DBG_Flag_TF   = 8,  // TRAP FLAG
    DBG_Flag_IF   = 9,  // INTERRUPT ENABLE FLAG
    DBG_Flag_DF   = 10, // DIRECTION FLAG
    DBG_Flag_OF   = 11, // OVERFLOW FLAG
    DBG_Flag_IOPL = 12, // IO PRIVILEGE (2 bits wide [13:12]) FLAG
    DBG_Flag_NT   = 14, // NESTED TASK FLAG
    DBG_Flag_MD   = 15, // MODE FLAG
    DBG_Flag_RF   = 16, // RESUME FLAG
    DBG_Flag_VM   = 17, // VIRTUAL 8086 MODE FLAG
    DBG_Flag_AC   = 18, // ALIGNMENT CHECK FLAG
    DBG_Flag_VIF  = 19, // VIRTUAL INTERRUPT FLAG
    DBG_Flag_VIP  = 20, // VIRTUAL INTERRUPT PENDING FLAG
    DBG_Flag_ID   = 21, // CPUID AVAILABLE FLAG
    DBG_Flag_AI   = 31, // ALTERNATE INSTRUCTION SET FLAG
} DBG_Flag;

#define DBG_FLAG_MASK(flag) (1ull << flag)

typedef enum {
#define X(_reg, ...) DBG_Register_##_reg,

    // Flags
    DBG_Register_BEGIN_FLAGS,
#include "./regs/flags.inc"
    DBG_Register_END_FLAGS,

    // Instruction pointer
    DBG_Register_BEGIN_IP,
#include "./regs/instruction_pointer.inc"
    DBG_Register_END_IP,

    // Debug Registers (TODO: not sure of width in general, on 64-bit they're 64, but I imagine
    // they're 32 on 32-bit)
    DBG_Register_BEGIN_DEBUG,
#include "./regs/debug_registers.inc"
    DBG_Register_END_DEBUG,

    // Segment Registers (16-bit)
    DBG_Register_BEGIN_SEGMENT,
#include "./regs/segment_registers.inc"
    DBG_Register_END_SEGMENT,

    // Control
    // TODO: ?

    // GPRs (8-bit)
    DBG_Register_BEGIN_GPR8,
#include "./regs/gpr_8bit.inc"
    DBG_Register_END_GPR8,

    // GPRs (16-bit)
    DBG_Register_BEGIN_GPR16,
#include "./regs/gpr_16bit.inc"
    DBG_Register_END_GPR16,

    // GPRs (32-bit)
    DBG_Register_BEGIN_GPR32,
#include "./regs/gpr_32bit.inc"
    DBG_Register_END_GPR32,

    // GPRs (64-bit)
    DBG_Register_BEGIN_GPR64,
#include "./regs/gpr_64bit.inc"
    DBG_Register_END_GPR64,

    // MMX (64-bit)
    DBG_Register_BEGIN_MMX,
#include "./regs/mmx.inc"
    DBG_Register_END_MMX,

    // SSE
    DBG_Register_BEGIN_SSE,
#include "./regs/sse.inc"
    DBG_Register_END_SSE,

    // AVX (256-bit)
    DBG_Register_BEGIN_AVX,
#include "./regs/avx.inc"
    DBG_Register_END_AVX,

    // AVX512 XMMn (128-bit)
    DBG_Register_BEGIN_AVX512_XMM,
#include "./regs/avx512_xmm.inc"
    DBG_Register_END_AVX512_XMM,

    // AVX512 YMMn (256-bit)
    DBG_Register_BEGIN_AVX512_YMM,
#include "./regs/avx512_ymm.inc"
    DBG_Register_END_AVX512_YMM,

    // AVX512 ZMMn (512-bit)
    DBG_Register_BEGIN_AVX512_ZMM,
#include "./regs/avx512_zmm.inc"
    DBG_Register_END_AVX512_ZMM,

    // TODO: AVX512 kmask registers?

    // x87 FPU
    DBG_Register_BEGIN_X87,
#include "./regs/x87.inc"
    DBG_Register_END_X87,

#undef X

} DBG_Register;

// TODO: others?
typedef enum {
    DBG_CpuFeature_MMX,
    DBG_CpuFeature_SSE,
    DBG_CpuFeature_AVX,
    DBG_CpuFeature_AVX512,
    DBG_CpuFeature_X87,
} DBG_CpuFeature;

// int3 instruction encoding
#define DBG_BREAKPOINT_INSTRUCTION 0xCC
#define DBG_MAX_INSTRUCTION_LEN    15
