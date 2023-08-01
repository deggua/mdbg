#pragma once

#include "common/types.h"

// NOTE: these are the respective flags bit positions
typedef enum {
    FLAG_CF   = 0,  // CARRY
    FLAG_PF   = 2,  // PARITY
    FLAG_AF   = 4,  // AUX CARRY
    FLAG_ZF   = 6,  // ZERO
    FLAG_SF   = 7,  // SIGN
    FLAG_TF   = 8,  // TRAP
    FLAG_IF   = 9,  // INTERRUPT ENABLE
    FLAG_DF   = 10, // DIRECTION
    FLAG_OF   = 11, // OVERFLOW
    FLAG_IOPL = 12, // IO PRIVILEGE (2 bits wide [13:12])
    FLAG_NT   = 14, // NESTED TASK
    FLAG_MD   = 15, // MODE
    FLAG_RF   = 16, // RESUME
    FLAG_VM   = 17, // VIRTUAL 8086 MODE
    FLAG_AC   = 18, // ALIGNMENT CHECK
    FLAG_VIF  = 19, // VIRTUAL INTERRUPT
    FLAG_VIP  = 20, // VIRTUAL INTERRUPT PENDING
    FLAG_ID   = 21, // CPUID AVAILABLE
    FLAG_AI   = 31, // ALTERNATE INSTRUCTION SET
} DBG_Flag;

#define FLAG_MASK(flag) (1ull << flag)

typedef enum {
#define X(_reg, ...) REG_##_reg,

    // Flags
    REG_BEGIN_FLAGS,
#include "./regs/flags.inc"
    REG_END_FLAGS,

    // Instruction pointer
    REG_BEGIN_IP,
#include "./regs/instruction_pointer.inc"
    REG_END_IP,

    // Debug Registers (TODO: not sure of width in general, on 64-bit they're 64, but I imagine
    // they're 32 on 32-bit)
    REG_BEGIN_DEBUG,
#include "./regs/debug_registers.inc"
    REG_END_DEBUG,

    // Segment Registers (16-bit)
    REG_BEGIN_SEGMENT,
#include "./regs/segment_registers.inc"
    REG_END_SEGMENT,

    // Control
    // TODO: ?

    // GPRs (8-bit)
    REG_BEGIN_GPR8,
#include "./regs/gpr_8bit.inc"
    REG_END_GPR8,

    // GPRs (16-bit)
    REG_BEGIN_GPR16,
#include "./regs/gpr_16bit.inc"
    REG_END_GPR16,

    // GPRs (32-bit)
    REG_BEGIN_GPR32,
#include "./regs/gpr_32bit.inc"
    REG_END_GPR32,

    // GPRs (64-bit)
    REG_BEGIN_GPR64,
#include "./regs/gpr_64bit.inc"
    REG_END_GPR64,

    // MMX (64-bit)
    REG_BEGIN_MMX,
#include "./regs/mmx.inc"
    REG_END_MMX,

    // SSE
    REG_BEGIN_SSE,
#include "./regs/sse.inc"
    REG_END_SSE,

    // AVX (256-bit)
    REG_BEGIN_AVX,
#include "./regs/avx.inc"
    REG_END_AVX,

    // AVX512 XMMn (128-bit)
    REG_BEGIN_AVX512_XMM,
#include "./regs/avx512_xmm.inc"
    REG_END_AVX512_XMM,

    // AVX512 YMMn (256-bit)
    REG_BEGIN_AVX512_YMM,
#include "./regs/avx512_ymm.inc"
    REG_END_AVX512_YMM,

    // AVX512 ZMMn (512-bit)
    REG_BEGIN_AVX512_ZMM,
#include "./regs/avx512_zmm.inc"
    REG_END_AVX512_ZMM,

    // TODO: AVX512 kmask registers?

    // x87 FPU
    REG_BEGIN_X87,
#include "./regs/x87.inc"
    REG_END_X87,

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
