#pragma once

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>

#include "common/macros.h"

#if MDBG_TARGET_OS == MDBG_OS_WINDOWS
#    include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#    include <unistd.h>
#endif

#define U8_DEC_FMT  "%" PRIu8
#define U16_DEC_FMT "%" PRIu16
#define U32_DEC_FMT "%" PRIu32
#define U64_DEC_FMT "%" PRIu64

#define U8_HEX_FMT  "%" PRIx8
#define U16_HEX_FMT "%" PRIx16
#define U32_HEX_FMT "%" PRIx32
#define U64_HEX_FMT "%" PRIx64

#define I8_DEC_FMT  "%" PRId8
#define I16_DEC_FMT "%" PRId16
#define I32_DEC_FMT "%" PRId32
#define I64_DEC_FMT "%" PRId64

#define I8_HEX_FMT  "%" PRIx8
#define I16_HEX_FMT "%" PRIx16
#define I32_HEX_FMT "%" PRIx32
#define I64_HEX_FMT "%" PRIx64

typedef float  f32;
typedef double f64;

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef uint_fast8_t  u8_fast;
typedef uint_fast16_t u16_fast;
typedef uint_fast32_t u32_fast;
typedef uint_fast64_t u64_fast;

typedef int_fast8_t  i8_fast;
typedef int_fast16_t i16_fast;
typedef int_fast32_t i32_fast;
typedef int_fast64_t i64_fast;

typedef uint_least8_t  u8_min;
typedef uint_least16_t u16_min;
typedef uint_least32_t u32_min;
typedef uint_least64_t u64_min;

typedef int_least8_t  i8_min;
typedef int_least16_t i16_min;
typedef int_least32_t i32_min;
typedef int_least64_t i64_min;

typedef size_t  usize;
typedef ssize_t isize;

#pragma pack(push, 1)

typedef union {
    f32 f32;

    struct {
        u32 frac : 23;
        u32 exp  : 8;
        u32 sign : 1;
    };

    u32 u32;
    u8  u8[sizeof(f32)];
} f32_ieee754;

typedef union {
    f64 f64;

    struct {
        u64 frac : 52;
        u64 exp  : 11;
        u64 sign : 1;
    };

    u64 u64;
    u8  u8[sizeof(f64)];
} f64_ieee754;

typedef union {
    struct {
        u64 frac    : 63;
        u64 integer : 1;
        u16 exp     : 15;
        u16 sign    : 1;
    };

    struct {
        u64 lower64;
        u16 upper16;
    };

    u8 u8[sizeof(u64) + sizeof(u16)];
} f80_ieee754;

#pragma pack(pop)

static_assert_decl(sizeof(f32) == 4);
static_assert_decl(sizeof(f64) == 8);
static_assert_decl(sizeof(f32_ieee754) == 4);
static_assert_decl(sizeof(f64_ieee754) == 8);
static_assert_decl(sizeof(f80_ieee754) == 10);
