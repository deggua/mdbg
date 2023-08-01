#pragma once

#include <assert.h>
#include <stdalign.h>
#include <stdio.h>
#include <stdlib.h>

#define static_assert_decl(const_expr) static_assert((const_expr), "Assertion false: " #const_expr)
#define static_assert_expr(const_expr) (0 * sizeof(struct { static_assert_decl(const_expr); }))

#define same_type(a, b) (__builtin_types_compatible_p(__typeof__(a), __typeof__(b)))
#define is_array(a)     (static_assert_expr(!same_type((a), &(a)[0])))

#define containerof(ptr, type, member) ((type*)((char*)ptr - offsetof(type, member)))
#define lengthof(arr)                  (is_array(arr), sizeof(arr) / sizeof((arr)[0]))
#define likely(x)                      (__builtin_expect(!!(x), 1))
#define unlikely(x)                    (__builtin_expect(!!(x), 0))

#define OPTIMIZE_UNREACHABLE __builtin_unreachable()
#define OPTIMIZE_ASSUME(expr)     \
    do {                          \
        if (!(expr))              \
            OPTIMIZE_UNREACHABLE; \
    } while (0)

// TODO: could use __builtin_trap()
#if !defined(NDEBUG)
#    define BP_EXIT()             \
        do {                      \
            asm volatile("int3"); \
            exit(EXIT_FAILURE);   \
        } while (0)
#else
#    define BP_EXIT() exit(EXIT_FAILURE)
#endif

// TODO: check what this does in GDB, if it doesn't trigger a breakpoint at the abort call, use int3
// or equiv
#define ABORT(msg, ...)               \
    do {                              \
        fprintf(                      \
            stderr,                   \
            "Aborted in %s @ %s:%d\n" \
            "Reason: " msg "\n\n",    \
            __func__,                 \
            __FILE__,                 \
            __LINE__,                 \
            ##__VA_ARGS__);           \
        BP_EXIT();                    \
    } while (0)

// TODO: overload, 2+ args provides msg
#define ASSERT(cond)                               \
    do {                                           \
        if (!(cond)) {                             \
            fprintf(                               \
                stderr,                            \
                "Assertion failed in %s @ %s:%d\n" \
                "Condition: %s\n\n",               \
                __func__,                          \
                __FILE__,                          \
                __LINE__,                          \
                #cond);                            \
            BP_EXIT();                             \
        }                                          \
    } while (0)

#define ANSI_START "\x1B["
#define ANSI_END   "m"

#define ANSI_FG_RED     ";31"
#define ANSI_FG_YELLOW  ";33"
#define ANSI_FG_BLUE    ";34"
#define ANSI_FG_MAGENTA ";35"

#define ANSI_BOLD  "1"
#define ANSI_FAINT "2"
#define ANSI_BLINK "5"

#define ANSI_RESET_ALL   "\x1B[0m"
#define ANSI(style, str) ANSI_START style ANSI_END str ANSI_RESET_ALL

#define LOCATION_STYLE ANSI_FAINT
#define ERROR_STYLE    ANSI_BOLD ANSI_FG_RED
#define WARNING_STYLE  ANSI_BOLD ANSI_FG_YELLOW
#define INFO_STYLE     ANSI_BOLD ANSI_FG_BLUE
#define DEBUG_STYLE    ANSI_BOLD ANSI_FG_MAGENTA

// TODO: ability to log to file
#if ENABLE_LOGGING
#    if 0
#        define _LOG_INTERNAL(prefix, msg, ...)                               \
            fprintf(                                                          \
                stdout,                                                       \
                prefix ANSI(LOCATION_STYLE, " [%s:%d in '%s'] :: ") msg "\n", \
                __FILE__,                                                     \
                __LINE__,                                                     \
                __PRETTY_FUNCTION__,                                          \
                ##__VA_ARGS__)
#    else
#        define _LOG_INTERNAL(prefix, msg, ...)                         \
            fprintf(                                                    \
                stdout,                                                 \
                prefix ANSI(LOCATION_STYLE, "| %20s:%-4d | ") msg "\n", \
                __FILE__,                                               \
                __LINE__,                                               \
                ##__VA_ARGS__)
#    endif
#else
#    define _LOG_INTERNAL(prefix, msg, ...)
#endif

#define LOG_ERROR(msg, ...)   _LOG_INTERNAL(ANSI(ERROR_STYLE, " ERROR "), msg, ##__VA_ARGS__)
#define LOG_WARNING(msg, ...) _LOG_INTERNAL(ANSI(WARNING_STYLE, "  WARN "), msg, ##__VA_ARGS__)
#define LOG_INFO(msg, ...)    _LOG_INTERNAL(ANSI(INFO_STYLE, "  INFO "), msg, ##__VA_ARGS__)
#define LOG_DEBUG(msg, ...)   _LOG_INTERNAL(ANSI(DEBUG_STYLE, " DEBUG "), msg, ##__VA_ARGS__)
