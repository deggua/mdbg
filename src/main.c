#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pdcurses/curses.h>

#include "dbg/dbg.h"

#include "deps/strlib/strlib.h"
#include "deps/zydis/Zydis.h"

#include "common/types.h"
#include "common/macros.h"

#include "tui.h"

typedef enum {
    LAUNCH_DEFAULT,
    LAUNCH_ATTACH,
    LAUNCH_START,
} LaunchMode;

typedef struct {
    String     exe;
    String     args;
    String     workdir;
    long long  pid;
    LaunchMode mode;
} LaunchSettings;

static void PrintUsage(void)
{
    printf(
        "Usage:\n"
        "  Default :: mdbg\n"
        "  Attach  :: mdbg -p PID\n"
        "  Start   :: mdbg executable [-a \"args\"] [-d \"working_dir\"]\n"
        "  Help    :: mdbg -h\n\n");
}

static LaunchSettings ParseArgs(size_t argc, char** argv)
{
    LaunchSettings ret = {
        .exe     = String(""),
        .args    = String(""),
        .workdir = String(""),
        .pid     = 0,
        .mode    = LAUNCH_DEFAULT,
    };

    if (argc == 1) {
        return ret;
    }

    for (size_t ii = 1; ii < argc; ii++) {
        String arg = String(argv[ii]);

        if (String_Equal(arg, str("-h"))) {
            PrintUsage();
            exit(0);

        } else if (String_Equal(arg, str("-p"))) {
            if (ii + 1 >= argc) {
                printf("Error: -p flag requires a subsequent PID\n");
                PrintUsage();
                exit(1);
            }

            ret.pid = atoll(argv[ii + 1]);
            if (ret.pid == 0) {
                printf("Error: Invalid PID = %s", argv[ii + 1]);
                exit(1);
            }
            ret.mode = LAUNCH_ATTACH;
            ii += 1;

        } else if (String_Equal(arg, str("-a"))) {
            if (ii + 1 >= argc) {
                printf("Error: -a flag requires subsequent arguments\n");
                PrintUsage();
                exit(1);
            }

            String_Delete(ret.args);
            ret.args = String(argv[ii + 1]);
            ii += 1;

        } else if (String_Equal(arg, str("-d"))) {
            if (ii + 1 >= argc) {
                printf("Error: -d flag requires a subsequent directory\n");
                PrintUsage();
                exit(1);
            }

            String_Delete(ret.workdir);
            ret.workdir = String(argv[ii + 1]);
            ii += 1;

        } else {
            // must be the executable
            String_Delete(ret.exe);
            ret.exe  = String(argv[ii]);
            ret.mode = LAUNCH_START;
        }

        String_Delete(arg);
    }

    return ret;
}

static void TUI_PrintRegisters(TUI_Window* window, DBG_Thread* thread)
{
    WINDOW* wind = window->content;
    werase(wind);
    mvwprintw(
        wind,
        0,
        0,
        "%-3s = %016llX\n\n",
        DBG_Register_Name(REG_RIP),
        DBG_Thread_ReadRegister(thread, REG_RIP).U64.rw_val);

#if 0
    int  max_line_len = getmaxx(wind);
    int  cur_line_len = 0;
#endif
    char buf[128] = {0};

    for (int ii = REG_RAX; ii <= REG_RSP; ii++) {
        int chars_out = snprintf(
            buf,
            sizeof(buf),
            "%-3s = %016llX  ",
            DBG_Register_Name(ii),
            DBG_Thread_ReadRegister(thread, ii).U64.rw_val);

        waddstr(wind, buf);
        // cur_line_len += chars_out;

        chars_out = snprintf(
            buf,
            sizeof(buf),
            "%-3s = %016llX  ",
            DBG_Register_Name(ii + 8),
            DBG_Thread_ReadRegister(thread, ii + 8).U64.rw_val);

        waddstr(wind, buf);
        waddstr(wind, "\n");
    }

    DBG_RegisterValue rv_rflags = DBG_Thread_ReadRegister(thread, REG_RFLAGS);
    u64               rflags    = rv_rflags.U64.rw_val;

    bool flag_cf  = !!(rflags & FLAG_MASK(FLAG_CF));
    bool flag_pf  = !!(rflags & FLAG_MASK(FLAG_PF));
    bool flag_af  = !!(rflags & FLAG_MASK(FLAG_AF));
    bool flag_zf  = !!(rflags & FLAG_MASK(FLAG_ZF));
    bool flag_sf  = !!(rflags & FLAG_MASK(FLAG_SF));
    bool flag_tf  = !!(rflags & FLAG_MASK(FLAG_TF));
    bool flag_if  = !!(rflags & FLAG_MASK(FLAG_IF));
    bool flag_df  = !!(rflags & FLAG_MASK(FLAG_DF));
    bool flag_of  = !!(rflags & FLAG_MASK(FLAG_OF));
    bool flag_any = flag_cf || flag_pf || flag_af || flag_zf || flag_sf || flag_tf || flag_if
                    || flag_df || flag_of;

    snprintf(
        buf,
        sizeof(buf),
        "\nFLAGS = [ %s%s%s%s%s%s%s%s%s%s]",
        flag_cf ? "CF " : "",
        flag_pf ? "PF " : "",
        flag_af ? "AF " : "",
        flag_zf ? "ZF " : "",
        flag_sf ? "SF " : "",
        flag_tf ? "TF " : "",
        flag_if ? "IF " : "",
        flag_df ? "DF " : "",
        flag_of ? "OF " : "",
        flag_any ? "" : " ");
    waddstr(wind, buf);
}

static void TUI_PrintSseRegisters(TUI_Window* window, DBG_Thread* thread)
{
    WINDOW* wind = window->content;
    werase(wind);

    char buf[128] = {0};
    for (int ii = REG_XMM0; ii <= REG_XMM15; ii++) {
        DBG_RegisterValue rv = DBG_Thread_ReadRegister(thread, ii);

        snprintf(
            buf,
            sizeof(buf),
            "%-5s = %016llX%016llX\n",
            DBG_Register_Name(ii),
            rv.U128.rw_val[1],
            rv.U128.rw_val[0]);
        waddstr(wind, buf);
    }
}

static void TUI_PrintAvxRegisters(TUI_Window* window, DBG_Thread* thread)
{
    WINDOW* wind = window->content;
    werase(wind);

    char buf[256] = {0};
    for (int ii = REG_YMM0; ii <= REG_YMM15; ii++) {
        DBG_RegisterValue rv = DBG_Thread_ReadRegister(thread, ii);

        snprintf(
            buf,
            sizeof(buf),
            "%-5s = %016llX%016llX%016llX%016llX\n",
            DBG_Register_Name(ii),
            rv.U256.rw_val[3],
            rv.U256.rw_val[2],
            rv.U256.rw_val[1],
            rv.U256.rw_val[0]);
        waddstr(wind, buf);
    }
}

static void TUI_PrintStack(TUI_Window* window, DBG_Process* proc, DBG_Thread* thread)
{
    WINDOW* wind = window->content;
    werase(wind);

    DBG_RegisterValue rv_sp = DBG_Thread_ReadRegister(thread, REG_RSP);
    DBG_Address       sp    = rv_sp.U64.rw_val;

    char buf[512]  = {0};
    int  max_lines = getmaxy(wind);
    for (int ii = 0; ii < max_lines; ii++) {
        u64 val;
        DBG_Process_ReadMemory(proc, sp + sizeof(u64) * (size_t)ii, &val, sizeof(val));
        snprintf(buf, sizeof(buf), "SP+%-4zX  %016llX\n", sizeof(u64) * (size_t)ii, val);
        waddstr(wind, buf);
    }
}

static void
TUI_PrintDisassembly(TUI_Window* window, DBG_Process* proc, DBG_Thread* thread, bool is_int3)
{
    WINDOW* wind  = window->content;
    int     lines = getmaxy(wind);
    int     cols  = getmaxx(wind);
    u64     r_RIP = DBG_Thread_ReadRegister(thread, REG_RIP).U64.rw_val;

    uint8_t                      instr_mem[16] = {0};
    ZydisDisassembledInstruction instr         = {0};

    // TODO: kind of weird behavior, if we hit int3 then RIP is after it
    // but if we hit a user BP then it's before it
    u64 addr = is_int3 ? r_RIP - 1 : r_RIP;
    for (int ii = 0; ii < lines; ii++) {
        wmove(wind, ii, 0);
        int line_chars = 0;
        if (!DBG_Process_ReadMemory(proc, addr, instr_mem, sizeof(instr_mem))) {
            ABORT("Failed to read process memory");
        }

        ZydisDisassembleIntel(
            ZYDIS_MACHINE_MODE_LONG_64,
            addr,
            instr_mem,
            sizeof(instr_mem),
            &instr);

        char buf[512];
        bool is_color_on  = false;
        int  color_number = 0;

        if (addr == r_RIP) {
            wattron(wind, COLOR_RIP);
            is_color_on  = true;
            color_number = 1;
        } else {
            DBG_Breakpoint* bp = DBG_Process_GetBP(proc, addr);
            if (bp) {
                DBG_BreakpointInfo bp_info = DBG_Process_QueryBP(proc, bp);
                if (bp_info.enabled) {
                    wattron(wind, COLOR_BREAKPOINT);
                    is_color_on  = true;
                    color_number = 2;
                }
            }
        }

        line_chars += snprintf(buf, sizeof(buf), " %016llX ", addr);
        waddstr(wind, buf);

        waddch(wind, ACS_VLINE);
        waddch(wind, ' ');
        line_chars += 2;

        waddstr(wind, instr.text);
        line_chars += strlen(instr.text);

        if (line_chars < cols) {
            int jj;
            for (jj = 0; jj < cols - line_chars; jj++) {
                buf[jj] = ' ';
            }
            buf[jj] = '\0';
            waddstr(wind, buf);
        }

        if (is_color_on) {
            wattroff(wind, COLOR_PAIR(color_number));
        }

        addr += instr.info.length;
    }
}

struct {
    DBG_Process* proc;
    DBG_Event    e;
} DBG;

struct {
    TUI_Window* c_root;

    TUI_Window* c_regs;
    TUI_Window* gpr;
    TUI_Window* sse;
    TUI_Window* avx;

    TUI_Window* disas;

    TUI_Window* c_cmd_stack;
    TUI_Window* cmds;
    TUI_Window* stack;
} TUI;

static void BuildTui(void)
{
    TUI_Initialize();
    TUI_SetTerminalTitle("dbg");
    TUI.c_root = TUI_Window_New(NULL, str("Root"), TUI_Split_Vertical, false);

    TUI.c_regs = TUI_Window_New(TUI.c_root, str(""), TUI_Split_Horizontal, false);
    TUI.gpr    = TUI_Window_New(TUI.c_regs, str("Registers"), 0, true);
    TUI.sse    = TUI_Window_New(TUI.c_regs, str("SSE"), 0, true);
    TUI.avx    = TUI_Window_New(TUI.c_regs, str("AVX"), 0, true);

    TUI.disas = TUI_Window_New(TUI.c_root, str("Disassembly"), 0, true);

    TUI.c_cmd_stack = TUI_Window_New(TUI.c_root, str(""), TUI_Split_Horizontal, false);
    TUI.cmds        = TUI_Window_New(TUI.c_cmd_stack, str("Commands"), 0, true);
    TUI.stack       = TUI_Window_New(TUI.c_cmd_stack, str("Stack"), 0, true);

    TUI_Window_Build(TUI.c_root);
}

typedef enum {
    DumpMemory_BYTE  = 'b',
    DumpMemory_WORD  = 'w',
    DumpMemory_DWORD = 'd',
    DumpMemory_QWORD = 'q',
} DumpMemory_ElementSize;

typedef enum {
    DumpMemory_SIGNED   = 'd',
    DumpMemory_UNSIGNED = 'u',
    DumpMemory_HEX      = 'x',
    DumpMemory_FLOAT    = 'f',
} DumpMemory_Format;

static size_t ElementSizeToBytes(DumpMemory_ElementSize esize)
{
    switch (esize) {
        case DumpMemory_BYTE: {
            return sizeof(u8);
        } break;

        case DumpMemory_WORD: {
            return sizeof(u16);
        } break;

        case DumpMemory_DWORD: {
            return sizeof(u32);
        } break;

        case DumpMemory_QWORD: {
            return sizeof(u64);
        } break;

        default:
            return (size_t)-1;
    }
}

static String DumpMemory(
    DBG_Process*           proc,
    size_t                 count,
    DumpMemory_Format      format,
    DumpMemory_ElementSize size,
    DBG_Address            addr)
{
    size_t esize = ElementSizeToBytes(size);
    if (esize == (size_t)-1) {
        goto error_BadSize;
    }

    // TODO: Needs to use StringBuilder or something similar for efficiency
    String cur = String("");
    for (size_t ii = 0; ii < count; ii++) {
        if (ii > 0 && ii % 8 == 0) {
            String tmp = String_Join(cur, str("\n"));
            String_Delete(cur);
            cur = tmp;
        }

        String next;
        switch (size) {
            case DumpMemory_BYTE: {
                u8 mem;
                if (!DBG_Process_ReadMemory(proc, addr + esize * ii, &mem, sizeof(mem))) {
                    goto error_ReadMemory;
                }

                switch (format) {
                    case DumpMemory_SIGNED: {
                        next = String_CFormat("%lld ", (long long)mem);
                    } break;

                    case DumpMemory_UNSIGNED: {
                        next = String_CFormat("%llu ", (unsigned long long)mem);
                    } break;

                    case DumpMemory_HEX: {
                        next = String_CFormat("%02llX ", (unsigned long long)mem);
                    } break;

                    default: {
                        goto error_BadFormat;
                    } break;
                }
            } break;

            case DumpMemory_WORD: {
                u16 mem;
                if (!DBG_Process_ReadMemory(proc, addr + esize * ii, &mem, sizeof(mem))) {
                    goto error_ReadMemory;
                }

                switch (format) {
                    case DumpMemory_SIGNED: {
                        next = String_CFormat("%lld ", (long long)mem);
                    } break;

                    case DumpMemory_UNSIGNED: {
                        next = String_CFormat("%llu ", (unsigned long long)mem);
                    } break;

                    case DumpMemory_HEX: {
                        next = String_CFormat("%04llX ", (unsigned long long)mem);
                    } break;

                    default: {
                        goto error_BadFormat;
                    } break;
                }
            } break;

            case DumpMemory_DWORD: {
                u32 mem;
                if (!DBG_Process_ReadMemory(proc, addr + esize * ii, &mem, sizeof(mem))) {
                    goto error_ReadMemory;
                }

                switch (format) {
                    case DumpMemory_SIGNED: {
                        next = String_CFormat("%lld ", (long long)mem);
                    } break;

                    case DumpMemory_UNSIGNED: {
                        next = String_CFormat("%llu ", (unsigned long long)mem);
                    } break;

                    case DumpMemory_HEX: {
                        next = String_CFormat("%08llX ", (unsigned long long)mem);
                    } break;

                    case DumpMemory_FLOAT: {
                        f32_ieee754 mem_conv = {.u32 = mem};

                        next = String_CFormat("%0.4f ", mem_conv.f32);
                    } break;

                    default: {
                        goto error_BadFormat;
                    } break;
                }
            } break;

            case DumpMemory_QWORD: {
                u64 mem;
                if (!DBG_Process_ReadMemory(proc, addr + esize * ii, &mem, sizeof(mem))) {
                    goto error_ReadMemory;
                }

                switch (format) {
                    case DumpMemory_SIGNED: {
                        next = String_CFormat("%lld ", (long long)mem);
                    } break;

                    case DumpMemory_UNSIGNED: {
                        next = String_CFormat("%llu ", (unsigned long long)mem);
                    } break;

                    case DumpMemory_HEX: {
                        next = String_CFormat("%016llX ", (unsigned long long)mem);
                    } break;

                    case DumpMemory_FLOAT: {
                        f64_ieee754 mem_conv = {.u64 = mem};

                        next = String_CFormat("%0.8f ", mem_conv.f64);
                    } break;

                    default: {
                        goto error_BadFormat;
                    } break;
                }
            } break;
        }

        String tmp = String_Join(cur, next);
        String_Delete(cur);
        String_Delete(next);
        cur = tmp;
    }

    String final = String_Join(cur, str("\n"));
    String_Delete(cur);
    return final;

error_BadFormat:
error_ReadMemory:
    String_Delete(cur);
error_BadSize:
    return String("");
}

static void RefreshTui(const DBG_Event* e)
{
    DBG_Thread_GetContext(e->thread);

    TUI_Window_Refresh(TUI.c_root);

    TUI_PrintRegisters(TUI.gpr, e->thread);
    TUI_Window_Refresh(TUI.gpr);

    TUI_PrintSseRegisters(TUI.sse, e->thread);
    TUI_Window_Refresh(TUI.sse);

    TUI_PrintAvxRegisters(TUI.avx, e->thread);
    TUI_Window_Refresh(TUI.avx);

    TUI_PrintStack(TUI.stack, e->process, e->thread);
    TUI_Window_Refresh(TUI.stack);

    bool hit_int3 = (e->type == DBG_EventType_Breakpoint && e->event_breakpoint.bp == NULL);
    TUI_PrintDisassembly(TUI.disas, e->process, e->thread, hit_int3);
    TUI_Window_Refresh(TUI.disas);
}

static bool GetCommand(char* buf, size_t len)
{
    size_t pos = 0;

    wattroff(TUI.cmds->content, COLOR_CMD_OUTPUT);
    wattron(TUI.cmds->content, COLOR_CMD_INPUT);
    waddstr(TUI.cmds->content, "> ");
    TUI_Window_Refresh(TUI.cmds);

    while (true) {
        int input = wgetch(TUI.cmds->content);

        bool is_enter     = (input == '\r');
        bool is_text      = (0x20 <= input && input < 0x7F); // printable ascii char
        bool is_buf_full  = (pos == len);
        bool is_buf_empty = (pos == 0);
        bool is_backspace
            = (input == KEY_BACKSPACE || input == KEY_DC || input == 0x7F || input == '\b');
        bool is_ctrl_c = (input == 0x3); // TODO: probably not portable
        // bool is_resized = (input == KEY_RESIZE); // TODO: doesn't work
        // TODO: need to handle arrow keys

        if (is_enter) {
            buf[pos] = '\0';
            waddch(TUI.cmds->content, '\n');
            wattroff(TUI.cmds->content, COLOR_CMD_INPUT);
            wattron(TUI.cmds->content, COLOR_CMD_OUTPUT);
            return true;

        } else if (is_ctrl_c) {
            waddch(TUI.cmds->content, '\n');
            return false;

        } else if (is_backspace && !is_buf_empty) {
            pos -= 1;
            int cur_x = getcurx(TUI.cmds->content);
            int cur_y = getcury(TUI.cmds->content);

            int new_x, new_y;
            if (cur_x > 0) {
                new_x = cur_x - 1;
                new_y = cur_y;
            } else {
                new_x = getmaxx(TUI.cmds->content) - 1;
                new_y = cur_y - 1;
            }
            mvwdelch(TUI.cmds->content, new_y, new_x);

        } else if (is_text && !is_buf_full) {
            buf[pos++] = (char)input;
            waddch(TUI.cmds->content, input);
            TUI_Window_Refresh(TUI.cmds);
        }
    }
}

typedef enum {
    CommandStatus_SUCCESS,
    CommandStatus_FAILURE,
    CommandStatus_EXIT,
} CommandStatus;

typedef struct {
    String        output;
    CommandStatus status;
} CommandResult;

static CommandResult Command_Quit(const String cmd)
{
    (void)cmd;

    return (CommandResult){
        .output = String(""),
        .status = CommandStatus_EXIT,
    };
}

static CommandResult Command_Continue(const String cmd)
{
    (void)cmd;

    DBG_Process_DebugContinue(&DBG.e);
    DBG.e = DBG_Process_DebugWait(DBG.proc);

    return (CommandResult){
        .output = String(""),
        .status = CommandStatus_SUCCESS,
    };
}

static CommandResult Command_SetBreakpoint(const String cmd)
{
    String      bp_addr_str = String_Slice(cmd, str("b ").len, cmd.len);
    DBG_Address bp_addr     = strtoull(cstr(bp_addr_str), NULL, 16);
    String_Delete(bp_addr_str);

    if (!DBG_Process_SetBP(DBG.proc, bp_addr)) {
        return (CommandResult){
            .output = String_CFormat("Failed to set breakpoint at %016llX\n", bp_addr),
            .status = CommandStatus_FAILURE,
        };
    }

    return (CommandResult){
        .output = String(""),
        .status = CommandStatus_SUCCESS,
    };
}

static CommandResult Command_DeleteBreakpoint(const String cmd)
{
    String      bp_addr_str = String_Slice(cmd, str("del ").len, cmd.len);
    DBG_Address bp_addr     = strtoull(cstr(bp_addr_str), NULL, 16);
    String_Delete(bp_addr_str);

    DBG_Breakpoint* del_bp = DBG_Process_GetBP(DBG.proc, bp_addr);
    if (!del_bp) {
        return (CommandResult){
            .output = String_CFormat("No breakpoint at %016llX\n", bp_addr),
            .status = CommandStatus_FAILURE,
        };
    }

    ASSERT(DBG_Process_DeleteBP(DBG.proc, del_bp));
    return (CommandResult){
        .output = String(""),
        .status = CommandStatus_SUCCESS,
    };
}

static CommandResult Command_ExamineMemory(const String cmd)
{
    size_t      count = 16;
    char        size  = DumpMemory_BYTE;
    char        fmt   = DumpMemory_HEX;
    DBG_Address addr  = 0;

    int matched, matched_expected;
    if (String_StartsWith(cmd, str("x/"))) {
        matched          = String_CScan(cmd, "x/%zu%c%c %llx", &count, &fmt, &size, &addr);
        matched_expected = 4;

    } else {
        matched          = String_CScan(cmd, "x %llx", &addr);
        matched_expected = 1;
    }

    if (matched != matched_expected) {
        return (CommandResult){
            .output = String("Missing arguments, valid forms:\n"
                             "  x addr_hex\n"
                             "  x/Nft addr_hex\n"),
            .status = CommandStatus_FAILURE,
        };
    }

    String output = DumpMemory(DBG.proc, count, fmt, size, addr);
    if (output.len == 0) {
        return (CommandResult){
            .output
            = String("Bad argument(s):\n"
                     "  addr = valid address    (in hex)\n"
                     "  N    = unsigned integer (in decimal)\n"
                     "  f    = format specifier (d = signed, u = unsigned, x = hex, f = float)\n"
                     "  t    = type specifier   (b = u8, w = u16, d = u32, q = u64)\n"),
            .status = CommandStatus_FAILURE,
        };
    }

    return (CommandResult){
        .output = output,
        .status = CommandStatus_SUCCESS,
    };
}

static CommandResult Command_Clear(const String cmd)
{
    (void)cmd;

    werase(TUI.cmds->content);
    return (CommandResult){
        .output = String(""),
        .status = CommandStatus_SUCCESS,
    };
}

typedef enum {
    CommandMatch_PREFIX,
    CommandMatch_EXACT,
} CommandMatch;

static CommandResult RunCommand(const String cmd)
{
    static struct {
        CommandMatch match;
        const String expr;
        CommandResult (*handler)(const String cmd);
    } cmd_table[] = {
        { CommandMatch_EXACT,     str("q"),             Command_Quit},
        { CommandMatch_EXACT,     str("c"),         Command_Continue},
        { CommandMatch_EXACT, str("clear"),            Command_Clear},
        {CommandMatch_PREFIX,    str("b "),    Command_SetBreakpoint},
        {CommandMatch_PREFIX,  str("del "), Command_DeleteBreakpoint},
        {CommandMatch_PREFIX,     str("x"),    Command_ExamineMemory},
    };

    for (size_t ii = 0; ii < lengthof(cmd_table); ii++) {
        switch (cmd_table[ii].match) {
            case CommandMatch_EXACT: {
                if (String_Equal(cmd, cmd_table[ii].expr)) {
                    return cmd_table[ii].handler(cmd);
                }
            } break;

            case CommandMatch_PREFIX: {
                if (String_StartsWith(cmd, cmd_table[ii].expr)) {
                    return cmd_table[ii].handler(cmd);
                }
            } break;
        }
    }

    return (CommandResult){
        .output = String("Unknown command\n"),
        .status = CommandStatus_FAILURE,
    };
}

static void LaunchTui(DBG_Process* proc)
{
    BuildTui();

    DBG.proc = proc;
    DBG.e    = DBG_Process_DebugWait(proc);

    scrollok(TUI.cmds->content, true);
    RefreshTui(&DBG.e);

    String prev_cmd = String("");
    while (true) {
        char buf[256] = {0};
        bool exec     = GetCommand(buf, sizeof(buf));
        if (!exec) {
            continue;
        }

        String cmd = String(buf);

        CommandResult result;
        if (String_Equal(cmd, str(""))) {
            String_Delete(cmd);
            cmd = prev_cmd;
        } else {
            String_Delete(prev_cmd);
            prev_cmd = cmd;
        }

        result = RunCommand(cmd);
        switch (result.status) {
            case CommandStatus_FAILURE:
            case CommandStatus_SUCCESS: {
                if (result.output.len > 0) {
                    waddstr(TUI.cmds->content, cstr(result.output));
                    waddch(TUI.cmds->content, '\n');
                }
                String_Delete(result.output);
            } break;

            case CommandStatus_EXIT: {
                String_Delete(result.output);
                return;
            } break;
        }

        RefreshTui(&DBG.e);
    }
}

int main(int argc, char** argv)
{
    DBG_Process* proc = NULL;

    LaunchSettings settings = ParseArgs((size_t)argc, argv);
    switch (settings.mode) {
        case LAUNCH_ATTACH: {
            proc = DBG_Process_AttachPID(settings.pid);
            if (proc == NULL) {
                ABORT("Failed to attach to process with PID = %lld", settings.pid);
            }
        } break;

        case LAUNCH_START: {
            proc = DBG_Process_AttachNew(
                cstr(settings.exe),
                cstr(settings.args),
                cstr(settings.workdir));
            if (proc == NULL) {
                // clang-format off
                ABORT(
                    "Failed to create and attach to process:\n"
                    "    Exe: " STRING_FMT "\n"
                    "   Args: " STRING_FMT "\n"
                    "Workdir: " STRING_FMT "\n",
                    STRING_ARG(settings.exe),
                    STRING_ARG(settings.args),
                    STRING_ARG(settings.workdir));
                // clang-format on
            }
        } break;

        default:
            break; // nop
    }

    LaunchTui(proc);

    return EXIT_SUCCESS;
}
