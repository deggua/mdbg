#pragma once

#include <pdcurses/curses.h>

#include "common/types.h"
#include "deps/strlib/strlib.h"

typedef struct TUI_Window TUI_Window;
#define Vector_Type       TUI_Window*
#define Vector_Type_Alias TUI_WindowPtr
#include "deps/ctl/containers/vector.h"

#define COLOR_RIP_NUM        1
#define COLOR_BREAKPOINT_NUM 2
#define COLOR_CMD_NUM        3

#define COLOR_RIP        COLOR_PAIR(COLOR_RIP_NUM)
#define COLOR_BREAKPOINT COLOR_PAIR(COLOR_BREAKPOINT_NUM)
#define COLOR_CMD_INPUT  (COLOR_PAIR(COLOR_CMD_NUM) | A_BOLD)
#define COLOR_CMD_OUTPUT (COLOR_PAIR(COLOR_CMD_NUM) | A_DIM)

typedef enum {
    TUI_Split_Vertical,
    TUI_Split_Horizontal,
} TUI_Split;

typedef struct TUI_Window {
    String                title;      // title of the window
    Vector(TUI_WindowPtr) children;   // child window(s)
    TUI_Window*           parent;     // parent window
    WINDOW*               border;     // ncurses border window
    WINDOW*               content;    // ncurses content window
    TUI_Split             split;      // inner split orientation
    bool                  has_border; // whether the window has a border
} TUI_Window;

void        TUI_Initialize(void);
void        TUI_SetTerminalTitle(const char* str);
TUI_Window* TUI_Window_New(TUI_Window* parent, const String title, TUI_Split split, bool border);
void        TUI_Window_Delete(TUI_Window* wind);
void        TUI_Window_Construct(TUI_Window* root, int index, int total, TUI_Split parent_split);
void        TUI_Window_Build(TUI_Window* root);
void        TUI_Window_Destruct(TUI_Window* root);
void        TUI_Window_SetSplit(TUI_Window* wind, TUI_Split split);
void        TUI_Window_Refresh(TUI_Window* wind);
int         TUI_Window_GetLines(TUI_Window* wind);
