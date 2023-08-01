#include <windows.h>
#include <pdcurses/curses.h>

#include "tui.h"

#include "common/types.h"
#include "common/macros.h"
#include "deps/strlib/strlib.h"

// NOTE: Required to be called before using any TUI_* functions
void TUI_Initialize(void)
{
    initscr();
    raw();
    noecho();
    keypad(stdscr, TRUE);
    refresh();
    start_color();

    init_pair(COLOR_BREAKPOINT_NUM, COLOR_BLACK, COLOR_RED);
    init_pair(COLOR_RIP_NUM, COLOR_BLACK, COLOR_WHITE);
    init_pair(COLOR_CMD_NUM, COLOR_WHITE, COLOR_BLACK);
}

void TUI_SetTerminalTitle(const char* str)
{
    SetConsoleTitle(str);
}

// NOTE: doesn't create ncurses structures
TUI_Window* TUI_Window_New(TUI_Window* parent, const String title, TUI_Split split, bool border)
{
    TUI_Window* ret = malloc(sizeof(*ret));
    if (ret == NULL) {
        ABORT("Failed to allocate memory for window");
    }

    if (!Vector_Init(&ret->children, 4)) {
        ABORT("Failed to allocate memory for window's children container");
    }

    ret->title      = String_Copy(title);
    ret->parent     = parent;
    ret->split      = split;
    ret->has_border = border;

    ret->border  = NULL;
    ret->content = NULL;

    if (parent == NULL) {
        return ret;
    }

    if (!Vector_Push(&parent->children, ret)) {
        ABORT("Failed to add child window to parent");
    }

    return ret;
}

// NOTE: doesn't free ncurses structures
void TUI_Window_Delete(TUI_Window* wind)
{
    if (wind->parent != NULL) {
        TUI_Window* parent = wind->parent;
        for (size_t ii = 0; ii < parent->children.length; ii++) {
            if (parent->children.at[ii] == wind) {
                Vector_Remove(&parent->children, ii);
                break;
            }
        }
    }

    wind->parent = NULL;
    for (size_t ii = 0; ii < wind->children.length; ii++) {
        TUI_Window_Delete(wind->children.at[ii]);
    }

    Vector_Uninit(&wind->children);

    String_Delete(wind->title);
}

// Given a root window, construct the ncurses windows required to implement said hierarchy
void TUI_Window_Construct(TUI_Window* root, int index, int total, TUI_Split parent_split)
{
    WINDOW* parent;
    if (root->parent == NULL) {
        parent = stdscr;
    } else {
        parent = root->parent->content;
    }

    int max_width, max_height;
    max_width  = getmaxx(parent);
    max_height = getmaxy(parent);

    int width, height;
    int horiz_scale, vert_scale;
    if (parent_split == TUI_Split_Horizontal) {
        height = max_height / total;
        width  = max_width;

        horiz_scale = 0;
        vert_scale  = height;

        bool is_last = index == total - 1;
        if (is_last) {
            height = max_height - vert_scale * index;
        }
    } else {
        height = max_height;
        width  = max_width / total;

        horiz_scale = width;
        vert_scale  = 0;

        bool is_last = index == total - 1;
        if (is_last) {
            width = max_width - horiz_scale * index;
        }
    }

    if (root->has_border) {
        root->border = derwin(parent, height, width, vert_scale * index, horiz_scale * index);

        box(root->border, 0, 0);
        mvwprintw(root->border, 0, 2, cstr(root->title));

        touchwin(parent);
        wrefresh(root->border);

        root->content = derwin(root->border, height - 2, width - 2, 1, 1);
        touchwin(root->border);
        wrefresh(root->content);
    } else {
        root->content = derwin(parent, height, width, vert_scale * index, horiz_scale * index);
        touchwin(parent);
        wrefresh(root->content);
    }

    for (size_t ii = 0; ii < root->children.length; ii++) {
        TUI_Window_Construct(
            root->children.at[ii],
            (int)ii,
            (int)root->children.length,
            root->split);
    }
}

void TUI_Window_Build(TUI_Window* root)
{
    TUI_Window_Construct(root, 0, 1, TUI_Split_Horizontal);
}

// Given a root window, destroy their ncurses windows
// NOTE: After calling this changes to the TUI_Window's properties do not affect their render, to
// alter a property it is necessary to destroy and construct the hierarchy
// TODO: This is inefficient if window properties need to change on the fly
void TUI_Window_Destruct(TUI_Window* root) {}

void TUI_Window_SetSplit(TUI_Window* wind, TUI_Split split)
{
    wind->split = split;
}

void TUI_Window_Refresh(TUI_Window* wind)
{
    if (wind->has_border) {
        touchwin(wind->border);
    } else if (wind->parent == NULL) {
        touchwin(stdscr);
    } else {
        touchwin(wind->parent->content);
    }

    wrefresh(wind->content);

    for (size_t ii = 0; ii < wind->children.length; ii++) {
        TUI_Window_Refresh(wind->children.at[ii]);
    }
}

int TUI_Window_GetLines(TUI_Window* wind)
{
    return getmaxy(wind->content);
}
