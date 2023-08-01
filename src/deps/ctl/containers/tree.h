#include <stdbool.h>
#include <stddef.h>

#include "../common/ctl.h"

#if !defined(CTL_TREE_INCLUDED)
#    define CTL_TREE_INCLUDED

#    define TreeNode(T, N) CONCAT(TreeNode, T, N)
#    define Tree_New(T, N) CONCAT(Tree_New, T, N)

/* --------- END PUBLIC API ---------- */
#endif

#if !defined(Tree_Type)
#    error "Tree requires a type specialization"
#endif

#if !defined(Tree_Type_Alias)
#    define Tree_Type_Alias Tree_Type
#endif

#if !defined(Tree_Children)
#    error "Tree requires a children specialization"
#endif

#if !defined(Tree_Malloc)
#    if !defined(CTL_DEFAULT_ALLOCATOR)
#        define CTL_DEFAULT_ALLOCATOR
#    endif

#    define Tree_Malloc(bytes) calloc(1, bytes)
#endif

#if !defined(Tree_Realloc)
#    if !defined(CTL_DEFAULT_ALLOCATOR)
#        warning "Non-default malloc used with default realloc"
#    endif

#    define Tree_Realloc realloc
#endif

#if !defined(Tree_Free)
#    if !defined(CTL_DEFAULT_ALLOCATOR)
#        warning "Non-default malloc used with default free"
#    endif

#    define Tree_Free free
#endif

#if defined(CTL_DEFAULT_ALLOCATOR)
#    include <stdlib.h>
#endif

#define T  Tree_Type
#define T_ Tree_Type_Alias
#define N  Tree_Children

typedef struct TreeNode(T_, N) {
    struct TreeNode(T_, N) * parent;
    struct TreeNode(T_, N) * child[N];
    T val;
}
TreeNode(T_, N);

// functions

TreeNode(T_, N) * Tree_New(T_, N)(void) {
    TreeNode(T, N)* node = Tree_Malloc(sizeof(TreeNode(T_, N)));
    return node;
}

CTL_OVERLOADABLE
static inline void Tree_DeleteNode(TreeNode(T_, N) * node) {
    Tree_Free(node);
}

void Tree_DeleteTree(TreeNode(T_, N) * root) {
    for (size_t ii = 0; ii < N; ++ii) {
        Tree_DeleteNode(root->child[ii]);
    }
    Tree_DeleteNode(root);
}

ssize_t Tree_AddChild(TreeNode(T_, N) * parent, TreeNode(T_, N) * child) {
    for (size_t ii = 0; ii < N; ++ii) {
        if (parent->child[ii] == NULL) {
            parent->child[ii] = child;
            return ii;
        }
    }

    return -1;
}

ssize_t Tree_RemoveChild(TreeNode(T_, N) * parent, TreeNode(T_, N) * child) {
    for (size_t ii = 0; ii < N; ++ii) {
        if (parent->child[ii] == child) {
            parent->child[ii] = NULL;
            return ii;
        }
    }

    return -1;
}

// cleanup macros
#undef T
#undef T_
#undef N

#undef CTL_DEFAULT_ALLOCATOR

#undef Tree_Type
#undef Tree_Type_Alias
#undef Tree_Children

#undef Tree_Malloc
#undef Tree_Realloc
#undef Tree_Free
