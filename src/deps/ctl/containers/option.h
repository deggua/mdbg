#include "../common/ctl.h"

#if !defined(CTL_OPTION_INCLUDED)
#    define CTL_OPTION_INCLUDED

#    define Option(T) CONCAT(Option, T)
#endif

#if !defined(Option_Type)
#    error "Option requires a type specialization"
#endif

#if !defined(Option_Type_Alias)
#    define Option_Type_Alias Option_Type
#endif

#define T  Option_Type
#define T_ Option_Type_Alias

#include <stdbool.h>

typedef struct Option(T_) {
    T    it;
    bool is;
}
Option(T_);

#undef T
#undef T_

#undef Option_Type_Alias
#undef Option_Type
