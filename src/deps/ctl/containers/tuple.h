/* --- Templated Tuple Type --- */

/*
    Usage:

    Tuple_Types: Comma delimited list of the types in the tuple
        Ex: #define Tuple_Types int, float, char*

    Tuple_Types_Aliases: Comma delimited list of the type aliases to use for the tuple
        Ex: #define Tuple_Types_Aliases int, float, str
*/

#include "../common/pp_magic.h"

#if !defined(CTL_TUPLE_INCLUDED)
#    define CTL_TUPLE_INCLUDED

#    define Tuple(...) CONCAT(Tuple, __VA_ARGS__)
#endif

#if !defined(Tuple_Types)
#    error "Tuple requires a type-list for type specialization"
#endif

#if !defined(Tuple_Types_Aliases)
#    define Tuple_Types_Aliases Tuple_Types
#endif

#define Tuple_Members               e1, e2, e3, e4, e5, e6, e7, e8, e9, e10
#define Tuple_MemberList            (Tuple_Members)
#define Tuple_GenMember(type, name) type name;
#define Tuple_GenMembers(...)       EVAL(MAP_WITH_ID_LIST(Tuple_GenMember, EMPTY, Tuple_MemberList, __VA_ARGS__))

/* clang-format off */

typedef struct Tuple(Tuple_Types_Aliases){
    Tuple_GenMembers(Tuple_Types)
} Tuple(Tuple_Types_Aliases);

/* clang-format on */

#undef Tuple_Types
#undef Tuple_Types_Aliases

#undef Tuple_Members
#undef Tuple_MemberList
#undef Tuple_GenMember
#undef Tuple_GenMembers
