#include <string.h>

#include "common/macros.h"
#include "common/types.h"

#include "dbg/dbg.h"

static const char* REGISTER_NAMES[] = {
#define X(_name, ...) [REG_##_name] = #_name,
#include "regs/all.inc"
#undef X
};

static const DBG_RegisterType REGISTER_TYPES[] = {
#define X(_name, _width, _type) [REG_##_name] = DBG_RegisterType_##_type##_width,
#include "regs/all.inc"
#undef X
};

const char* DBG_Register_Name(DBG_Register reg)
{
    if (reg < 0 || (size_t)reg >= lengthof(REGISTER_NAMES)) {
        return NULL;
    }

    return REGISTER_NAMES[reg];
}

// TODO: should probably use a hash table
DBG_Register DBG_Register_FromName(const char* name)
{
    for (size_t ii = 0; ii < lengthof(REGISTER_NAMES); ii++) {
        if (REGISTER_NAMES[ii] == NULL) {
            continue;
        }

        if (!strcmp(name, REGISTER_NAMES[ii])) {
            return ii;
        }
    }

    return REG_INVALID;
}

DBG_RegisterType DBG_Register_Type(DBG_Register reg)
{
    if (reg < 0 || (size_t)reg >= lengthof(REGISTER_TYPES)) {
        return DBG_RegisterType_NULL;
    }

    return REGISTER_TYPES[reg];
}
