#pragma once

#include "dbg.h"

static inline DBG_RegisterValue DBG_RV_NULL(void)
{
    return (DBG_RegisterValue){
        .type = DBG_RegisterValueType_NULL,
    };
}

static inline DBG_RegisterValue DBG_RV_U8(u8 v)
{
    return (DBG_RegisterValue){
        .type      = DBG_RegisterValueType_U8,
        .U8.rw_val = v,
    };
}

static inline DBG_RegisterValue DBG_RV_U16(u16 v)
{
    return (DBG_RegisterValue){
        .type       = DBG_RegisterValueType_U16,
        .U16.rw_val = v,
    };
}

static inline DBG_RegisterValue DBG_RV_U32(u32 v)
{
    return (DBG_RegisterValue){
        .type       = DBG_RegisterValueType_U32,
        .U32.rw_val = v,
    };
}

static inline DBG_RegisterValue DBG_RV_U64(u64 v)
{
    return (DBG_RegisterValue){
        .type       = DBG_RegisterValueType_U64,
        .U64.rw_val = v,
    };
}

static inline DBG_RegisterValue DBG_RV_U128(u64 v0, u64 v1)
{
    return (DBG_RegisterValue){
        .type        = DBG_RegisterValueType_U128,
        .U128.rw_val = {v0, v1},
    };
}

static inline DBG_RegisterValue DBG_RV_U256(u64 v0, u64 v1, u64 v2, u64 v3)
{
    return (DBG_RegisterValue){
        .type        = DBG_RegisterValueType_U256,
        .U256.rw_val = {v0, v1, v2, v3},
    };
}

static inline DBG_RegisterValue
DBG_RV_U512(u64 v0, u64 v1, u64 v2, u64 v3, u64 v4, u64 v5, u64 v6, u64 v7)
{
    return (DBG_RegisterValue){
        .type        = DBG_RegisterValueType_U512,
        .U512.rw_val = {v0, v1, v2, v3, v4, v5, v6, v7},
    };
}

static inline DBG_RegisterValue DBG_RV_F32(u32 v)
{
    f32_ieee754 conv = {
        .u32 = v,
    };

    return (DBG_RegisterValue){
        .type         = DBG_RegisterValueType_F32,
        .F32.rw_val   = v,
        .F32.r_approx = conv.f32,
    };
}

static inline DBG_RegisterValue DBG_RV_F64(u64 v)
{
    f64_ieee754 conv = {
        .u64 = v,
    };

    return (DBG_RegisterValue){
        .type         = DBG_RegisterValueType_F64,
        .F64.rw_val   = v,
        .F64.r_approx = conv.f64,
    };
}

static inline DBG_RegisterValue DBG_RV_F80(u64 v0, u16 v1)
{
    // TODO: need to read the spec for extended precision ieee754 to write the approximation
    return (DBG_RegisterValue){
        .type               = DBG_RegisterValueType_F80,
        .F80.rw_val_lower64 = v0,
        .F80.rw_val_upper16 = v1,
        .F80.r_approx       = 0.0f,
    };
}
