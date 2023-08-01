// TODO: There's code shared between EnumerateKeys, EnumerateValues, and Grow that should be commonized
// TODO: Dict_Enumerate returning a Tuple(key, value)? Would work but the API might get ugly
// TODO: Should we use a 64-bit hash function?
// TODO: Should we use a ligher weight integer hashing function?
// TODO: Should we provide a hash function/compare function for void*?

/* --- Templated Dictionary Type --- */
/* Usage:

    -- Required --
        Dict_KeyType:   The key type for the dictionary, hashed, used to lookup value types in the dict
        Dict_ValueType: The value type stored in the dictionary

    -- Possibly Required --
        Dict_KeyType_Alias:   Alias for the key type
        Dict_ValueType_Alias: Alias for the value type

        Dict_CompareKey(key1, key2): A comparison function for the key type
        Dict_HashKey(key):           A hash function for the key type that results in a uint32_t, defaults provided

    -- Optional --
        Dict_Malloc(bytes):       An allocator function (obeying ISO C's malloc/calloc semantics) that zero's memory
        Dict_Realloc(ptr, bytes): A reallocator function (obeying ISO C's realloc semantics)
        Dict_Free(ptr):           A free function (obeying ISO C's free semantics)

    -- Notes --
        Hash functions are provided for most integral types:
            float, double, int types -- 3 round xor-shift-multiply
            char*                    -- FNV1a
        Default compare key function is simple equality (key1 == key2) for integral types and strcmp for char*
*/

#include <assert.h>
#include <immintrin.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../common/ctl.h"

#if !defined(CTL_DICT_INCLUDED)
#    define CTL_DICT_INCLUDED

#    define Dict(Tkey, Tval)     CONCAT(Dict, Tkey, Tval)
#    define Dict_New(Tkey, Tval) CONCAT(Dict_New, Tkey, Tval)

/* these are internal -- don't use these */
#    define Dict_KeyGroup(Tkey, Tval)   CONCAT(DictKeyGroup, Tkey, Tval)
#    define Dict_ValueGroup(Tkey, Tval) CONCAT(DictValueGroup, Tkey, Tval)
#endif

#if !defined(Dict_KeyType) || !defined(Dict_ValueType)
#    error "Dict template requires key and value types to be defined"
#endif

#if !defined(Dict_HashKey)
#    if !defined(CTL_DICT_COMMON_HASH)
#        define CTL_DICT_COMMON_HASH

static inline uint32_t Dict_Hash32(uint32_t x) {
    x ^= x >> 17;
    x *= 0xed5ad4bb;
    x ^= x >> 11;
    x *= 0xac4c1b51;
    x ^= x >> 15;
    x *= 0x31848bab;
    x ^= x >> 14;
    return x;
}

static inline uint32_t Dict_HashKey_U8(uint8_t key) {
    return Dict_Hash32(key);
}

static inline uint32_t Dict_HashKey_U16(uint16_t key) {
    return Dict_Hash32(key);
}

static inline uint32_t Dict_HashKey_U32(uint32_t key) {
    return Dict_Hash32(key);
}

static inline uint32_t Dict_HashKey_U64(uint64_t key) {
    return Dict_Hash32((uint32_t)key) ^ Dict_Hash32((uint32_t)(key >> 32));
}

static inline uint32_t Dict_HashKey_F32(float key) {
    union {
        float    f32;
        uint32_t u32;
    } conv = {.f32 = key};

    _Static_assert(sizeof(float) == sizeof(uint32_t), "float isn't 32 bits");
    return Dict_Hash32(conv.u32);
}

static inline uint32_t Dict_HashKey_F64(double key) {
    union {
        double   f64;
        uint64_t u64;
    } conv = {.f64 = key};

    _Static_assert(sizeof(double) == sizeof(uint64_t), "double isn't 64 bits");
    return Dict_HashKey_U64(conv.u64);
}

static inline uint32_t Dict_HashKey_Str(const char* restrict str) {
    uint64_t hash = 0xcbf29ce484222325;

    while (*str) {
        hash ^= *str++;
        hash *= 0x100000001b3;
    }

    return (uint32_t)hash ^ (uint32_t)(hash >> 32);
}

#    endif

#    define Dict_HashKey(key) \
        _Generic((key),                   \
            uint8_t:    Dict_HashKey_U8,  \
            int8_t:     Dict_HashKey_U8,  \
            uint16_t:   Dict_HashKey_U16, \
            int16_t:    Dict_HashKey_U16, \
            uint32_t:   Dict_HashKey_U32, \
            int32_t:    Dict_HashKey_U32, \
            uint64_t:   Dict_HashKey_U64, \
            int64_t:    Dict_HashKey_U64, \
            float:      Dict_HashKey_F32, \
            double:     Dict_HashKey_F64, \
            char*:      Dict_HashKey_Str)((key))
#endif

#if !defined(Dict_CompareKey)
#    if !defined(CTL_DICT_COMMON_COMPARE)
#        define CTL_DICT_COMMON_COMPARE

static inline bool Dict_CompareKey_U8(uint8_t k1, uint8_t k2) {
    return k1 == k2;
}

static inline bool Dict_CompareKey_U16(uint16_t k1, uint16_t k2) {
    return k1 == k2;
}

static inline bool Dict_CompareKey_U32(uint32_t k1, uint32_t k2) {
    return k1 == k2;
}

static inline bool Dict_CompareKey_U64(uint64_t k1, uint64_t k2) {
    return k1 == k2;
}

static inline bool Dict_CompareKey_F32(float k1, float k2) {
    return k1 == k2;
}

static inline bool Dict_CompareKey_F64(double k1, double k2) {
    return k1 == k2;
}

static inline bool Dict_CompareKey_Str(char* k1, char* k2) {
    return !strcmp(k1, k2);
}

#    endif

#    define Dict_CompareKey(k1, k2) \
        (_Generic((k1), \
            uint8_t:    Dict_CompareKey_U8,  \
            int8_t:     Dict_CompareKey_U8,  \
            uint16_t:   Dict_CompareKey_U16, \
            int16_t:    Dict_CompareKey_U16, \
            uint32_t:   Dict_CompareKey_U32, \
            int32_t:    Dict_CompareKey_U32, \
            uint64_t:   Dict_CompareKey_U64, \
            int64_t:    Dict_CompareKey_U64, \
            float:      Dict_CompareKey_F32, \
            double:     Dict_CompareKey_F64, \
            char*:      Dict_CompareKey_Str \
        )((k1), (k2)))
#endif

#if !defined(Dict_Malloc)
#    if !defined(CTL_DICT_DEFAULT_ALLOC)
#        define CTL_DICT_DEFAULT_ALLOC
#    endif
#    define Dict_Malloc(bytes) calloc(1, bytes)
#endif

#if !defined(Dict_Realloc)
#    if !defined(CTL_DICT_DEFAULT_ALLOC)
#        warning "Non-default malloc used with default realloc"
#    endif
#    define Dict_Realloc realloc
#endif

#if !defined(Dict_Free)
#    if !defined(CTL_DICT_DEFAULT_ALLOC)
#        warning "Non-default malloc used with default free"
#    endif
#    define Dict_Free free
#endif

#if defined(CTL_DICT_DEFAULT_ALLOC)
#    include <stdlib.h>
#endif

// useful macros internally

#define Tkey Dict_KeyType
#define Tval Dict_ValueType

#if !defined(Dict_KeyType_Alias)
#    define Tkey_ Tkey
#else
#    define Tkey_ Dict_KeyType_Alias
#endif

#if !defined(Dict_ValueType_Alias)
#    define Tval_ Tval
#else
#    define Tval_ Dict_ValueType_Alias
#endif

#if !defined(CTL_DICT_COMMON_TYPES)
#    define CTL_DICT_COMMON_TYPES

typedef union {
    __m128d  d128;
    __m128i  i128;
    uint64_t u64[2];
    uint32_t u32[4];
    uint16_t u16[8];
    uint8_t  u8[16];
} Dict_v128;

typedef union {
    struct {
        uint8_t hlow     : 7;
        uint8_t occupied : 1;
    };
    uint8_t u8;
} Dict_Metadata;

typedef union {
    Dict_Metadata slot[16];
    Dict_v128     v128;
} Dict_MetadataGroup;

static inline uint16_t Dict_CompareBitmask(Dict_MetadataGroup metadata, uint8_t expected) {
    __m128i  exp_vector = _mm_set1_epi8(expected);
    __m128i  comparison = _mm_cmpeq_epi8(exp_vector, metadata.v128.i128);
    uint16_t mask       = _mm_movemask_epi8(comparison);

    return mask;
}

static inline uint16_t Dict_OccupiedBitmask(Dict_MetadataGroup metadata) {
    uint16_t mask = _mm_movemask_epi8(metadata.v128.i128);
    return mask;
}

#endif

typedef struct Dict_KeyGroup(Tkey_, Tval_) {
    Tkey key[16];
}
Dict_KeyGroup(Tkey_, Tval_);

typedef struct Dict_ValueGroup(Tkey_, Tval_) {
    Tval val[16];
}
Dict_ValueGroup(Tkey_, Tval_);

typedef struct Dict(Tkey_, Tval_) {
    size_t capacity;
    size_t size;
    Dict_KeyGroup(Tkey_, Tval_) * key_group;
    Dict_ValueGroup(Tkey_, Tval_) * value_group;
    Dict_MetadataGroup* metadata_group;
}
Dict(Tkey_, Tval_);

CTL_OVERLOADABLE
static inline bool Dict_Grow(Dict(Tkey_, Tval_) * dict);

/**
 * @brief Initializes a dict for use
 * @param dict A pointer to the dict to initialize
 * @param capacity The initial capacity of the dict
 * @return True if the initialization succeeded, false otherwise
 * @note If capacity is not of the form 2^N * 16, it is rounded up to the next suitable form (e.g. 0 -> 16,
 * 17 -> 32, etc)
 */
CTL_OVERLOADABLE
static inline bool Dict_Init(Dict(Tkey_, Tval_) * dict, size_t capacity) {
    dict->capacity = 16 * CTL_NEXT_POW2(capacity / 16);
    dict->size     = 0;

    size_t group_count         = dict->capacity / 16;
    size_t metadata_group_size = group_count * sizeof(Dict_MetadataGroup);
    size_t key_group_size      = group_count * sizeof(Dict_KeyGroup(Tkey_, Tval_));
    size_t value_group_size    = group_count * sizeof(Dict_ValueGroup(Tkey_, Tval_));

    void* block = Dict_Malloc(metadata_group_size + key_group_size + value_group_size);
    if (block == NULL) {
        return false;
    }

    dict->metadata_group = block;
    dict->key_group      = block + metadata_group_size;
    dict->value_group    = block + metadata_group_size + key_group_size;

    return true;
}

/**
 * @brief Allocates and initializes a dict on the heap
 * @param capacity The initial capacity of the dict
 * @return A pointer to the dict on the heap, or NULL if the allocation failed
 * @note If capacity is not of the form 2^N * 16, it is rounded up to the next suitable form (e.g. 0 -> 16,
 * 17 -> 32, etc)
 */
static inline Dict(Tkey_, Tval_) * Dict_New(Tkey_, Tval_)(size_t capacity) {
    Dict(Tkey_, Tval_)* dict = Dict_Malloc(sizeof(*dict));
    if (!Dict_Init(dict, capacity)) {
        Dict_Free(dict);
        return NULL;
    }

    return dict;
}

/**
 * @brief Uninitializes a dict, which then allows it to be discarded without leaking memory
 * @param dict The dict to uninitialize
 * @warning This function should only be used in conjunction with @ref Dict_Init
 */
CTL_OVERLOADABLE
static inline void Dict_Uninit(Dict(Tkey_, Tval_) * dict) {
    Dict_Free(dict->metadata_group);
    dict->metadata_group = NULL;
}

/**
 * @brief Deletes a dict that was allocated on the heap
 * @param dict The dict to delete
 * @warning This function should only be used in conjunction with @ref Dict_New
 */
CTL_OVERLOADABLE
static inline void Dict_Delete(Dict(Tkey_, Tval_) * dict) {
    Dict_Uninit(dict);
    Dict_Free(dict);
}

CTL_OVERLOADABLE
static inline bool
Dict_Find(Dict(Tkey_, Tval_) * dict, Tkey key, uint32_t hash, size_t* group_index_out, size_t* slot_index_out) {
    size_t        group_index       = hash & (dict->capacity / 16 - 1);
    Dict_Metadata expected_metadata = {.hlow = hash, .occupied = true};

    // look through the dict for a match
    // NOTE: we don't bother to provide a termination condition because the table should always have an
    // empty entry
    while (true) {
        // compare a group at a time via SIMD (16 in one go)
        uint16_t mask = Dict_CompareBitmask(dict->metadata_group[group_index], expected_metadata.u8);

        // if bits are set in the mask, check each of the set bit positions (corresponding to positions in
        // the group)
        for (int imask = mask, bitpos = 0; imask != 0; imask &= ~(1 << bitpos)) {
            bitpos = ffs(imask) - 1;
            if (Dict_CompareKey(key, dict->key_group[group_index].key[bitpos])) {
                *group_index_out = group_index;
                *slot_index_out  = bitpos;
                return true;
            }
        }

        // if any were unoccupied, the entry must not be present in the dictionary
        uint16_t occupied_mask = Dict_OccupiedBitmask(dict->metadata_group[group_index]);
        if (occupied_mask != 0xFFFF) {
            *group_index_out = group_index;
            *slot_index_out  = occupied_mask;
            return false;
        }

        // go to next group
        // TODO: quadratic probing? might be better
        group_index = (group_index + 1) & (dict->capacity / 16 - 1);
    }
}

/**
 * @brief Looks up a value given a key, returns true if the key was found, false otherwise
 * @param dict The dictionary to search for the key
 * @param key The key to look for
 * @param out_val A pointer to where to write the value found at @param key, if found
 * @return True if @param key was found and the value was written to @param out_val, false otherwise
 */
CTL_OVERLOADABLE
static inline bool Dict_Get(Dict(Tkey_, Tval_) * dict, Tkey key, Tval* out_val) {
    uint32_t hash = Dict_HashKey(key);
    size_t   group_index, slot_index;
    if (Dict_Find(dict, key, hash, &group_index, &slot_index)) {
        *out_val = dict->value_group[group_index].val[slot_index];
        return true;
    }

    return false;
}

/**
 * @brief Stores a <key, value> pair to the dictionary, replacing existing instances if present
 * @param dict The dictionary to store to
 * @param key The key to act as the unique identifier for the value
 * @param val The value to store associated with key
 * @return True if the <key, value> pair was inserted successfully, false otherwise
 * @warning Current behavior is to not overwrite the key, this can have implications if two separate key
 * allocations with identical hashes are used and the dict is used as a way to track these allocations (e.g.
 * 2 malloc'd char* = "str", the 2nd insertion doesn't store the pointer to the dict, which if left
 * un-free'd would be a leak)
 */
CTL_OVERLOADABLE
static inline bool Dict_Set(Dict(Tkey_, Tval_) * dict, Tkey key, Tval val) {
    uint32_t hash = Dict_HashKey(key);
    size_t   group_index, slot_index;
    if (Dict_Find(dict, key, hash, &group_index, &slot_index)) {
        // key was found in the dict already, overwrite the value
        // TODO: should we overwrite the key? e.g. char* identical strings in different memory locations?
        dict->value_group[group_index].val[slot_index] = val;
    } else {
        // key was not found in the dict already, we get the group index it should go in, but we need to
        // determine the next open slot from the slot mask
        size_t slot_mask = slot_index;
        int    bitpos    = ffs(~(uint16_t)slot_mask) - 1;

        dict->value_group[group_index].val[bitpos] = val;
        dict->key_group[group_index].key[bitpos]   = key;

        dict->metadata_group[group_index].slot[bitpos] = (Dict_Metadata){.hlow = hash, .occupied = true};
        dict->size += 1;
    }

    if (2 * dict->size >= dict->capacity) {
        if (!Dict_Grow(dict)) {
            // Growth allocation failed
            return false;
        }
    }

    return true;
}

/**
 * @brief Clears the dict of all elements, resetting to a clean state
 * @param dict The dict to clear
 */
CTL_OVERLOADABLE
static inline void Dict_Clear(Dict(Tkey_, Tval_) * dict) {
    Dict_Uninit(dict);
    Dict_Init(dict, 0);
}

/**
 * @brief Iteratively enumerate keys within the dict, returns a pointer to the next occupied key given an
 * existing key in the dict
 * @param dict The dictionary to enumerate
 * @param prev_key The previous key, passing NULL will give provide the first key in the dict
 * @return Returns NULL if @param prev_key was the last key in the dict, otherwise returns @param prev_key
 * successor
 */
CTL_OVERLOADABLE
static inline Tkey* Dict_EnumerateKeys(Dict(Tkey_, Tval_) * dict, Tkey* prev_key) {
    const size_t max_group_index = dict->capacity / 16;

    if (prev_key == NULL) {
        if (dict->metadata_group[0].slot[0].occupied) {
            // return the first one if no previous one was supplied and it's occupied
            return &dict->key_group[0].key[0];
        } else {
            // set prevKey to the first one since we know it's empty
            prev_key = &dict->key_group[0].key[0];
        }
    }

    // find the group index and slot index
    uintptr_t first_key_addr = (uintptr_t)&dict->key_group[0].key[0];
    uintptr_t delta_bytes    = (uintptr_t)prev_key - first_key_addr;
    size_t    group_index    = delta_bytes / sizeof(Dict_KeyGroup(Tkey_, Tval_));
    size_t    slot_index     = (delta_bytes - group_index * sizeof(Dict_KeyGroup(Tkey_, Tval_))) / sizeof(Tkey);

    // check if there is another slot in this group that is occupied after prev key
    uint16_t occupied_mask       = Dict_OccupiedBitmask(dict->metadata_group[group_index]);
    uint16_t clear_mask          = (1ull << ((uint32_t)slot_index + 1)) - 1;
    uint16_t upper_occupied_mask = occupied_mask & ~clear_mask;

    if (upper_occupied_mask) {
        int next_slot = ffs(upper_occupied_mask) - 1;
        return &dict->key_group[group_index].key[next_slot];
    }

    // if none were set we need to increment the group index and check the next group
    group_index += 1;

    for (; group_index < max_group_index; group_index += 1) {
        occupied_mask = Dict_OccupiedBitmask(dict->metadata_group[group_index]);

        if (occupied_mask) {
            int next_slot = ffs(occupied_mask) - 1;
            return &dict->key_group[group_index].key[next_slot];
        }
    }

    return NULL;
}

/**
 * @brief Iteratively enumerate values within the dict, returns a pointer to the next occupied value given
 * an existing value in the dict
 * @param dict The dictionary to enumerate
 * @param prev_value The previous value, passing NULL will give provide the first value in the dict
 * @return Returns NULL if @param prev_value was the last value in the dict, otherwise returns @param prev_value
 * successor
 */
CTL_OVERLOADABLE
static inline Tval* Dict_EnumerateValues(Dict(Tkey_, Tval_) * dict, Tval* prev_value) {
    const size_t max_group_index = dict->capacity / 16;

    if (prev_value == NULL) {
        if (dict->metadata_group[0].slot[0].occupied) {
            // return the first one if no previous one was supplied and it's occupied
            return &dict->value_group[0].val[0];
        } else {
            // set prevKey to the first one since we know it's empty
            prev_value = &dict->value_group[0].val[0];
        }
    }

    // find the group index and slot index
    uintptr_t first_key_addr = (uintptr_t)&dict->value_group[0].val[0];
    uintptr_t delta_bytes    = (uintptr_t)prev_value - first_key_addr;
    size_t    group_index    = delta_bytes / sizeof(Dict_ValueGroup(Tkey_, Tval_));
    size_t    slot_index     = (delta_bytes - group_index * sizeof(Dict_ValueGroup(Tkey_, Tval_))) / sizeof(Tkey);

    // check if there is another slot in this group that is occupied after prev key
    uint16_t occupied_mask       = Dict_OccupiedBitmask(dict->metadata_group[group_index]);
    uint16_t clear_mask          = (1ull << ((uint32_t)slot_index + 1)) - 1;
    uint16_t upper_occupied_mask = occupied_mask & ~clear_mask;

    if (upper_occupied_mask) {
        int next_slot = ffs(upper_occupied_mask) - 1;
        assert(group_index < max_group_index);
        return &dict->value_group[group_index].val[next_slot];
    }

    // if none were set we need to increment the group index and check the next group
    group_index += 1;

    for (; group_index < max_group_index; group_index += 1) {
        occupied_mask = Dict_OccupiedBitmask(dict->metadata_group[group_index]);

        if (occupied_mask) {
            int next_slot = ffs(occupied_mask) - 1;
            assert(group_index < max_group_index);
            return &dict->value_group[group_index].val[next_slot];
        }
    }

    return NULL;
}

CTL_OVERLOADABLE
static inline bool Dict_Grow(Dict(Tkey_, Tval_) * dict) {
    const size_t max_group_index = dict->capacity / 16;

    // create a new temp dict to use as a temporary
    Dict(Tkey_, Tval_) dict_new;
    if (!Dict_Init(&dict_new, dict->capacity)) {
        return false;
    }

    // iterate through occupied slots and add them to the new dict to rehash then entries
    size_t   group_index   = 0;
    uint16_t clear_mask    = 0;
    uint16_t occupied_mask = Dict_OccupiedBitmask(dict->metadata_group[group_index]);

    while (group_index < max_group_index) {
        uint16_t next_occupied_mask = occupied_mask & ~clear_mask;

        if (next_occupied_mask) {
            int  next_slot = ffs(next_occupied_mask) - 1;
            Tkey key       = dict->key_group[group_index].key[next_slot];
            Tval val       = dict->value_group[group_index].val[next_slot];

            if (!Dict_Set(&dict_new, key, val)) {
                Dict_Uninit(&dict_new);
                return false;
            }

            // adjust the clear mask to exclude already processed entries
            clear_mask = (1 << (next_slot + 1)) - 1;
        } else {
            // increment the group_index and reset the clear_mask
            group_index += 1;

            occupied_mask = Dict_OccupiedBitmask(dict->metadata_group[group_index]);
            clear_mask    = 0;
        }
    }

    // free the old dict, copy the new one's pointers
    Dict_Uninit(dict);
    *dict = dict_new;

    return true;
}

CTL_OVERLOADABLE
static inline bool Dict_Copy(Dict(Tkey_, Tval_) * src_dict, Dict(Tkey_, Tval_) * dst_dict) {
    // new_dict will be manipulated to prevent breaking dst_dict in the event of an allocation failure
    Dict(Tkey_, Tval_) new_dict;
    if (!Dict_Init(&new_dict, src_dict->capacity - 1)) {
        return false;
    }

    // figure out the total size of the source dict's memory
    size_t group_count         = src_dict->capacity / 16;
    size_t metadata_group_size = group_count * sizeof(Dict_MetadataGroup);
    size_t key_group_size      = group_count * sizeof(Dict_KeyGroup(Tkey_, Tval_));
    size_t value_group_size    = group_count * sizeof(Dict_ValueGroup(Tkey_, Tval_));
    size_t total_size          = metadata_group_size + key_group_size + value_group_size;

    // copy the source dict's data to the new dict's data
    memcpy(new_dict.metadata_group, src_dict->metadata_group, total_size);
    new_dict.size = src_dict->size;

    // free the dst_dict, then copy new_dict to it so that it's now the duplicate
    Dict_Uninit(dst_dict);
    *dst_dict = new_dict;

    return true;
}

// cleanup macros
#undef Dict_KeyType
#undef Dict_KeyType_Alias

#undef Dict_ValueType
#undef Dict_ValueType_Alias

#undef Dict_CompareKey
#undef Dict_HashKey

#undef Dict_Malloc
#undef Dict_Realloc
#undef Dict_Free
#undef CTL_DICT_DEFAULT_ALLOC

#undef Tkey
#undef Tval

#undef Tkey_
#undef Tval_
