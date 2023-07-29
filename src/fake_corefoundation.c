#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "fake_corefoundation.h"

#define ERR(msg) fprintf(stderr, msg); abort()

#define CFTypeCreate(type, freeFn) \
void freeFn(type ## Ref cf); \
const struct _CFType k ## type ## Type = { \
    .typeID = k ## type ## TypeID, \
    .free = (CFFreeFn)freeFn \
}; \
CFTypeID type ## GetTypeID() { return k ## type ## TypeID; }
#define CFAlloc(type) (type ## Ref)calloc(sizeof(struct _ ## type), 1)
#define typeField type
#define CFInit(obj, type) do { \
    obj->typeField = k ## type ## Type; \
    obj->typeField.refcnt = 1; \
} while (0)

/* CFType */

CFTypeRef CFRetain(CFTypeRef cf) {
    if (!cf) return NULL;

    atomic_fetch_add(&cf->refcnt, 1);
    return cf;
}

void CFRelease(CFTypeRef cf) {
    if (!cf) return;

    atomic_int prev = atomic_fetch_sub(&cf->refcnt, 1);
    if (prev == 1) {
        cf->free(cf);
    }
}

CFTypeID CFGetTypeID(CFTypeRef cf) {
    return cf->typeID;
}

bool CFEqual(CFTypeRef a, CFTypeRef b) {
    if (a == b)
        return true;
    
    // only implemented for strings atm
    if ((CFGetTypeID(a) == CFGetTypeID(b)) && (CFGetTypeID(a) == kCFStringTypeID)) {
        return strcmp(  CFStringGetCStringPtr((CFStringRef)a, kCFStringEncodingUTF8),
                        CFStringGetCStringPtr((CFStringRef)b, kCFStringEncodingUTF8)) == 0;
    }
    return false;
}

void CFShow(CFTypeRef obj) {
    fprintf(stderr, "<FakeCFObject %p, typeID: %u>\n", (void*)obj, (unsigned int)CFGetTypeID(obj));
}

/* CFString */

CFTypeCreate(CFString, CFStringFree);

CFStringRef CFStringMakeConstantString(const char* cStr) {
    // I don't know a nice way to make these really constant, so we'll heap-allocate them and leak the memory...
    CFStringRef str = CFAlloc(CFString);
    CFInit(str, CFString);
    str->data = cStr;
    str->isConstant = true;
    return str;
}

CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding) {
    if (encoding != kCFStringEncodingUTF8) {
        ERR("Unsupported string encoding.\n");
    }

    CFStringRef str = CFAlloc(CFString);
    CFInit(str, CFString);
    str->data = strdup(cStr);
    str->isConstant = false;
    return str;
}

CFStringRef CFStringCreateWithFormat(CFAllocatorRef alloc, CFTypeRef formatOptions, CFStringRef format, ...) {
    va_list args;
    va_start(args, format);
    char* cStr;
    vasprintf(&cStr, CFStringGetCStringPtr(format, kCFStringEncodingUTF8), args);
    CFStringRef str = CFStringCreateWithCString(kCFAllocatorDefault, cStr, kCFStringEncodingUTF8);
    free(cStr);
    va_end(args);
    return str;
}

const char * CFStringGetCStringPtr(CFStringRef theString, CFStringEncoding encoding) {
    return theString->data;
}

void CFStringFree(CFStringRef str) {
    if (!str->isConstant) {
        free((void*)str->data);
        free(str);
    }
}

/* CFData */

CFTypeCreate(CFData, CFDataFree);

CFDataRef CFDataCreate(CFAllocatorRef allocator, const uint8_t *bytes, CFIndex length) {
    CFDataRef data = CFAlloc(CFData);
    CFInit(data, CFData);
    data->data = malloc(length);
    data->size = length;
    memcpy(data->data, bytes, length);
    return data;
}

const uint8_t * CFDataGetBytePtr(CFDataRef theData) {
    return (const uint8_t *)theData->data;
}

CFIndex CFDataGetLength(CFDataRef theData) {
    return (CFIndex)theData->size;
}

void CFDataFree(CFDataRef data) {
    free(data->data);
    free(data);
}

/* CFNumber */

CFTypeCreate(CFNumber, CFNumberFree);

CFNumberRef CFNumberCreate(CFAllocatorRef allocator, CFNumberType theType, const void *valuePtr) {
    CFNumberRef num = CFAlloc(CFNumber);
    CFInit(num, CFNumber);
    uint64_t value;
    switch (theType) {
        case kCFNumberSInt32Type:
            value = (uint64_t)*(int32_t*)valuePtr;
            break;
        case kCFNumberSInt64Type:
        case kCFNumberLongLongType:
            value = (uint64_t)*(int64_t*)valuePtr;
            break;
        default:
            ERR("Unsupported number type.");
    }
    num->value = value;
    return num;
}

bool CFNumberGetValue(CFNumberRef number, CFNumberType theType, void *valuePtr) {
    switch (theType) {
        case kCFNumberSInt32Type:
            *(int32_t*)valuePtr = (int32_t)number->value;
            break;
        case kCFNumberSInt64Type:
        case kCFNumberLongLongType:
            *(int64_t*)valuePtr = (int64_t)number->value;
            break;
        default:
            ERR("Unsupported number type.");
    }
    return true;
}

void CFNumberFree(CFNumberRef num) {
    free(num);
}

/* CFArray */

CFTypeCreate(CFArray, CFArrayFree);

CFArrayCallBacks kCFTypeArrayCallBacks = (CFArrayCallBacks)&kCFTypeArrayCallBacks;

CFMutableArrayRef CFArrayCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFArrayCallBacks *callBacks) {
    CFArrayRef array = CFAlloc(CFArray);
    CFInit(array, CFArray);
    array->count = 0;
    array->values = calloc(capacity, sizeof(const void*));
    array->cf_values = callBacks && *callBacks == kCFTypeArrayCallBacks;
    if (callBacks && *callBacks != kCFTypeArrayCallBacks) {
        ERR("Other CFArrayCallBacks not supported.\n");
    }
    return array;
}

CFIndex CFArrayGetCount(CFArrayRef theArray) {
    return theArray->count;
}

const void * CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx) {
    return theArray->values[idx];
}

void CFArrayAppendValue(CFMutableArrayRef theArray, const void *value) {
    CFIndex oldCount = theArray->count;
    theArray->values = realloc(theArray->values, sizeof(const void*) * (oldCount + 1));
    theArray->values[oldCount] = value;
    theArray->count = oldCount + 1;
    if (theArray->cf_values)
        CFRetain((CFTypeRef)value);
}

void CFArrayFree(CFArrayRef array) {
    if (array->cf_values) {
        for (CFIndex i = 0; i < array->count; i++)
            CFRelease((CFTypeRef)array->values[i]);
    }
    free(array->values);
    free(array);
}

/* CFDictionary */

CFTypeCreate(CFDictionary, CFDictionaryFree);

CFDictionaryKeyCallBacks kCFTypeDictionaryKeyCallBacks = (CFDictionaryKeyCallBacks)&kCFTypeDictionaryKeyCallBacks;
CFDictionaryValueCallBacks kCFTypeDictionaryValueCallBacks = (CFDictionaryKeyCallBacks)&kCFTypeDictionaryValueCallBacks;

CFMutableDictionaryRef CFDictionaryCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFDictionaryKeyCallBacks *keyCallBacks, const CFDictionaryValueCallBacks *valueCallBacks) {
    CFDictionaryRef dict = CFAlloc(CFDictionary);
    CFInit(dict, CFDictionary);
    dict->count = 0;
    dict->keys = calloc(capacity, sizeof(const void*));
    dict->values = calloc(capacity, sizeof(const void*));

    dict->cf_keys = keyCallBacks && *keyCallBacks == kCFTypeDictionaryKeyCallBacks;
    if (keyCallBacks && *keyCallBacks != kCFTypeDictionaryKeyCallBacks) {
        ERR("Other CFDictionaryKeyCallBacks not supported.\n");
    }

    dict->cf_values = valueCallBacks && *valueCallBacks == kCFTypeDictionaryValueCallBacks;
    if (valueCallBacks && *valueCallBacks != kCFTypeDictionaryValueCallBacks) {
        ERR("Other CFDictionaryValueCallBacks not supported.\n");
    }
    return dict;
}

const void** CFDictionaryFind(CFDictionaryRef dict, const void* key) {
    for (CFIndex i = 0; i < dict->count; i++) {
        const void* otherKey = dict->keys[i];
        if ((key == otherKey) ||
            (dict->cf_keys && CFEqual((CFTypeRef)key, (CFTypeRef)otherKey))) {
            
            return &dict->values[i];
        }
    }
    return NULL;
}

void CFDictionarySetValue(CFMutableDictionaryRef dict, const void *key, const void *value) {
    const void** slot = CFDictionaryFind(dict, key);
    if (!slot) {
        CFIndex oldCount = dict->count;
        dict->values = realloc(dict->values, sizeof(const void*) * (oldCount + 1));
        dict->keys = realloc(dict->keys, sizeof(const void*) * (oldCount + 1));
        dict->count = oldCount + 1;
        dict->keys[oldCount] = key;
        if (dict->cf_keys)
            CFRetain((CFTypeRef)key);
        slot = &dict->values[oldCount];
        *slot = NULL;
    }
    CFTypeRef oldValue = NULL;
    if (dict->cf_values && *slot)
        oldValue = (CFTypeRef)*slot;
    *slot = value;
    if (dict->cf_values)
        CFRetain((CFTypeRef)value);
    if (oldValue)
        CFRelease(oldValue);
}

const void * CFDictionaryGetValue(CFDictionaryRef dict, const void *key) {
    const void** slot = CFDictionaryFind(dict, key);
    if (slot) {
        return *slot;
    }
    return NULL;
}

void CFDictionaryFree(CFDictionaryRef dict) {
    for (CFIndex i = 0; i < dict->count; i++) {
        if (dict->cf_keys)
            CFRelease((CFTypeRef)dict->keys[i]);
        if (dict->cf_values)
            CFRelease((CFTypeRef)dict->values[i]);
    }
    free(dict->keys);
    free(dict->values);
    free(dict);
}

/* CFBoolean */

CFTypeCreate(CFBoolean, CFBooleanFree);

// needs to be non-const so that refcnt can change
struct _CFBoolean _booleanTrue = (struct _CFBoolean){
    .type = (struct _CFType){
        .typeID = kCFBooleanTypeID,
        .refcnt = 1,
        .free = (CFFreeFn)CFBooleanFree,
    },
    .value = true,
};
const CFBooleanRef kCFBooleanTrue = (const CFBooleanRef)&_booleanTrue;

struct _CFBoolean _booleanFalse = (struct _CFBoolean){
    .type = (struct _CFType){
        .typeID = kCFBooleanTypeID,
        .refcnt = 1,
        .free = (CFFreeFn)CFBooleanFree,
    },
    .value = true,
};
const CFBooleanRef kCFBooleanFalse = (const CFBooleanRef)&_booleanFalse;

void CFBooleanFree(CFBooleanRef b) {}

/* CFSet */

CFTypeCreate(CFSet, CFSetFree);

CFSetCallBacks kCFTypeSetCallBacks = (CFArrayCallBacks)&kCFTypeSetCallBacks;

CFMutableSetRef CFSetCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFSetCallBacks *callBacks) {
    CFSetRef set = CFAlloc(CFSet);
    CFInit(set, CFSet);
    set->count = 0;
    set->values = calloc(capacity, sizeof(const void*));
    set->cf_values = callBacks && *callBacks == kCFTypeSetCallBacks;
    if (callBacks && *callBacks != kCFTypeSetCallBacks) {
        ERR("Other CFSetCallBacks not supported.\n");
    }
    return set;
}

void CFSetAddValue(CFMutableSetRef theSet, const void *value) {
    bool inSet = false;
    for (CFIndex i = 0; i < theSet->count; i++) {
        const void* otherValue = theSet->values[i];
        if ((value == otherValue) ||
            (theSet->cf_values && CFEqual((CFTypeRef)value, (CFTypeRef)otherValue))) {
                
            inSet = true;
            break;
        }
    }
    if (!inSet) {
        CFIndex oldCount = theSet->count;
        theSet->values = realloc(theSet->values, sizeof(const void*) * (oldCount + 1));
        theSet->values[oldCount] = value;
        theSet->count = oldCount + 1;
        if (theSet->cf_values)
            CFRetain((CFTypeRef)value);
    }
}

void CFSetFree(CFSetRef set) {
    if (set->cf_values) {
        for (CFIndex i = 0; i < set->count; i++)
            CFRelease((CFTypeRef)set->values[i]);
    }
    free(set->values);
    free(set);
}
