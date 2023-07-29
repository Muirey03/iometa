#ifndef FAKE_COREFOUNDATION_H
#define FAKE_COREFOUNDATION_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

/* Typedefs */

typedef unsigned int CFIndex;
typedef uint8_t UInt8;
typedef uint32_t CFOptionFlags;

/* CFType */

typedef enum _CFTypeID {
    kCFStringTypeID,
    kCFDataTypeID,
    kCFNumberTypeID,
    kCFArrayTypeID,
    kCFDictionaryTypeID,
    kCFBooleanTypeID,
    kCFSetTypeID,
} CFTypeID;

struct _CFType;
typedef struct _CFType* CFTypeRef;
typedef void(*CFFreeFn)(CFTypeRef cf);

struct _CFType {
    CFTypeID typeID;
    atomic_int refcnt;
    CFFreeFn free;
};

#define DEFINE_TYPE(name, fields) \
    extern const struct _CFType k ## name ## Type; \
    struct _ ## name { \
        struct _CFType type; \
        fields \
    }; \
    typedef struct _ ## name * name ## Ref; \
    CFTypeID name ## GetTypeID();

CFTypeRef CFRetain(CFTypeRef cf);
void CFRelease(CFTypeRef cf);
CFTypeID CFGetTypeID(CFTypeRef cf);
void CFShow(CFTypeRef obj);

/* CFAllocator */

#define kCFAllocatorDefault NULL
typedef void* CFAllocatorRef;

/* CFString */

DEFINE_TYPE(CFString,
    const char* data;
    bool isConstant;
);

#define CFSTR(cStr) CFStringMakeConstantString(cStr)

typedef enum _CFStringEncoding {
    kCFStringEncodingUTF8,
    kCFStringEncodingMacRoman = kCFStringEncodingUTF8
} CFStringEncoding;

CFStringRef CFStringMakeConstantString(const char* cStr);
CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding);
CFStringRef CFStringCreateWithFormat(CFAllocatorRef alloc, CFTypeRef formatOptions, CFStringRef format, ...);
const char * CFStringGetCStringPtr(CFStringRef theString, CFStringEncoding encoding);

/* CFData */

DEFINE_TYPE(CFData,
    void* data;
    size_t size;
);

CFDataRef CFDataCreate(CFAllocatorRef allocator, const uint8_t *bytes, CFIndex length);
const uint8_t * CFDataGetBytePtr(CFDataRef theData);
CFIndex CFDataGetLength(CFDataRef theData);

/* CFNumber */

typedef enum _CFNumberType {
    kCFNumberSInt32Type,
    kCFNumberSInt64Type,
    kCFNumberLongLongType
} CFNumberType;

DEFINE_TYPE(CFNumber,
    uint64_t value;
);

CFNumberRef CFNumberCreate(CFAllocatorRef allocator, CFNumberType theType, const void *valuePtr);
bool CFNumberGetValue(CFNumberRef number, CFNumberType theType, void *valuePtr);

/* CFArray */

DEFINE_TYPE(CFArray,
    void const** values;
    size_t count;
    bool cf_values;
);

typedef void* CFArrayCallBacks;
extern CFArrayCallBacks kCFTypeArrayCallBacks;
typedef CFArrayRef CFMutableArrayRef;

CFMutableArrayRef CFArrayCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFArrayCallBacks *callBacks);
CFIndex CFArrayGetCount(CFArrayRef theArray);
const void * CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx);
void CFArrayAppendValue(CFMutableArrayRef theArray, const void *value);

/* CFDictionary */

DEFINE_TYPE(CFDictionary,
    const void** keys;
    const void** values;
    size_t count;
    bool cf_keys;
    bool cf_values;
);

typedef void* CFDictionaryKeyCallBacks;
typedef void* CFDictionaryValueCallBacks;
extern CFDictionaryKeyCallBacks kCFTypeDictionaryKeyCallBacks;
extern CFDictionaryValueCallBacks kCFTypeDictionaryValueCallBacks;
typedef CFDictionaryRef CFMutableDictionaryRef;

CFMutableDictionaryRef CFDictionaryCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFDictionaryKeyCallBacks *keyCallBacks, const CFDictionaryValueCallBacks *valueCallBacks);
void CFDictionarySetValue(CFMutableDictionaryRef theDict, const void *key, const void *value);
const void * CFDictionaryGetValue(CFDictionaryRef theDict, const void *key);

/* CFBoolean */

DEFINE_TYPE(CFBoolean,
    bool value;
);

extern const CFBooleanRef kCFBooleanTrue;
extern const CFBooleanRef kCFBooleanFalse;

/* CFSet */

DEFINE_TYPE(CFSet,
    void const** values;
    size_t count;
    bool cf_values;
);

typedef void* CFSetCallBacks;
extern CFSetCallBacks kCFTypeSetCallBacks;
typedef CFSetRef CFMutableSetRef;

CFMutableSetRef CFSetCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFSetCallBacks *callBacks);
void CFSetAddValue(CFMutableSetRef theSet, const void *value);

#endif // FAKE_COREFOUNDATION_H
