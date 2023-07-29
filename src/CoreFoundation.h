#ifndef MY_COREFOUNDATION_H
#define MY_COREFOUNDATION_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

/* Typedefs */

typedef unsigned int CFIndex;
typedef uint8_t UInt8;
typedef uint32_t CFOptionFlags;

/* CFType */

typedef unsigned int CFTypeID;
struct _CFType;
typedef struct _CFType* CFTypeRef;

CFTypeRef CFRetain(CFTypeRef cf);
void CFRelease(CFTypeRef cf);
CFTypeID CFGetTypeID(CFTypeRef cf);
void CFShow(CFTypeRef obj);

#define DECLARE_TYPE(name) \
    typedef CFTypeRef name ## Ref; \
    CFTypeID name ## GetTypeID();

/* CFAllocator */

#define kCFAllocatorDefault NULL
typedef void* CFAllocatorRef;

/* CFString */

DECLARE_TYPE(CFString);

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

DECLARE_TYPE(CFData);

CFDataRef CFDataCreate(CFAllocatorRef allocator, const uint8_t *bytes, CFIndex length);
const uint8_t * CFDataGetBytePtr(CFDataRef theData);
CFIndex CFDataGetLength(CFDataRef theData);

/* CFNumber */

typedef enum _CFNumberType {
    kCFNumberSInt32Type,
    kCFNumberSInt64Type,
    kCFNumberLongLongType
} CFNumberType;

DECLARE_TYPE(CFNumber);

CFNumberRef CFNumberCreate(CFAllocatorRef allocator, CFNumberType theType, const void *valuePtr);
bool CFNumberGetValue(CFNumberRef number, CFNumberType theType, void *valuePtr);

/* CFArray */

DECLARE_TYPE(CFArray);

typedef void* CFArrayCallBacks;
extern CFArrayCallBacks kCFTypeArrayCallBacks;
typedef CFArrayRef CFMutableArrayRef;

CFMutableArrayRef CFArrayCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFArrayCallBacks *callBacks);
CFIndex CFArrayGetCount(CFArrayRef theArray);
void * CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx);
void CFArrayAppendValue(CFMutableArrayRef theArray, const void *value);

/* CFDictionary */

DECLARE_TYPE(CFDictionary);

typedef void* CFDictionaryKeyCallBacks;
typedef void* CFDictionaryValueCallBacks;
extern CFDictionaryKeyCallBacks kCFTypeDictionaryKeyCallBacks;
extern CFDictionaryValueCallBacks kCFTypeDictionaryValueCallBacks;
typedef CFDictionaryRef CFMutableDictionaryRef;

CFMutableDictionaryRef CFDictionaryCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFDictionaryKeyCallBacks *keyCallBacks, const CFDictionaryValueCallBacks *valueCallBacks);
void CFDictionarySetValue(CFMutableDictionaryRef theDict, const void *key, const void *value);
void * CFDictionaryGetValue(CFDictionaryRef theDict, const void *key);

/* CFBoolean */

DECLARE_TYPE(CFBoolean);

extern const CFBooleanRef kCFBooleanTrue;
extern const CFBooleanRef kCFBooleanFalse;

/* CFSet */

DECLARE_TYPE(CFSet);

typedef void* CFSetCallBacks;
extern CFSetCallBacks kCFTypeSetCallBacks;
typedef CFSetRef CFMutableSetRef;

CFMutableSetRef CFSetCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFSetCallBacks *callBacks);
void CFSetAddValue(CFMutableSetRef theSet, const void *value);

#endif // MY_COREFOUNDATION_H
