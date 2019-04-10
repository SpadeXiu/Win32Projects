#ifndef _IDT_HOOK
#define _IDT_HOOK


#include <ntddk.h>

#define CR0_WP_DISABLE_MASK  0xfffeffff

#define INT_VECTOR_DB	0x1
#define INT_VECTOR_BP	0x3 
#define INT_VECTOR_PF	0xE

#define MAKELONG(high,low) (UINT32)((((UINT32)(high) & 0xffff) << 16) | \
	((UINT32)(low) & 0xffff))

#define GETHIGH(a) (UINT16)(((UINT32)(a) >> 16) & 0xffff)

#define GETLOW(a) (UINT16)(((UINT32)(a)) & 0xffff)

#pragma pack(push, 1)

typedef struct IDTR {
	UINT16 limit;
	UINT32 base;
} IDTR, *PIDTR;

typedef struct IA32_IDT_ENTRY {
	UINT16 offset_low;
	UINT16 selector;
	UINT16 attr;
	UINT16 offset_high;
} IA32_IDT_ENTRY, *PIA32_IDT_ENTRY;

#pragma pack(pop)

#endif // _IDT_HOOK
