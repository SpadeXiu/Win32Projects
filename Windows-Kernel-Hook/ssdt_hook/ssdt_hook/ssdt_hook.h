#ifndef SSDT_HOOK
#define SSDT_HOOK

#include <ntddk.h>

#define CR0_WP_DISABLE_MASK  0xfffeffff

typedef struct KeServiceDescriptorEntry {
	PULONG		ServiceTableBase;
	PULONG		ServiceCounterTableBase;
	ULONG		NumberOfServices;
	PULONG		ParamTableBase;
} KeServiceDescriptorTableEntry_t, *PKeServiceDescriptorTableEntry_t;

// µ¼ÈëSSDTµÄ·ûºÅ
__declspec(dllimport)  KeServiceDescriptorTableEntry_t KeServiceDescriptorTable;


typedef NTSTATUS (*NT_READ_FILE)(
	_In_     HANDLE           FileHandle,
	_In_opt_ HANDLE           Event,
	_In_opt_ PIO_APC_ROUTINE  ApcRoutine,
	_In_opt_ PVOID            ApcContext,
	_Out_    PIO_STATUS_BLOCK IoStatusBlock,
	_Out_    PVOID            Buffer,
	_In_     ULONG            Length,
	_In_opt_ PLARGE_INTEGER   ByteOffset,
	_In_opt_ PULONG           Key
	);

typedef NTSTATUS (*NT_WRITE_FILE)(
	_In_     HANDLE           FileHandle,
	_In_opt_ HANDLE           Event,
	_In_opt_ PIO_APC_ROUTINE  ApcRoutine,
	_In_opt_ PVOID            ApcContext,
	_Out_    PIO_STATUS_BLOCK IoStatusBlock,
	_In_    PVOID			  Buffer,
	_In_     ULONG            Length,
	_In_opt_ PLARGE_INTEGER   ByteOffset,
	_In_opt_ PULONG           Key
	);



#endif // SSDT_HOOK
