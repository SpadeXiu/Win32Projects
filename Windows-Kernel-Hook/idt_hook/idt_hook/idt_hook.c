#include "idt_hook.h"

PVOID g_bp_proc; // Breakpoint
PVOID g_db_proc; // Debug Exception
PVOID g_pf_proc; // Page Fault

/////////////////////////////////////////////////////////////////////////

VOID my_bp_handler()
{
	KdPrint(("\r\n#BreakPoint\r\n"));
}

VOID my_db_handler()
{
	KdPrint(("\r\n#Debug Exception\r\n"));
}

VOID my_pf_handler()
{
	UINT32 laddr;
	__asm
	{
		mov eax, cr2;
		mov laddr, eax;
	}
	KdPrint(("\r\n#Page Fault at 0x%.8x\r\n", laddr));
}

__declspec(naked) VOID bp_hook()
{
	_asm
	{
		push fs;
		push ds;
		push es;
		push gs;
		pushad;
		pushfd;
		mov bx, 0x30;
		mov fs, bx;
		call my_bp_handler;
		popfd;
		popad;
		pop gs;
		pop es;
		pop ds;
		pop fs;
		jmp g_bp_proc;
	}
}

__declspec(naked) VOID db_hook()
{
	_asm
	{
		push fs;
		push ds;
		push es;
		push gs;
		pushad;
		pushfd;
		mov bx, 0x30;
		mov fs, bx;
		call my_db_handler;
		popfd;
		popad;
		pop gs;
		pop es;
		pop ds;
		pop fs;
		jmp g_db_proc;
	}
}

__declspec(naked) VOID pf_hook()
{
	_asm
	{
		push fs;
		push ds;
		push es;
		push gs;
		pushad;
		pushfd;
		mov bx, 0x30;
		mov fs, bx;
		call my_pf_handler;
		popfd;
		popad;
		pop gs;
		pop es;
		pop ds;
		pop fs;
		jmp g_pf_proc;
	}
}
/////////////////////////////////////////////////////////////////////////

VOID DisableWriteProtect()
{
	_asm
	{
		mov eax, cr0;
		and eax, CR0_WP_DISABLE_MASK;
		mov cr0, eax;
		cli;
	}
}

VOID EnableWriteProtect()
{
	_asm
	{
		mov eax, cr0;
		or eax, ~CR0_WP_DISABLE_MASK;
		mov cr0, eax;
		sti;
	}
}

PVOID GetIntProcAddress(UINT8 vector)
{
	IDTR idtr;
	PVOID proc = NULL;
	PIA32_IDT_ENTRY idt_entries = NULL;

	_asm sidt idtr; // 获取 IDTR 寄存器的内容

	// idtr.base 是 IDT 的线性基地址, C语言中使用的地址是虚拟地址;
	// 由于在 Windows 系统中数据段的段基址为 0, 所以线性地址 = 虚拟地址.
	idt_entries = (PIA32_IDT_ENTRY)(idtr.base);

	proc = (PVOID)MAKELONG(idt_entries[vector].offset_high,
		idt_entries[vector].offset_low);
	
	return proc;
}

VOID SetIntProcAddress(PVOID proc, UINT8 vector)
{
	IDTR idtr;
	PIA32_IDT_ENTRY idt_entries = NULL;

	_asm sidt idtr;

	idt_entries = (PIA32_IDT_ENTRY)(idtr.base);

	DisableWriteProtect();

	idt_entries[vector].offset_high = GETHIGH(proc);
	idt_entries[vector].offset_low = GETLOW(proc);

	EnableWriteProtect();
}

VOID IdtHook(UINT8 vector, PVOID new_proc, PVOID *old_proc)
{
	*old_proc = GetIntProcAddress(vector);

	ASSERT(*old_proc != NULL);

	SetIntProcAddress(new_proc, vector);
}

/////////////////////////////////////////////////////////////////////////

VOID UnLoadDriver(PDRIVER_OBJECT p_driver_object)
{
	KdPrint(("UnloadDriver Success\r\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT p_driver_object, PUNICODE_STRING p_reg_path)
{
	p_driver_object->DriverUnload = UnLoadDriver;

	IdtHook(INT_VECTOR_BP, (PVOID)bp_hook, &g_bp_proc);
	IdtHook(INT_VECTOR_DB, (PVOID)db_hook, &g_db_proc);
	IdtHook(INT_VECTOR_PF, (PVOID)pf_hook, &g_pf_proc);
	
	return STATUS_SUCCESS;
}