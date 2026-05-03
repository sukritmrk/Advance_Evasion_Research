#pragma once
#include "Def.h"

// Modular ของ Hell's Gate 
__forceinline DWORD getHellsGateSSN(ULONG_PTR uiNtDllAddr, EXPORT_TABLES ntdllExports, const char* FuncName) {

	for (int i = 0; i < ntdllExports.dwNumberOfNames; i++) {

		auto szFuncName = reinterpret_cast<char*>(uiNtDllAddr + ntdllExports.pdwAddressOfNames[i]);

		if (ManualStrCmp(szFuncName, FuncName)) {

			WORD wOrdinal = ntdllExports.pwAddressOfNameOrdinals[i];

			DWORD dwFuncRVA = ntdllExports.pdwAddressOfFunctions[wOrdinal];

			ULONG_PTR uiFuncAddr = uiNtDllAddr + dwFuncRVA;

			// --- เริ่มต้น Hell's Gate Check ---
			PBYTE pByteAddr = reinterpret_cast<PBYTE>(uiFuncAddr);

			// ตรวจสอบ Pattern: mov r10, rcx (4C 8B D1) และ mov eax, SSN (B8)
			if (pByteAddr[0] == 0x4C && pByteAddr[1] == 0x8B
				&& pByteAddr[2] == 0xD1 && pByteAddr[3] == 0xB8) {

				return *reinterpret_cast<PDWORD>(pByteAddr + 4);

			}
			else {
				// ถ้าไม่ตรง Pattern แสดงว่าอาจโดน Hook หรือไม่ใช่ Syscall Stub
				return 0;
			}
		}
	}
	return -1;
}

// Modular ของ Halo's Gate 
__forceinline DWORD getHalosGateSSN(ULONG_PTR uiNtDllAddr, EXPORT_TABLES ntdllExports, PIMAGE_NT_HEADERS64 pNtHeader, const char* FuncName) {

	// ส่วน logic การหา .text สำหรับการเช็คขอบเขตของ Section ไม่ให้โปรแกรมเดินเลยจนเกิด Memory corruption
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);
	WORD NumberOfSection = pNtHeader->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER TextSection;

	for (WORD i = 0; i < NumberOfSection; i++) {

		if (ManualStrCmp((const char*)pSection[i].Name, ".text")) {
			TextSection = pSection[i];
		}
	}
	if(TextSection.VirtualAddress == 0){ return 0; }

	PBYTE uiTextStart = {0};
	PBYTE uiTextEnd = {0};

	uiTextStart = reinterpret_cast<PBYTE>(uiNtDllAddr + TextSection.VirtualAddress);
	uiTextEnd = reinterpret_cast<PBYTE>(uiNtDllAddr + TextSection.VirtualAddress + TextSection.Misc.VirtualSize);

	for (int i = 0; i < ntdllExports.dwNumberOfNames; i++) {

		auto szFuncName = reinterpret_cast<char*>(uiNtDllAddr + ntdllExports.pdwAddressOfNames[i]);

		if (ManualStrCmp(szFuncName, FuncName)) {

			WORD wOrdinal = ntdllExports.pwAddressOfNameOrdinals[i];

			DWORD dwFuncRVA = ntdllExports.pdwAddressOfFunctions[wOrdinal];

			ULONG_PTR uiFuncAddr = uiNtDllAddr + dwFuncRVA;

			// --- เริ่มต้น Halo's Gate Check ---
			PBYTE pByteAddr = reinterpret_cast<PBYTE>(uiFuncAddr);
			if (pByteAddr == NULL) return -1;

			// ตรวจสอบ Pattern: mov r10, rcx (4C 8B D1) และ mov eax, SSN (B8)
			if (pByteAddr[0] == 0x4C && pByteAddr[1] == 0x8B
				&& pByteAddr[2] == 0xD1 && pByteAddr[3] == 0xB8) {

				return *reinterpret_cast<PDWORD>(pByteAddr + 4);
			}
			// ไม่เจอ เริ่มส่วนของการเช็ค Neighbor SSN number
			for (int j = 1; j < ntdllExports.pExportDir->NumberOfFunctions; j++) {

				// เช็คด้านบน
				PBYTE pUpFunc = pByteAddr - (j * 0x20);
				if (pUpFunc > uiTextStart && pUpFunc < uiTextEnd) {

					if (pUpFunc[0] == 0x4C && pUpFunc[1] == 0x8B
						&& pUpFunc[2] == 0xD1 && pUpFunc[3] == 0xB8) {

						return (*reinterpret_cast<PDWORD>(pUpFunc + 4)) + j;
					}
				}
				// เช็คด้านล่าง
				PBYTE pDownFunc = pByteAddr + (j * 0x20);
				if (pDownFunc > uiTextStart && pDownFunc < uiTextEnd) {

					if (pDownFunc[0] == 0x4C && pDownFunc[1] == 0x8B
						&& pDownFunc[2] == 0xD1 && pDownFunc[3] == 0xB8) {

						return (*reinterpret_cast<PDWORD>(pDownFunc + 4)) - j;
					}
				}
			}
			// กรณีหาฟังก์ชันเจอแต่กู้ SSN ไม่ได้
			return -1;
		}
	}
	// กรณีวนลูปชื่อฟังก์ชันจนครบแล้วไม่เจอ
	return 0;
}

// Modular ของ Tartarus's Gate 
__forceinline DWORD getTartarusGateSSN(ULONG_PTR NtDllAddr, EXPORT_TABLES ntdllExports, PIMAGE_NT_HEADERS64 pNtHeader, const char* FuncName) {

	// ส่วน logic การหา .text สำหรับการเช็คขอบเขตของ Section ไม่ให้โปรแกรมเดินเลยจนเกิด Memory corruption
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);
	WORD NumberOfSection = pNtHeader->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER TextSection = { 0 };

	// logic ส่วนของเช็ค .text 
	for (WORD i = 0; i < NumberOfSection; i++) {

		if (ManualStrCmp((const char*)pSection[i].Name, ".text")) {
			TextSection = pSection[i];
		}
	}
	if (TextSection.VirtualAddress == 0) { return 0; }

	// TextStart ไว้ทำหรับกำหนด safety การเดินหา SSN เป้าหมายเพื่อบอกโปรแกรมว่าเป็นจุดเริ่มต้นจริงไหม
	// TextEnd ไว้กำหนดว่าจุดที่ต้องเดินหา SSN สิ้นสุดตรงไหน โดยอาศัยขนาดกำหนดขอบเขต
	PBYTE pTextStart = { 0 };
	PBYTE pTextEnd = { 0 };

	// Base Address + RVA ของ TextSection
	// Base Address + RVA ของ TextSection + ขนาดของ TextSection 
	pTextStart = reinterpret_cast<PBYTE>(NtDllAddr + TextSection.VirtualAddress);
	pTextEnd = reinterpret_cast<PBYTE>(NtDllAddr + TextSection.VirtualAddress + TextSection.Misc.VirtualSize);

	for (int i = 0; i < ntdllExports.dwNumberOfNames; i++) {

		// Base Address + AddressOfName ในดัชนีลำดับที่ n [i]
		auto szFuncName = reinterpret_cast<char*>(NtDllAddr + ntdllExports.pdwAddressOfNames[i]);

		// หาชื่อของ Native API นั้น เพื่อนำไปเปรียบเทียบหาเลข SSN
		if (ManualStrCmp(szFuncName, FuncName)) {

			WORD Ordinal = ntdllExports.pwAddressOfNameOrdinals[i];

			DWORD FuncRVA = ntdllExports.pdwAddressOfFunctions[Ordinal];

			ULONG_PTR FuncAddr = NtDllAddr + FuncRVA;

			// --- เริ่มต้น Tartarus's Gate Check ---
			// เข้าถึงตำแหน่งของ Section เพื่อทำการตรวจสอบว่าเป็นฟังก์ชัน Native API ที่เราหาไหม
			PBYTE pByteAddr = reinterpret_cast<PBYTE>(FuncAddr);
			if (pByteAddr == NULL) return -1;

			// ตรวจสอบ Pattern ว่าเป็น mov r10, rcx (4C 8B D1) และ mov eax, SSN (B8)
			if (pByteAddr[0] == 0x4C && pByteAddr[1] == 0x8B
				&& pByteAddr[2] == 0xD1 && pByteAddr[3] == 0xB8) {

				return *reinterpret_cast<PDWORD>(pByteAddr + 4);
			}
			// ไม่เจอ เริ่มส่วนของการเช็ค Neighbor SSN number
			// j เป็นลำดับการเดินการหา Function
			// การนำ i (ชื่อ Native API) -/+ j (ลำดับของ Native API) เป็นการหาลำดับที่แท้จริงเพื่อตรวจสอบเพื่อนบ้าน SSN แรกสุดที่โดน hook
			for (int j = 1; j < ntdllExports.pExportDir->NumberOfFunctions; j++) {

				// ตรวจหา Signature ของการ Hook
				// เช็คด้านบน Up
				// Up (i - j) เลื่อนรายชื่อขึ้นไปหาคนที่ชื่อมาก่อน(SSN ของเขาน้อยกว่าเรา)->เจอแล้วเอามา บวก j เพื่อดันค่าให้กลับมาเท่ากับตัวเรา
				if (i - j >= 0) {
					WORD upOrdinal = ntdllExports.pwAddressOfNameOrdinals[i - j];
					DWORD upRVA = ntdllExports.pdwAddressOfFunctions[upOrdinal];
					auto pUpFunc = reinterpret_cast<PBYTE>(NtDllAddr + upRVA);

					// เช็คจุดเริ่มต้นและจุดสิ้นสุดของ Native API ที่เราหา กรณีที่ไม่เจอเลยใน dll นั้น ๆ
					if (pUpFunc > pTextStart && pUpFunc < pTextEnd) {

						// เช็คหาว่า มี hook ไหม 0xE8 = CALL, 0xE9 = JMP, 
						// 0xFF 0x25 = JMP QWORD PTR [RIP+offset], 0x68 = PUSH, 0xC3 = RET
						bool upHoooked = pUpFunc[0] == 0xE8 || pUpFunc[0] == 0xE9
							|| (pUpFunc[0] == 0xFF && pUpFunc[1] == 0x25)
							|| pUpFunc[0] == 0x68 || pUpFunc[0] == 0xC3;

						if (!upHoooked) {

							// เช็คว่า มี pattern เป็นเลข SSN ไหม (mov r10, rcx และ mov eax, SSN)
							// และ มี pattern เป็น syscall และ ret ไหม
							if (pUpFunc[0] == 0x4C && pUpFunc[1] == 0x8B
								&& pUpFunc[2] == 0xD1 && pUpFunc[3] == 0xB8
								&& pUpFunc[18] == 0x0F && pUpFunc[19] == 0x05
								&& pUpFunc[20] == 0xC3) {

								// เช็ค Signature โดยครอบเอา SSN ที่หามา, + ด้วยจำนวนก้าวเพิ่อย้อนกลับไปหาเลข SSN จริง
								// แล้ว dereference เพื่อเอา SSN ไปใช้
								auto UpNeighborSSN = *reinterpret_cast<PDWORD>(pUpFunc + 4);
								DWORD expectedTarget = UpNeighborSSN + j;

								return expectedTarget;
							}
						}
					}
				}
				// เช็คด้านล่าง Down
				// Down (i + j) เลื่อนรายชื่อลงไปหาคนที่ชื่อมาทีหลัง (SSN ของเขามากกว่าเรา) -> เจอแล้วเอามา ลบ j เพื่อดึงค่าให้กลับมาเท่ากับตัวเรา
				// logic ใน if นี้คือถ้าเดินหา SSN, เช็ค hook และ Signature ไปจนมากกว่าจำนวนชื่อ Native API 
				// โปรแกรมจะหยุดเพื่อป้องกันไม่ให้เกิด memory corruption นั่นเอง
				if (i + j < ntdllExports.dwNumberOfNames) {
					WORD downOrdinal = ntdllExports.pwAddressOfNameOrdinals[i + j];
					DWORD downRVA = ntdllExports.pdwAddressOfFunctions[downOrdinal];
					auto pDownFunc = reinterpret_cast<PBYTE>(NtDllAddr + downRVA);

					// เช็คจุดเริ่มต้นและจุดสิ้นสุดของ Native API ที่เราหา กรณีที่ไม่เจอเลยใน dll นั้น ๆ
					if (pDownFunc > pTextStart && pDownFunc < pTextEnd) {

						// เช็คหาว่า มี hook ไหม 
						bool downHooked = pDownFunc[0] == 0xE8 || pDownFunc[0] == 0xE9
							|| (pDownFunc[0] == 0xFF && pDownFunc[1] == 0x25)
							|| pDownFunc[0] == 0x68 || pDownFunc[0] == 0xC3;

						if (!downHooked) {

							// เช็คว่า มี pattern เป็นเลข SSN, เป็น syscall และ ret ไหม
							if (pDownFunc[0] == 0x4C && pDownFunc[1] == 0x8B
								&& pDownFunc[2] == 0xD1 && pDownFunc[3] == 0xB8
								&& pDownFunc[18] == 0x0F && pDownFunc[19] == 0x05
								&& pDownFunc[20] == 0xC3) {

								// เช็ค Signature โดยครอบเอา SSN ที่หามา, - ด้วยจำนวนก้าวเพิ่อย้อนกลับไปหาเลข SSN จริง
								// แล้ว dereference เพื่อเอา SSN ไปใช้
								auto downNeighborSSN = *reinterpret_cast<PDWORD>(pDownFunc + 4);
								DWORD expectedTarget = downNeighborSSN - j;

								return expectedTarget;
							}
						}
					}
				}
			}
			// กรณีหาฟังก์ชันเจอแต่กู้ SSN ไม่ได้
			return -1;
		}
	}
	// กรณีวนลูปชื่อฟังก์ชันจนครบแล้วไม่เจอ
	return 0;
}

// Modular ของ FreshyCalls's Gate 
__forceinline DWORD getFreshyCallSSN(ULONG_PTR NtDllAddr, EXPORT_TABLES ntdllExports, const char* FuncName) {	

	Freshy_Entry SyscallTable[500];		// สร้าง struct เก็บชื่อและเลข SSN ที่ sorted แล้ว
	Freshy_Entry TempTable;				// struct ชั่วคราวสำหรับใช้ตอนย้ายเข้า SyscallTable
	int SyscallCount{ 0 };				// เอาไว้นับจำนวน Native API ในขั้นตอนค้นหา

	for (int i = 0; i < ntdllExports.dwNumberOfNames; i++) {

		// Base Address + AddressOfName ในดัชนีลำดับที่ n [i]
		// szFuncName มีรายชื่อ Function ทั้งหมดมาเก็บไว้แล้ว
		auto szFuncName = reinterpret_cast<char*>(NtDllAddr + ntdllExports.pdwAddressOfNames[i]);

		// เริ่มต้น Freshy Call SSN check
		PBYTE pByteAddr = reinterpret_cast<PBYTE>(szFuncName);
		if (pByteAddr == NULL) return -1;

			if ((pByteAddr[0] == 'Z' && pByteAddr[1] == 'w')) {

				WORD wOrdinal = ntdllExports.pwAddressOfNameOrdinals[i];

				DWORD dwFuncRVA = ntdllExports.pdwAddressOfFunctions[wOrdinal];

				ULONG_PTR uiFuncAddr = NtDllAddr + dwFuncRVA;

				SyscallTable[SyscallCount].FuncName = szFuncName;
				SyscallTable[SyscallCount].FuncAddress = uiFuncAddr;

				SyscallCount++;
			}
	}

	// - 1 เพื่อ ลดรอบการสลับ เช่น มี 10 ลำดับ (A-J แบบมั่วตำแหน่ง) สลับ J ไปท้ายสุดเสร็จ ก็ตัด J ออกจาก loop  
	// - i - 1 เพื่อลดรอบการสลับ และ ป้องกันเดินเลย memory 
	for (int i = 0; i < SyscallCount - 1; i++) {
		for (int j = 0; j < SyscallCount - i - 1; j++) {

			auto currentAddr = SyscallTable[j].FuncAddress;
			auto nextAddr = SyscallTable[j + 1].FuncAddress;

			if (currentAddr > nextAddr) {

				// A -> Temp
				TempTable = SyscallTable[j];

				// B -> A
				SyscallTable[j] = SyscallTable[j + 1];

				// Temp -> B
				SyscallTable[j + 1] = TempTable;
			}
		}
	}
	for (int i = 0; i < SyscallCount; i++) {
		if (ManualStrCmp((const char*)SyscallTable[i].FuncName + 2, FuncName + 2)) {

			return i;
		}
	}
	return 0;
}