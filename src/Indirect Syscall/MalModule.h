#include "Def.h"

__forceinline BOOL IsNtDll(PWSTR dllName) {
	if (dllName == nullptr) {
		return false;
	}

	wchar_t ntdll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', 0 };

	int i = 0;
	while (dllName[i] != L'\0' && ntdll[i] != L'\0') {
		wchar_t c1 = dllName[i];
		wchar_t c2 = ntdll[i];

		if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
		if (c2 >= L'A' && c2 <= L'Z') c2 += 32;

		if (c1 != c2) { return false; }
		i++;
	}

	return (dllName[i] == L'\0' && ntdll[i] == L'\0');
}

__forceinline BOOL ManualStrCmp(const char* s1, const char* s2) {
	while (*s1 && (*s1 == *s2)) {
		s1++; s2++;
	}
	return *(unsigned char*)s1 - *(unsigned char*)s2 == 0;
}

__forceinline ULONG_PTR getNtdllBase() {

	ULONG_PTR pebAddr = __readgsqword(0x60);

	auto LdrAddr = *reinterpret_cast<ULONG_PTR*>(pebAddr + 0x18);

	auto Head = reinterpret_cast<LIST_ENTRY*>(LdrAddr + 0x20);
	LIST_ENTRY* current = Head->Flink;

	while (current != Head) {
		auto pEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY_CUSTOM>(
			(PBYTE)current - 0x10);

		if (pEntry->BaseDllName.pBuffer != NULL) {
			if (IsNtDll(pEntry->BaseDllName.pBuffer)) {
				return reinterpret_cast<ULONG_PTR>(pEntry->DllBase);
			}
		}
		current = current->Flink;
	}
	return 0;
}

__forceinline PIMAGE_NT_HEADERS64 getNtHeader(ULONG_PTR NtDllAddr) {

	auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(NtDllAddr);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		cout << "Error: Not a valid DOS Header at the base!" << endl;
	}
	else {
		cout << "pDosHeader is at : " << hex << pDosHeader << endl;
	}

	auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(pDosHeader->e_lfanew + NtDllAddr);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		cout << "Error: Not a valid NT Header signature!" << endl;
	}
	return pNtHeader;
}

__forceinline BOOL getExportTables(ULONG_PTR uiBaseAddr, PIMAGE_NT_HEADERS64 pNtHeader, PEXPORT_TABLES pOutTables) {
	if (!pNtHeader || !pOutTables) return false;

	DWORD exportDirRVA = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportDirRVA == 0) return false;

	pOutTables->pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiBaseAddr + exportDirRVA);

	pOutTables->pdwAddressOfNames = reinterpret_cast<PDWORD>(uiBaseAddr + pOutTables->pExportDir->AddressOfNames);
	pOutTables->pwAddressOfNameOrdinals = reinterpret_cast<PWORD>(uiBaseAddr + pOutTables->pExportDir->AddressOfNameOrdinals);
	pOutTables->pdwAddressOfFunctions = reinterpret_cast<PDWORD>(uiBaseAddr + pOutTables->pExportDir->AddressOfFunctions);
	pOutTables->dwNumberOfNames = pOutTables->pExportDir->NumberOfNames;

	return true;
}

__forceinline ULONG_PTR findGadget(PIMAGE_NT_HEADERS64 pNtHeader, ULONG_PTR uiNtDllAddr) {
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);
	WORD NumberOfSection = pNtHeader->FileHeader.NumberOfSections;

	for (WORD i = 0; i < NumberOfSection; i++) {

		if (ManualStrCmp((const char*)pSection[i].Name, ".text")) {

			auto pStart = reinterpret_cast<PBYTE>(uiNtDllAddr + pSection[i].VirtualAddress);
			DWORD dwSize = pSection[i].Misc.VirtualSize;

			// หาคำว่า syscall;(0F, 05) และ ret (C3)
			for (DWORD j = 0; j < dwSize - 2; j++) {
				if (pStart[j] == 0x0F && pStart[j + 1] == 0x05 && pStart[j + 2] == 0xC3) {

					return reinterpret_cast<ULONG_PTR>(&pStart[j]);
				}
			}
		}
	}
	return 0;
}