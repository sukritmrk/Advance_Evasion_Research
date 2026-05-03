#pragma once
#include "DefRemote.h"

__forceinline DWORD static GetPIDByName(const wchar_t* targetName, HANDLE hSnapshot) {
	DWORD pid = 0;

	PROCESSENTRY32W pe = { 0 };
	pe.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(hSnapshot, &pe)) {
		do {
			if (_wcsicmp(pe.szExeFile, targetName) == 0) {
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32NextW(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot);
	return pid;
}

__forceinline BOOL ManualStrCmp(const char* s1, const char* s2) {
	while (*s1 && (*s1 == *s2)) {
		s1++; s2++;
	}
	return *(unsigned char*)s1 - *(unsigned char*)s2 == 0;
}

__forceinline PIMAGE_NT_HEADERS64 getNtDll(HMODULE victimDll) {

	auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(victimDll);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		cout << "Error: Not a valid DOS Header at the base!" << endl;
	}
	else {
		cout << "pDosHeader is at : " << hex << pDosHeader << endl;
	}

	auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>((PBYTE)victimDll + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		cout << "Error: Not a valid NT Header signature!" << endl;
	}
	else {
		return pNtHeader;
	}
}

__forceinline DWORD findTextSection(PIMAGE_NT_HEADERS64 pNtHeader, HMODULE victimDll, ExtractVictimBoxDetail& VictimBox) {

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);
	WORD NumberOfSection = pNtHeader->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER TextSection = { 0 };

	// logic ส่วนของเช็ค .text 
	for (WORD i = 0; i < NumberOfSection; i++) {

		if (ManualStrCmp((const char*)pSection[i].Name, ".text")) {
			TextSection = pSection[i];

			if (TextSection.VirtualAddress == 0) { return 0; }
		}
	}

	VictimBox.VictimBox = reinterpret_cast<PBYTE>(victimDll) + TextSection.VirtualAddress;
	VictimBox.SizeOfBox = TextSection.Misc.VirtualSize;
}