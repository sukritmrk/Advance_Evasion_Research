#pragma once
#include <Windows.h>
#include <iostream>

using namespace std;

#define NTSTATUS LONG
#define NTAPI __stdcall

typedef struct _UNICODE_STR {
	USHORT Length;
	USHORT MaximumLength;
	ULONG Padding;
	PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

typedef struct _LDR_DATA_TABLE_ENTRY_CUSTOM {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID      DllBase;
	PVOID      EntryPoint;
	ULONG      SizeOfImage;
	UNICODE_STR FullDllName;
	UNICODE_STR BaseDllName;
} LDR_DATA_TABLE_ENTRY_CUSTOM, * PLDR_DATA_TABLE_ENTRY_CUSTOM;

typedef struct _EXPORT_TABLES {
	PIMAGE_EXPORT_DIRECTORY pExportDir;
	PDWORD pdwAddressOfNames;
	PWORD  pwAddressOfNameOrdinals;
	PDWORD pdwAddressOfFunctions;
	DWORD  dwNumberOfNames;
} EXPORT_TABLES, * PEXPORT_TABLES;

struct GadgetDetail {
	PBYTE VA;
	DWORD SizeOfRawData;
};

// Struct ของการทำ Freshy Call
struct Freshy_Entry {
	char* FuncName;
	DWORD FuncAddress;
};

// --- Function Prototypes ---

BOOL ManualStrCmp(const char* s1, const char* s2);
BOOL IsNtDll(PWSTR dllName);
ULONG_PTR getNtdllBase();
PIMAGE_NT_HEADERS64 getNtHeader(ULONG_PTR NtDllAddr);
BOOL findTextSection(PIMAGE_NT_HEADERS64 pNtHeader, ULONG_PTR BaseAddr, GadgetDetail& findGadgetBox);
PBYTE findGadget(GadgetDetail& findGadgetBox);
BOOL getExportTables(ULONG_PTR uiBaseAddr, PIMAGE_NT_HEADERS64 pNtHeader, PEXPORT_TABLES pOutTables);

// --- Stub Assembly ---