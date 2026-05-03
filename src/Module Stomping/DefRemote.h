#pragma once
#pragma once
#include <windows.h>
#include <iostream>
#include <cstdint>
#include <TlHelp32.h>

using namespace std;

#define NTSTATUS LONG
#define NTAPI __stdcall
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

struct ExtractVictimBoxDetail {
	PBYTE VictimBox;
	DWORD SizeOfBox;
};

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PSECURITY_DESCRIPTOR SecurityDescriptor;
	PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(WINAPI* pNtOpenProcess)(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
	);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtect,
	PULONG OldProtect
	);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToWrite,
	PSIZE_T NumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToRead,
	PSIZE_T NumberOfBytesRead
	);