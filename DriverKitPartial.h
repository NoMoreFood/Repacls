#pragma once

#include <Windows.h>
#include <winternl.h>

#pragma comment(lib,"ntdll.lib")

typedef struct _PRELATIVE_NAME
{
	UNICODE_STRING Name;
	HANDLE CurrentDir;
} PRELATIVE_NAME, *PPRELATIVE_NAME;

typedef struct _FILE_DIRECTORY_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	WCHAR         FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef NTSTATUS(WINAPI *RTLDOSPATHNAMETONTPATHNAME_U)(PCWSTR DosPathName, PUNICODE_STRING NtPathName, PWSTR* FilePathInNtPathName, PRELATIVE_NAME* RelativeName);
typedef NTSTATUS(WINAPI *NTQUERYDIRECTORYFILE)(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);

static HMODULE hRtlLoadLibrary = LoadLibrary(L"ntdll.dll");
static RTLDOSPATHNAMETONTPATHNAME_U RtlDosPathNameToNtPathName_U = (RTLDOSPATHNAMETONTPATHNAME_U)GetProcAddress(hRtlLoadLibrary, "RtlDosPathNameToNtPathName_U");
static NTQUERYDIRECTORYFILE NtQueryDirectoryFile = (NTQUERYDIRECTORYFILE)GetProcAddress(hRtlLoadLibrary, "NtQueryDirectoryFile");