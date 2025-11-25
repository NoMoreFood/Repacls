#pragma once

#include <regex>

#include "Operation.h"

class OperationRemoveStreams final : public Operation
{

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"RemoveStreams"; }
	static std::wstring GetCommandByName() { return L"RemoveStreamsByName"; }
	static ClassFactory<OperationRemoveStreams> RegisteredFactory;
	static ClassFactory<OperationRemoveStreams> RegisteredFactoryByName;

	// operation specific
	std::wregex tRegex;

	//
	// Definitions below avoid need to install Windows Driver Development Kit
	//

	typedef struct _IO_STATUS_BLOCK {
		union {
			NTSTATUS Status;
			PVOID    Pointer;
		};
		ULONG_PTR Information;
	} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

	typedef enum _FILE_INFORMATION_CLASS {
		FileStreamInformation = 22
	} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

	#pragma pack(push, 4)
	typedef struct _FILE_STREAM_INFORMATION { // Information Class 22
		ULONG NextEntryOffset;
		ULONG StreamNameLength;
		LARGE_INTEGER EndOfStream;
		LARGE_INTEGER AllocationSize;
		WCHAR StreamName[1];
	} FILE_STREAM_INFORMATION, * PFILE_STREAM_INFORMATION;
	#pragma pack(pop)

	typedef NTSTATUS(NTAPI* NTQUERYINFORMATIONFILE)(
		IN HANDLE FileHandle,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		OUT PVOID FileInformation,
		IN ULONG Length,
		IN FILE_INFORMATION_CLASS FileInformationClass);

	NTQUERYINFORMATIONFILE NtQueryInformationFile;

public:

	// overrides
	void ProcessObjectAction(ObjectEntry & tObjectEntry) override;

	// constructors
	OperationRemoveStreams(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};