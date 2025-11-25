#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#include "InputOutput.h"
#include "ObjectFile.h"
#include "DriverKitPartial.h"
#include "OperationDepth.h"

void ObjectFile::GetBaseObject(std::wstring sPath)
{
	// make a local copy of the path since we may have to alter it
	// handle special case where a drive root is specified
	// we must ensure it takes the form x:\. to resolve correctly
	const size_t iSemiColon = sPath.rfind(L':');
	if (iSemiColon != std::wstring::npos)
	{
		const std::wstring sEnd = std::wstring(sPath).substr(iSemiColon);
		if (sEnd == L":" || sEnd == L":\\")
		{
			sPath = std::wstring(sPath.substr(0, iSemiColon)) + L":\\.";
		}
	}

	// convert the path to a long path that is compatible with the other call
	UNICODE_STRING tPathU;
	RtlDosPathNameToNtPathName_U(sPath.data(), &tPathU, nullptr, nullptr);

	// to get the process started, we need to have one entry so
	// we will set that to the passed argument
	ObjectEntry oEntryFirst;

	// copy it to a null terminated string
	oEntryFirst.Name = std::wstring(tPathU.Buffer, tPathU.Length / sizeof(WCHAR));

	// get common file attributes
	WIN32_FILE_ATTRIBUTE_DATA tData;
	GetFileAttributesExW(oEntryFirst.Name.c_str(), GetFileExInfoStandard, &tData);
	oEntryFirst.Depth = 0;
	oEntryFirst.ObjectType = SE_FILE_OBJECT;
	oEntryFirst.FileSize = { { tData.nFileSizeLow, static_cast<LONG>(tData.nFileSizeHigh) } };
	oEntryFirst.Attributes = tData.dwFileAttributes;
	oEntryFirst.CreationTime = tData.ftCreationTime;
	oEntryFirst.ModifiedTime = tData.ftLastWriteTime;

	// free the buffer returned previously
	RtlFreeUnicodeString(&tPathU);

	oProcessor.GetQueue().Push(oEntryFirst);
}

void ObjectFile::GetChildObjects(ObjectEntry& oEntry)
{
	// break out if entry flags a termination
	if (oEntry.Name.empty()) return;

	// skip if hidden and system
	if (oEntry.Depth == 0 && IsHiddenSystem(oEntry.Attributes)
		&& InputOutput::ExcludeHiddenSystem())
	{
		Processor::CompleteEntry(oEntry);
		return;
	}

	// do security analysis
	oProcessor.AnalyzeSecurity(oEntry);

	// stop processing if not a directory
	if (!IsDirectory(oEntry.Attributes))
	{
		Processor::CompleteEntry(oEntry);
		return;
	}

	// construct a string that can be used in the rtl apis
	UNICODE_STRING tPathU = { static_cast<USHORT>(oEntry.Name.size() * sizeof(WCHAR)),
		static_cast<USHORT>(oEntry.Name.size() * sizeof(WCHAR)),oEntry.Name.data() };

	// update object attributes object
	OBJECT_ATTRIBUTES oAttributes;
	InitializeObjectAttributes(&oAttributes, nullptr, OBJ_CASE_INSENSITIVE, nullptr, nullptr)
	oAttributes.ObjectName = &tPathU;

	// get an open file handle
	HANDLE hFindFile;
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS Status = NtOpenFile(&hFindFile, FILE_LIST_DIRECTORY | SYNCHRONIZE,
		&oAttributes, &IoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT |
		((oEntry.Depth == 0) ? 0 : FILE_OPEN_REPARSE_POINT));

	if (Status == STATUS_ACCESS_DENIED)
	{
		InputOutput::AddError(L"Access denied error occurred while enumerating directory");
		Processor::CompleteEntry(oEntry);
		++oProcessor.ItemsEnumerationFailures;
		return;
	}
	else if (Status == STATUS_OBJECT_PATH_NOT_FOUND ||
		Status == STATUS_OBJECT_NAME_NOT_FOUND)
	{
		InputOutput::AddError(L"Path not found error occurred while enumerating directory");
		Processor::CompleteEntry(oEntry);
		++oProcessor.ItemsEnumerationFailures;
		return;
	}
	else if (Status != STATUS_SUCCESS)
	{
		InputOutput::AddError(L"Unknown error occurred while enumerating directory");
		Processor::CompleteEntry(oEntry);
		++oProcessor.ItemsEnumerationFailures;
		return;
	}

	// enumerate files in the directory
	for (bool bFirstRun = true; true; bFirstRun = false)
	{
		thread_local BYTE DirectoryInfo[MAX_DIRECTORY_BUFFER];
		Status = NtQueryDirectoryFile(hFindFile, nullptr, nullptr, nullptr, &IoStatusBlock,
		                              DirectoryInfo, MAX_DIRECTORY_BUFFER, static_cast<FILE_INFORMATION_CLASS>(FileDirectoryInformation),
		                              FALSE, nullptr, (bFirstRun) ? TRUE : FALSE);

		// done processing
		if (Status == STATUS_NO_MORE_FILES) break;

		if (Status != 0)
		{
			InputOutput::AddError(L"An error occurred while enumerating items in the directory");
			break;
		}

		for (FILE_DIRECTORY_INFORMATION* oInfo = (FILE_DIRECTORY_INFORMATION*)DirectoryInfo;
			oInfo != nullptr; oInfo = (FILE_DIRECTORY_INFORMATION*)((BYTE*)oInfo + oInfo->NextEntryOffset))
		{
			// continue immediately if we get the '.' or '..' entries
			if (IsDirectory(oInfo->FileAttributes))
			{
				if (((oInfo->FileNameLength == 2 * sizeof(WCHAR)) && memcmp(oInfo->FileName, L"..", 2 * sizeof(WCHAR)) == 0) ||
					((oInfo->FileNameLength == 1 * sizeof(WCHAR)) && memcmp(oInfo->FileName, L".", 1 * sizeof(WCHAR)) == 0))
				{
					if (oInfo->NextEntryOffset == 0) break; else continue;
				}
			}

			// construct the entry
			ObjectEntry oSubEntry;
			oSubEntry.Depth = oEntry.Depth + 1;
			oSubEntry.ObjectType = SE_FILE_OBJECT;
			oSubEntry.FileSize = { { oInfo->EndOfFile.LowPart, oInfo->EndOfFile.HighPart } };
			oSubEntry.Attributes = oInfo->FileAttributes;
			oSubEntry.CreationTime = { oInfo->CreationTime.LowPart, static_cast<DWORD>(oInfo->CreationTime.HighPart) };
			oSubEntry.ModifiedTime = { oInfo->LastWriteTime.LowPart, static_cast<DWORD>(oInfo->LastWriteTime.HighPart) };
			oSubEntry.Name += oEntry.Name + ((oEntry.Depth == 0 && oEntry.Name.back() == '\\') ? L"" : L"\\")
				+ std::wstring(oInfo->FileName, oInfo->FileNameLength / sizeof(WCHAR));

			// if a leaf object, just process immediately and don't worry about putting it on the queue
			if (!IsDirectory(oSubEntry.Attributes) || IsReparsePoint(oSubEntry.Attributes))
			{
				// for performance do security analysis immediately instead of addiing to queue
				if (oEntry.Depth <= OperationDepth::MaxDepth())
				{
					oProcessor.AnalyzeSecurity(oSubEntry);
					Processor::CompleteEntry(oSubEntry);
				}
			}
			else
			{
				oProcessor.GetQueue().Push(oSubEntry);
			}

			// this loop is complete, exit
			if (oInfo->NextEntryOffset == 0) break;
		}
	}

	// cleanup
	NtClose(hFindFile);
	Processor::CompleteEntry(oEntry);

}
