#include "OperationRemoveStreams.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationRemoveStreams> OperationRemoveStreams::RegisteredFactory(GetCommand());

OperationRemoveStreams::OperationRemoveStreams(std::queue<std::wstring>& oArgList, const std::wstring& sCommand) : Operation(oArgList)
{

	// load function pointer to query file information
	HMODULE hModule = GetModuleHandle(L"ntdll.dll");
	if (hModule == NULL || (NtQueryInformationFile = (decltype(NtQueryInformationFile)) 
		GetProcAddress(hModule, "NtQueryInformationFile")) == NULL)
	{
		wprintf(L"ERROR: Unable to obtain function pointer in parameter '%s'.\n", GetCommand().c_str());
		exit(-1);
	}

	// only flag this to apply to the core object with the file name
	AppliesToObject = true;
}

void OperationRemoveStreams::ProcessObjectAction(ObjectEntry& tObjectEntry)
{
	HANDLE hFile = CreateFile(tObjectEntry.Name.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		InputOutput::AddError(L"Unable open file for stream deletion.");
		return;
	}

	// loop until we can fill the stream into a buffer
	NTSTATUS iStatus;
	thread_local std::vector<BYTE> sInfoBuffer(16 * 1024, 0);
	for (iStatus = STATUS_BUFFER_OVERFLOW; iStatus == STATUS_BUFFER_OVERFLOW;
		sInfoBuffer.resize(sInfoBuffer.size() * 2, 0))
	{
		IO_STATUS_BLOCK tIOStatus = {};
		iStatus = NtQueryInformationFile(hFile, &tIOStatus, sInfoBuffer.data(), (ULONG) sInfoBuffer.size(), FileStreamInformation);
		if (iStatus == STATUS_SUCCESS) break;
	}

	// cleanup and verify we got the data we needed
	CloseHandle(hFile);
	if (iStatus != STATUS_SUCCESS) return;

	// Loop for all streams
	for (PFILE_STREAM_INFORMATION pStreamInfo = (PFILE_STREAM_INFORMATION)sInfoBuffer.data(); pStreamInfo->StreamNameLength != 0;
		pStreamInfo = (PFILE_STREAM_INFORMATION)((LPBYTE)pStreamInfo + pStreamInfo->NextEntryOffset))
	{
		// skip main data stream
		const WCHAR sData[] = L"::$DATA";
		if (_countof(sData) - 1 == pStreamInfo->StreamNameLength / sizeof(WCHAR) &&
			_wcsnicmp(pStreamInfo->StreamName, sData, _countof(sData) - 1) == 0)
		{
			if (pStreamInfo->NextEntryOffset == 0) break;
			continue;
		}

		// remove the stream
		std::wstring sStream((const wchar_t *) pStreamInfo->StreamName, (size_t) (pStreamInfo->StreamNameLength / sizeof(WCHAR)));
		std::wstring sFullStreamName = (tObjectEntry.Name + sStream);
		if (InputOutput::InWhatIfMode() || (SetFileAttributes(sFullStreamName.c_str(), FILE_ATTRIBUTE_NORMAL) != 0 && DeleteFile(sFullStreamName.c_str()) != 0))
		{
			InputOutput::AddInfo(L"Removed stream: " + sStream, L"");
		}
		else
		{
			InputOutput::AddError(L"Unable delete stream: " + sStream); 
		}

		// break if no next stream
		if (pStreamInfo->NextEntryOffset == 0) break;
	}
}