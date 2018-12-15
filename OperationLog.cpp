#include "OperationLog.h"
#include "InputOutput.h"
#include "Functions.h"

#include <fstream>
#include <iostream>
#include <locale>
#include <codecvt>

ClassFactory<OperationLog> * OperationLog::RegisteredFactory =
new ClassFactory<OperationLog>(GetCommand());

#define Q(x) L"\"" + (x) + L"\""

HANDLE OperationLog::hLogHandle = INVALID_HANDLE_VALUE;

OperationLog::OperationLog(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sLogFile = ProcessAndCheckArgs(1, oArgList, L"\\0");

	// exit immediately if command had already been called
	if (hLogHandle != INVALID_HANDLE_VALUE)
	{
		wprintf(L"ERROR: %s cannot be specified more than once.", GetCommand().c_str());
		exit(-1);
	}

	// fetch params
	hLogHandle = CreateFile(sLogFile[0].c_str(), GENERIC_WRITE,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// write out the file type marker
	const BYTE hHeader[] = { 0xEF,0xBB,0xBF };
	DWORD iBytes = 0;
	if (WriteFile(hLogHandle, &hHeader, _countof(hHeader), &iBytes, NULL) == 0)
	{
		wprintf(L"ERROR: Could not write out file type marker '%s'.\n", GetCommand().c_str());
		exit(-1);
	}

	// write out the header
	std::wstring sToWrite = std::wstring(L"") + Q(L"Time") + L"," + Q(L"Type") + L"," + Q(L"Path") + L"," + Q(L"Message") + L"\r\n";
	if (WriteToFile(sToWrite, hLogHandle) == 0)
	{
		wprintf(L"ERROR: Could not write header to log file for parameter '%s'.\n", GetCommand().c_str());
		exit(-1);
	}

	// enable input/output routines to try to log data using this class
	InputOutput::Log() = true;
}

void OperationLog::LogFileItem(const std::wstring & sInfoLevel, const std::wstring & sPath, const std::wstring & sMessage)
{
	// sanity check
	if (hLogHandle == INVALID_HANDLE_VALUE) return;

	// get time string
	WCHAR sDate[20];
	const __time64_t tUtcTime = _time64(NULL);
	struct tm tLocalTime;
	_localtime64_s(&tLocalTime, &tUtcTime);
	wcsftime(sDate, _countof(sDate), L"%Y-%m-%d %H:%M:%S", &tLocalTime);

	// write out information
	std::wstring sToWrite = std::wstring(L"") + Q(sDate) + L"," + Q(sInfoLevel) + L"," + Q(sPath) + L"," + Q(sMessage) + L"\r\n";
	if (WriteToFile(sToWrite, hLogHandle) == 0)
	{
		wprintf(L"ERROR: Could not write data to log file for parameter '%s'.\n", GetCommand().c_str());
		exit(-1);
	}
}