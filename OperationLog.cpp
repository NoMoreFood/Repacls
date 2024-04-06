#include "OperationLog.h"
#include "InputOutput.h"
#include "Helpers.h"

#include <locale>

ClassFactory<OperationLog> OperationLog::RegisteredFactory(GetCommand());

#define Q(x) L"\"" + (x) + L"\""

HANDLE OperationLog::hLogHandle = INVALID_HANDLE_VALUE;

OperationLog::OperationLog(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	const std::vector<std::wstring> sLogFile = ProcessAndCheckArgs(1, oArgList, L"\\0");

	// exit immediately if command had already been called
	if (hLogHandle != INVALID_HANDLE_VALUE)
	{
		wprintf(L"ERROR: %s cannot be specified more than once.", GetCommand().c_str());
		std::exit(-1);
	}

	// fetch params
	hLogHandle = CreateFile(sLogFile.at(0).c_str(), GENERIC_WRITE,
		FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	// write out the file type marker
	constexpr BYTE hHeader[] = { 0xEF,0xBB,0xBF };
	DWORD iBytes = 0;
	if (WriteFile(hLogHandle, &hHeader, _countof(hHeader), &iBytes, nullptr) == 0)
	{
		wprintf(L"ERROR: Could not write out file type marker '%s'.\n", GetCommand().c_str());
		std::exit(-1);
	}

	// write out the header
	const std::wstring sToWrite = std::wstring(L"") + Q(L"Time") + L"," + Q(L"Type") + L"," + Q(L"Path") + L"," + Q(L"Message") + L"\r\n";
	if (WriteToFile(sToWrite, hLogHandle) == 0)
	{
		wprintf(L"ERROR: Could not write header to log file for parameter '%s'.\n", GetCommand().c_str());
		std::exit(-1);
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
	const __time64_t tUtcTime = _time64(nullptr);
	tm tLocalTime;
	_localtime64_s(&tLocalTime, &tUtcTime);
	std::ignore = wcsftime(sDate, _countof(sDate), L"%Y-%m-%d %H:%M:%S", &tLocalTime);

	// write out information
	const std::wstring sToWrite = std::wstring(L"") + Q(sDate) + L"," + Q(sInfoLevel) + L"," + Q(sPath) + L"," + Q(sMessage) + L"\r\n";
	if (WriteToFile(sToWrite, hLogHandle) == 0)
	{
		wprintf(L"ERROR: Could not write data to log file for parameter '%s'.\n", GetCommand().c_str());
		std::exit(-1);
	}
}