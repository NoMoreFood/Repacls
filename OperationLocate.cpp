#include "OperationLocate.h"
#include "InputOutput.h"
#include "Helpers.h"

ClassFactory<OperationLocate> OperationLocate::RegisteredFactory(GetCommand());

OperationLocate::OperationLocate(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	const std::vector<std::wstring> sReportFile = ProcessAndCheckArgs(1, oArgList, L"\\0");
	const std::vector<std::wstring> sMatchAndArgs = ProcessAndCheckArgs(1, oArgList, L"\\0");

	// fetch params
	HANDLE hFile = CreateFile(sReportFile.at(0).c_str(), GENERIC_WRITE,
		FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	// see if names could be resolved
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// complain
		Print(L"ERROR: Could not create file '{}' specified for parameter '{}'.", sReportFile.at(0), GetCommand());
		std::exit(-1);
	}

	// register the file handle
	hReportFile = RegisterFileHandle(hFile, GetCommand());

	// if this is the first handle using this file, write out a header
	if (hFile == hReportFile)
	{
		// write out the file type marker
		constexpr BYTE hHeader[] = { 0xEF,0xBB,0xBF };
		DWORD iBytes = 0;
		if (WriteFile(hFile, &hHeader, _countof(hHeader), &iBytes, nullptr) == 0)
		{
			Print(L"ERROR: Could not write out file type marker '{}'.", GetCommand());
			std::exit(-1);
		}

		// write out the header
		if (WriteToFile(OutToCsv(L"Path", L"Creation Time", L"Modified Time",
			L"Size", L"Attributes", L"Object Type"), hReportFile) == 0)
		{
			Print(L"ERROR: Could not write header to report file for parameter '{}'.", GetCommand());
			std::exit(-1);
		}
	}

	// only flag this to apply to the core object with the file name
	AppliesToObject = true;

	// compile the regular expression
	try
	{
		tRegex = std::wregex(sMatchAndArgs.at(0), std::wregex::icase | std::wregex::optimize);
	}
	catch (const std::regex_error &)
	{
		Print(L"ERROR: Invalid regular expression '{}' specified for parameter '{}'.", sMatchAndArgs.at(0), GetCommand());
		std::exit(-1);
	}
}

void OperationLocate::ProcessObjectAction(ObjectEntry & tObjectEntry)
{
	// skip any file names that do not match the regex
	const WCHAR * sFileName = tObjectEntry.Name.c_str();
	if (wcsrchr(sFileName, '\\') != nullptr) sFileName = wcsrchr(sFileName, '\\') + 1;
	if (!std::regex_match(sFileName, tRegex)) return;

	// get common file attributes
	const std::wstring sSize = FileSizeToString(tObjectEntry.FileSize);
	const std::wstring sAttributes = FileAttributesToString(tObjectEntry.Attributes);
	const std::wstring sModifiedTime = FileTimeToString(tObjectEntry.ModifiedTime);
	const std::wstring sCreationTime = FileTimeToString(tObjectEntry.CreationTime);
	const std::wstring sType = (tObjectEntry.Attributes & FILE_ATTRIBUTE_DIRECTORY) ? L"Container" : L"Leaf";

	// write the string to a file
	if (WriteToFile(OutToCsv(tObjectEntry.Name, sCreationTime, sModifiedTime,
		sSize, sAttributes, sType).c_str(), hReportFile) == 0)
	{
		InputOutput::AddError(L"Unable to write security information to report file.");
	}
}