#include "OperationLocateText.h"
#include "InputOutput.h"
#include "Helpers.h"

#include <sstream>

ClassFactory<OperationLocateText> OperationLocateText::RegisteredFactory(GetCommand());

OperationLocateText::OperationLocateText(std::queue<std::wstring>& oArgList, const std::wstring& sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	const std::vector<std::wstring> sReportFile = ProcessAndCheckArgs(1, oArgList, L"\\0");
	const std::vector<std::wstring> sMatchAndArgs = ProcessAndCheckArgs(2, oArgList);

	HANDLE hFile = CreateFile(sReportFile.at(0).c_str(), GENERIC_WRITE,
		FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		Print(L"ERROR: Could not create file '{}' specified for parameter '{}'.", sReportFile.at(0), GetCommand());
		std::exit(-1);
	}

	hReportFile = RegisterFileHandle(hFile, GetCommand());

	if (hFile == hReportFile)
	{
		constexpr BYTE hHeader[] = { 0xEF,0xBB,0xBF };
		DWORD iBytes = 0;
		if (WriteFile(hFile, &hHeader, _countof(hHeader), &iBytes, nullptr) == 0)
		{
			Print(L"ERROR: Could not write out file type marker '{}'.", GetCommand());
			std::exit(-1);
		}

		// if this is the first handle using this file, write out a header
		if (WriteToFile(OutToCsv(L"Path", L"Line Number", L"Matched Line"), hReportFile) == 0)
		{
			Print(L"ERROR: Could not write header to report file for parameter '{}'.", GetCommand());
			std::exit(-1);
		}
	}

	AppliesToObject = true;

	try
	{
		tFileRegex = std::wregex(sMatchAndArgs.at(0), std::wregex::icase | std::wregex::optimize);
		tTextRegex = std::wregex(sMatchAndArgs.at(1), std::wregex::icase | std::wregex::optimize);
	}
	catch (const std::regex_error&)
	{
		Print(L"ERROR: Invalid regular expression specified for parameter '{}'.", GetCommand());
		std::exit(-1);
	}
}

void OperationLocateText::ProcessObjectAction(ObjectEntry& tObjectEntry)
{
	if (IsDirectory(tObjectEntry.Attributes)) return;

	const WCHAR* sFileName = tObjectEntry.Name.c_str();
	const WCHAR* sLastSep = wcsrchr(sFileName, L'\\');
	if (sLastSep != nullptr) sFileName = sLastSep + 1;
	if (!std::regex_match(sFileName, tFileRegex)) return;

	thread_local std::vector<char> tReadBuffer(64 * 1024);

	SmartPointer<HANDLE> hFile(CloseHandle, CreateFile(tObjectEntry.Name.c_str(), GENERIC_READ,
		FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
	if (!hFile.IsValid())
	{
		InputOutput::AddError(L"Unable to open file for reading.");
		return;
	}

	std::string sRawContent;
	DWORD iBytesRead = 0;
	while (ReadFile(hFile, tReadBuffer.data(), static_cast<DWORD>(tReadBuffer.size()), &iBytesRead, nullptr) != 0 && iBytesRead > 0)
	{
		sRawContent.append(tReadBuffer.data(), iBytesRead);
	}

	if (sRawContent.empty()) return;

	std::wstring sContent;
	const auto* pRaw = reinterpret_cast<const unsigned char*>(sRawContent.data());
	if (sRawContent.size() >= 2 && pRaw[0] == 0xFF && pRaw[1] == 0xFE)
	{
		sContent.assign(reinterpret_cast<const wchar_t*>(sRawContent.data() + 2),
			(sRawContent.size() - 2) / sizeof(wchar_t));
	}
	else
	{
		int iOffset = 0;
		if (sRawContent.size() >= 3 && pRaw[0] == 0xEF && pRaw[1] == 0xBB && pRaw[2] == 0xBF)
			iOffset = 3;

		const int iLen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
			sRawContent.data() + iOffset, static_cast<int>(sRawContent.size() - iOffset), nullptr, 0);
		if (iLen > 0)
		{
			sContent.resize(iLen);
			MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
				sRawContent.data() + iOffset, static_cast<int>(sRawContent.size() - iOffset),
				sContent.data(), iLen);
		}
		else
		{
			const int iAnsiLen = MultiByteToWideChar(CP_ACP, 0,
				sRawContent.data() + iOffset, static_cast<int>(sRawContent.size() - iOffset), nullptr, 0);
			if (iAnsiLen > 0)
			{
				sContent.resize(iAnsiLen);
				MultiByteToWideChar(CP_ACP, 0,
					sRawContent.data() + iOffset, static_cast<int>(sRawContent.size() - iOffset),
					sContent.data(), iAnsiLen);
			}
		}
	}

	std::wistringstream oStream(sContent);
	std::wstring sLine;
	LONGLONG iLineNumber = 0;
	while (std::getline(oStream, sLine))
	{
		++iLineNumber;
		if (!sLine.empty() && sLine.back() == L'\r') sLine.pop_back();
		if (!std::regex_search(sLine, tTextRegex)) continue;

		if (WriteToFile(OutToCsv(tObjectEntry.Name, std::to_wstring(iLineNumber), sLine), hReportFile) == 0)
		{
			InputOutput::AddError(L"Unable to write information to report file.");
		}
	}
}