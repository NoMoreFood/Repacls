#include "OperationLocateText.h"
#include "InputOutput.h"
#include "Helpers.h"

#include <climits>
#include <string_view>

ClassFactory<OperationLocateText> OperationLocateText::RegisteredFactory(GetCommand());

OperationLocateText::OperationLocateText(std::queue<std::wstring>& oArgList, const std::wstring& sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	const std::vector<std::wstring> sReportFile = ProcessAndCheckArgs(1, oArgList, L"\\0");
	const std::vector<std::wstring> sMatchAndArgs = ProcessAndCheckArgs(2, oArgList);

	HANDLE hFile = CreateFile(sReportFile.at(0).c_str(), GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

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

	// retain only the unfinished line while reading bounded chunks
	std::string sPending;
	size_t iScanOffset = 0;
	bool bFirstRead = true;
	bool bUtf16 = false;
	LONGLONG iLineNumber = 0;
	auto WriteLine = [&](std::string_view sBytes)
	{
		std::wstring sLine;
		if (sBytes.size() > INT_MAX || (bUtf16 && sBytes.size() % sizeof(WCHAR) != 0))
		{
			InputOutput::AddError(L"Unable to decode text line.");
			return false;
		}

		// preserve UTF-16 code units or decode UTF-8 with the system code page as fallback
		if (bUtf16)
		{
			sLine.resize(sBytes.size() / sizeof(WCHAR));
			memcpy(sLine.data(), sBytes.data(), sBytes.size());
		}
		else if (!sBytes.empty())
		{
			UINT iCodePage = CP_UTF8;
			const int iByteCount = static_cast<int>(sBytes.size());
			int iLength = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, sBytes.data(), iByteCount, nullptr, 0);
			if (iLength == 0)
			{
				iCodePage = CP_ACP;
				iLength = MultiByteToWideChar(iCodePage, 0, sBytes.data(), iByteCount, nullptr, 0);
			}
			sLine.resize(iLength);
			if (iLength == 0 || !MultiByteToWideChar(iCodePage, 0, sBytes.data(), iByteCount, sLine.data(), iLength))
			{
				InputOutput::AddError(L"Unable to decode text line.");
				return false;
			}
		}

		// match complete lines and keep their original numbering in the report
		++iLineNumber;
		if (!sLine.empty() && sLine.back() == L'\r') sLine.pop_back();
		if (std::regex_search(sLine, tTextRegex) &&
			!WriteToFile(OutToCsv(tObjectEntry.Name, std::to_wstring(iLineNumber), sLine), hReportFile))
		{
			InputOutput::AddError(L"Unable to write information to report file.");
			return false;
		}
		return true;
	};

	for (;;)
	{
		DWORD iBytesRead = 0;
		if (!ReadFile(hFile, tReadBuffer.data(), static_cast<DWORD>(tReadBuffer.size()), &iBytesRead, nullptr))
		{
			InputOutput::AddError(L"Unable to read file data.");
			return;
		}
		if (iBytesRead == 0) break;

		// consume the encoding marker once at the beginning of the file
		size_t iOffset = 0;
		if (bFirstRead)
		{
			const auto* pRaw = reinterpret_cast<const unsigned char*>(tReadBuffer.data());
			bUtf16 = iBytesRead >= 2 && pRaw[0] == 0xFF && pRaw[1] == 0xFE;
			if (bUtf16) iOffset = 2;
			else if (iBytesRead >= 3 && pRaw[0] == 0xEF && pRaw[1] == 0xBB && pRaw[2] == 0xBF) iOffset = 3;
			bFirstRead = false;
		}
		sPending.append(tReadBuffer.data() + iOffset, iBytesRead - iOffset);

		// carry incomplete code units and lines across read boundaries
		const size_t iCharSize = bUtf16 ? sizeof(WCHAR) : 1;
		size_t iLineStart = 0;
		for (; iScanOffset + iCharSize <= sPending.size(); iScanOffset += iCharSize)
		{
			if (sPending[iScanOffset] != '\n' || (bUtf16 && sPending[iScanOffset + 1] != '\0')) continue;
			if (!WriteLine(std::string_view(sPending).substr(iLineStart, iScanOffset - iLineStart))) return;
			iLineStart = iScanOffset + iCharSize;
		}
		sPending.erase(0, iLineStart);
		iScanOffset -= iLineStart;
	}

	if (!sPending.empty()) WriteLine(sPending);
}
