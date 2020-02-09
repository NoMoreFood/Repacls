#pragma once

#include <string>
#include <iostream>

#include "OperationLog.h"

class InputOutput
{
private:

	static std::wstring & GetFileName()
	{
		thread_local std::wstring sScreenBuffer;
		return sScreenBuffer;
	}

	static std::wstring & GetDetail()
	{
		thread_local std::wstring sScreenBuffer;
		return sScreenBuffer;
	}

public:

	static bool & InQuietMode() noexcept
	{
		static bool bQuietMode = false;
		return bQuietMode;
	}

	static bool & InWhatIfMode() noexcept
	{
		static bool bWhatIfMode = false;
		return bWhatIfMode;
	}

	static bool & ExcludeHiddenSystem() noexcept
	{
		static bool bExcludeHiddenSystem = false;
		return bExcludeHiddenSystem;
	}

	static short & MaxThreads() noexcept
	{
		static short iMaxThreads = 5;
		return iMaxThreads;
	}

	static bool & Log() noexcept
	{
		static bool bLog = false;
		return bLog;
	}

	static std::vector<std::wstring> & ScanPaths() noexcept
	{
		static std::vector<std::wstring> vScanPaths;
		return vScanPaths;
	}

	static void AddFile(const std::wstring & sLine)
	{
		// discover the long file name prefix so we can subtract it from the display path
		static std::wstring sPrefix;
		static size_t iPrefix = (size_t) -1;
		if (iPrefix == (size_t) -1)
		{
			const std::wstring sUnc = L"\\??\\UNC\\";
			const std::wstring sLocal = L"\\??\\";
			if (sLine.compare(0, sUnc.size(), sUnc.c_str()) == 0) { iPrefix = sUnc.size(); sPrefix = L"\\\\"; }
			else if (sLine.compare(0, sLocal.size(), sLocal.c_str()) == 0) iPrefix = sLocal.size();
			else iPrefix = 0;
		}

		GetFileName() = sPrefix + sLine.substr(iPrefix);
		GetDetail() = L"";
	}

	static void AddInfo(const std::wstring & sLine, const std::wstring & sPart, bool bMandatory = false)
	{
		if (Log())
		{
			OperationLog::LogFileItem(L"INFO", GetFileName(), sLine + ((sPart.empty()) ? L"" : L" in " + sPart));
		}

		if (!InQuietMode() || bMandatory)
		{
			GetDetail() += L"  INFO: " + sLine + ((sPart.empty()) ? L"" : L" in " + sPart) + L"\n";
		}
	}

	static void AddWarning(const std::wstring & sLine, const std::wstring & sPart = L"")
	{
		if (Log())
		{
			OperationLog::LogFileItem(L"WARNING", GetFileName(), sLine + ((sPart.empty()) ? L"" : L" in " + sPart));
		}

		GetDetail() += L"  WARNING: " + sLine + ((sPart.empty()) ? L"" : L" in " + sPart) + L"\n";
	}

	static void AddError(const std::wstring & sLine, const std::wstring & sExtended = L"")
	{
		if (Log())
		{
			OperationLog::LogFileItem(L"ERROR", GetFileName(), sLine);
		}

		GetDetail() += L"  ERROR: " + sLine + L"\n";
		if (!sExtended.empty()) GetDetail() += L"  ERROR DETAIL: " + sExtended + L"\n";
	}

	static void WriteToScreen()
	{
		// output to screen if there is anything to write
		if (!GetFileName().empty() && !GetDetail().empty())
		{
			wprintf(L"FILE: %s", (GetFileName() + L"\n" + GetDetail()).c_str());
		}

		// clear out buffer now that it's printed
		GetDetail() = L"";
	}
};