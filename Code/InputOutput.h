#pragma once

#include <string>
#include <mutex>
#include <atomic>

#include "OperationLog.h"

class InputOutput
{

	static std::wstring & GetFileName() noexcept
	{
		thread_local std::wstring sScreenBuffer;
		return sScreenBuffer;
	}

	static std::wstring & GetDetail() noexcept
	{
		thread_local std::wstring sScreenBuffer;
		return sScreenBuffer;
	}

public:

	static std::atomic<bool>& HadErrors() noexcept
	{
		static std::atomic<bool> bHadErrors = false;
		return bHadErrors;
	}

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
		// normalize each path independently when local and network roots share a scan
		if (sLine.starts_with(L"\\??\\UNC\\")) GetFileName() = L"\\\\" + sLine.substr(8);
		else if (sLine.starts_with(L"\\??\\")) GetFileName() = sLine.substr(4);
		else GetFileName() = sLine;
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
		HadErrors() = true;

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
			Print(L"OBJECT: {}", GetFileName() + L"\n" + GetDetail());
		}

		// clear out buffer now that it's printed
		GetDetail() = L"";
	}
};
