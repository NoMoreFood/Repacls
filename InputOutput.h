#pragma once

#include <string>
#include <iostream>

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

	static bool & InQuietMode()
	{
		static bool bQuietMode = false;
		return bQuietMode;
	}

	static bool & InWhatIfMode()
	{
		static bool bWhatIfMode = false;
		return bWhatIfMode;
	}

	static bool & ExcludeHiddenSystem()
	{
		static bool bExcludeHiddenSystem = false;
		return bExcludeHiddenSystem;
	}

	static short & MaxThreads()
	{
		static short iMaxThreads = 5;
		return iMaxThreads;
	}

	static std::wstring & BasePath()
	{
		static std::wstring sBasePath = L"";
		return sBasePath;
	}

	static void AddFile(const std::wstring & sLine)
	{
		// discover the long file name prefix so we can subtract it from the display path
		static std::wstring sPrefix = L"FILE: ";
		static size_t iPrefix = (size_t) -1;
		if (iPrefix == (size_t) -1)
		{
			const std::wstring sUnc = L"\\??\\UNC\\";
			const std::wstring sLocal = L"\\??\\";
			if (sLine.compare(0, sUnc.size(), sUnc.c_str()) == 0) { iPrefix = sUnc.size(); sPrefix += L"\\\\"; }
			else if (sLine.compare(0, sLocal.size(), sLocal.c_str()) == 0) iPrefix = sLocal.size();
			else iPrefix = 0;
		}

		GetFileName() = sPrefix + sLine.substr(iPrefix) + L"\n";
		GetDetail() = L"";
	}

	static void AddInfo(const std::wstring & sLine, std::wstring sPart, bool bMandatory = false)
	{
		if (!InQuietMode() || bMandatory)
		{
			GetDetail() += L"  INFO: " + sLine + ((sPart == L"") ? L"" : L" in " + sPart) + L"\n";
		}
	}

	static void AddWarning(const std::wstring & sLine)
	{
		GetDetail() += L"  WARNING: " + sLine + L"\n";
	}

	static void AddError(const std::wstring & sLine, const std::wstring & sExtended = L"")
	{
		GetDetail() += L"  ERROR: " + sLine + L"\n";
		if (sExtended != L"") GetDetail() += L"  ERROR DETAIL: " + sExtended + L"\n";
	}

	static void WriteToScreen()
	{
		// to to screen if there is anything to write
		if (GetFileName().size() > 0 && GetDetail().size() > 0)
		{
			wprintf(L"%s", (GetFileName() + GetDetail()).c_str());
		}

		// clear out buffer now that it's printed
		GetDetail() = L"";
	}
};