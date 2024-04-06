#pragma once

#include <Windows.h>
#include <sddl.h>
#include <string>

#include "Operation.h"

// helper functions
VOID EnablePrivs() noexcept;
PSID GetSidFromName(const std::wstring & sAccountName);
std::wstring GetNameFromSid(PSID tSid, bool * bMarkAsOrphan = nullptr);
std::wstring GetNameFromSidEx(PSID tSid, bool * bMarkAsOrphan = nullptr);
std::wstring GetDomainNameFromSid(PSID tSid);
std::wstring GenerateAccessMask(DWORD iCurrentMask);
std::wstring GenerateInheritanceFlags(DWORD iCurrentFlags);
HANDLE RegisterFileHandle(HANDLE hFile, const std::wstring & sOperation);
std::wstring GetAntivirusStateDescription();
std::wstring FileTimeToString(FILETIME tFileTime);
std::wstring FileSizeToString(LARGE_INTEGER iFileSize);
std::wstring FileAttributesToString(DWORD iAttributes);
BOOL WriteToFile(const std::wstring & sStringToWrite, HANDLE hFile) noexcept;
VOID InitThreadCom() noexcept;

// helper typedefs
typedef struct SidCompare
{
	bool operator()(PSID p1, PSID p2) const
	{
		const DWORD iLength1 = SidGetLength(p1);
		const DWORD iLength2 = SidGetLength(p2);
		if (iLength1 != iLength2) return iLength1 < iLength2;
		return memcmp(p1, p2, iLength1) > 0;
	}
}
SidCompare;

