#pragma once

#include <Windows.h>
#include <sddl.h>
#include <string>

#include "Operation.h"

// helper functions
VOID EnablePrivs() noexcept;
PSID GetSidFromName(const std::wstring & sAccountName);
std::wstring GetNameFromSid(const PSID tSid, bool * bMarkAsOrphan = nullptr);
std::wstring GetNameFromSidEx(const PSID tSid, bool * bMarkAsOrphan = nullptr);
std::wstring GetDomainNameFromSid(const PSID tSid);
std::wstring GenerateAccessMask(DWORD iCurrentMask);
std::wstring GenerateInheritanceFlags(DWORD iCurrentFlags);
HANDLE RegisterFileHandle(HANDLE hFile, const std::wstring & sOperation);
std::wstring GetAntivirusStateDescription();
std::wstring FileTimeToString(const FILETIME tFileTime);
std::wstring FileSizeToString(const LARGE_INTEGER iFileSize);
std::wstring FileAttributesToString(const DWORD iAttributes);
BOOL WriteToFile(const std::wstring & sStringToWrite, HANDLE hFile) noexcept;
VOID InitThreadCom() noexcept;

// helper typedefs
typedef struct SidCompare
{
	inline bool operator()(PSID p1, PSID p2) const
	{
		const DWORD iLength1 = SidGetLength(p1);
		const DWORD iLength2 = SidGetLength(p2);
		if (iLength1 != iLength2) return iLength1 < iLength2;
		return memcmp(p1, p2, iLength1) > 0;
	}
}
SidCompare;

