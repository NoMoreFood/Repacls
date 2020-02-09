#pragma once

#include <windows.h>
#include <sddl.h>
#include <string>

// helper functions
VOID EnablePrivs();
PSID GetSidFromName(std::wstring & sAccountName);
std::wstring GetNameFromSid(const PSID tSid, bool * bMarkAsOrphan = nullptr);
std::wstring GetNameFromSidEx(const PSID tSid, bool * bMarkAsOrphan = nullptr);
std::wstring GetDomainNameFromSid(const PSID tSid);
std::wstring GenerateAccessMask(DWORD iCurrentMask);
std::wstring GenerateInheritanceFlags(DWORD iCurrentFlags);
HANDLE RegisterFileHandle(HANDLE hFile, std::wstring sOperation);
std::wstring GetAntivirusStateDescription();
std::wstring FileTimeToString(LPFILETIME const tFileTime);
BOOL WriteToFile(const std::wstring & sStringToWrite, HANDLE hFile);

// helper typedefs
typedef struct SidCompare
{
	inline bool operator()(PSID p1, PSID p2) const noexcept
	{
		const DWORD iLength1 = GetLengthSid(p1);
		const DWORD iLength2 = GetLengthSid(p2);
		if (iLength1 != iLength2) return iLength1 < iLength2;
		return memcmp(p1, p2, iLength1) > 0;
	}
}
SidCompare;

