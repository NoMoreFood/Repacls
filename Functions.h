#pragma once

#include <windows.h>
#include <sddl.h>
#include <string>

// helper functions
VOID EnablePrivs();
const PSID GetSidFromName(std::wstring & sAccountName);
std::wstring GetNameFromSid(const PSID tSid, bool * bMarkAsOrphan);
std::wstring GetNameFromSidEx(const PSID tSid);
std::wstring GenerateAccessMask(DWORD iCurrentMask);
std::wstring GenerateInheritanceFlags(DWORD iCurrentFlags);
HANDLE RegisterFileHandle(HANDLE hFile, std::wstring sOperation);
bool CheckIfAntivirusIsActive();


