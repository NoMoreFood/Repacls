#include <windows.h>
#include <lmshare.h>
#include <lmapibuf.h>

#pragma comment(lib, "netapi32.lib")

#include "OperationSharePaths.h"
#include "InputOutput.h"

ClassFactory<OperationSharePaths> * OperationSharePaths::RegisteredFactory =
	new ClassFactory<OperationSharePaths>(GetCommand());

OperationSharePaths::OperationSharePaths(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// exit if there are not enough arguments to part
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// if extra arguments are specified, parse them
	bool bAdminOnly = false;
	bool bHiddenIncluded = false;
	if (sSubArgs.size() == 2)
	{
		if (_wcsicmp(sSubArgs[1].c_str(), L"INCLUDEHIDDEN") == 0)
		{
			bHiddenIncluded = true;
		}
		else if (_wcsicmp(sSubArgs[1].c_str(), L"ADMINONLY") == 0)
		{
			bAdminOnly = true;
		}
		else
		{
			wprintf(L"ERROR: Unrecognized parameter '%s' for command '%s'\n", sSubArgs[1].c_str(), sSubArgs[0].c_str());
			exit(-1);
		}
	}

	DWORD hResumeHandle = NULL;
	DWORD iReturn = 0;
	do
	{
		SHARE_INFO_502 * tInfo;
		DWORD iEntries = 0;
		DWORD iTotalEntries = 0;

		// enumerate file share
		iReturn = NetShareEnum((LPWSTR)sSubArgs[0].c_str(), 502, (LPBYTE*)&tInfo,
			MAX_PREFERRED_LENGTH, &iEntries, &iTotalEntries, &hResumeHandle);

		// check for unknown error
		if (iReturn != ERROR_SUCCESS && iReturn != ERROR_MORE_DATA)
		{
			wprintf(L"ERROR: Could not enumerate shares on '%s'\n", sSubArgs[0].c_str());
			exit(-1);
		}

		// process entries
		for (DWORD iEntry = 0; iEntry < iEntries; iEntry++)
		{
			// skip non-disk shares (e.g, printers)
			if ((tInfo[iEntry].shi502_type & STYPE_MASK) != STYPE_DISKTREE) continue;

			// skip administrative share unless admin command was specified
			if (bAdminOnly && !CheckBitSet(tInfo[iEntry].shi502_type, STYPE_SPECIAL) ||
				!bAdminOnly && CheckBitSet(tInfo[iEntry].shi502_type, STYPE_SPECIAL)) continue;

			// skip hidden shares unless hidden command was specified
			WCHAR * cEnd = (wcsrchr(tInfo[iEntry].shi502_netname, '$'));
			if (!bAdminOnly && !bHiddenIncluded && (cEnd != NULL && *(cEnd + 1) == '\0')) continue;

			// add path to the share list
			InputOutput::ScanPaths().push_back(
				L"\\\\" + sSubArgs[0] + L"\\" + tInfo[iEntry].shi502_netname);
		}

		// cleanup
		NetApiBufferFree(tInfo);
	} 
	while (iReturn == ERROR_MORE_DATA);
};