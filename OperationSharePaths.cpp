#include <windows.h>
#include <lmshare.h>
#include <lmapibuf.h>

#include <regex>

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
	bool bStopOnErrors = false;
	bool bAdminOnly = false;
	bool bHiddenIncluded = false;
	if (sSubArgs.size() == 2)
	{
		// further split the second arg into a command delimited list
		std::wstring sArg = oArgList.front(); oArgList.pop();
		std::wregex oRegex(L",");
		std::wsregex_token_iterator oFirst{ sSubArgs[1].begin(), sSubArgs[1].end(), oRegex, -1 }, oLast;
		std::vector<std::wstring> oShareArgs = { oFirst, oLast };

		// enumerate list 
		for (std::vector<std::wstring>::iterator sShareArg = oShareArgs.begin();
			sShareArg != oShareArgs.end(); sShareArg++)
		{
			if (_wcsicmp((*sShareArg).c_str(), L"INCLUDEHIDDEN") == 0)
			{
				bHiddenIncluded = true;
			}
			else if (_wcsicmp((*sShareArg).c_str(), L"ADMINONLY") == 0)
			{
				bAdminOnly = true;
			}
			if (_wcsicmp((*sShareArg).c_str(), L"STOPONERROR") == 0)
			{
				bStopOnErrors = true;
			}
			else
			{
				wprintf(L"ERROR: Unrecognized parameter '%s' for command '%s'\n", sSubArgs[1].c_str(), sSubArgs[0].c_str());
				exit(-1);
			}
		}
	}

	DWORD hResumeHandle = NULL;
	DWORD iReturn = 0;
	std::map<std::wstring, std::wstring> mPaths;
	do
	{
		SHARE_INFO_2 * tInfo;
		DWORD iEntries = 0;
		DWORD iTotalEntries = 0;

		// enumerate file share
		iReturn = NetShareEnum((LPWSTR)sSubArgs[0].c_str(), 2, (LPBYTE*)&tInfo,
			MAX_PREFERRED_LENGTH, &iEntries, &iTotalEntries, &hResumeHandle);

		// check for unknown error
		if (iReturn != ERROR_SUCCESS && iReturn != ERROR_MORE_DATA)
		{
			wprintf(L"ERROR: Could not enumerate shares on '%s'\n", sSubArgs[0].c_str());
			if (bStopOnErrors) exit(-1); else return;
		}

		// process entries
		for (DWORD iEntry = 0; iEntry < iEntries; iEntry++)
		{
			// skip non-disk shares (e.g, printers)
			if ((tInfo[iEntry].shi2_type & STYPE_MASK) != STYPE_DISKTREE) continue;

			// skip administrative share unless admin command was specified
			if (bAdminOnly && !CheckBitSet(tInfo[iEntry].shi2_type, STYPE_SPECIAL) ||
				!bAdminOnly && CheckBitSet(tInfo[iEntry].shi2_type, STYPE_SPECIAL)) continue;

			// skip hidden shares unless hidden command was specified
			WCHAR * cEnd = (wcsrchr(tInfo[iEntry].shi2_netname, '$'));
			if (!bAdminOnly && !bHiddenIncluded && (cEnd != NULL && *(cEnd + 1) == '\0')) continue;

			// add a trailing path if the path does not have one
			std::wstring sLocalPath = tInfo[iEntry].shi2_path;
			if (sLocalPath.back() != L'\\') sLocalPath += L'\\';

			// convert to uppercase
			std::transform(sLocalPath.begin(), sLocalPath.end(), sLocalPath.begin(), ::toupper);

			// add path to the share list
			mPaths[tInfo[iEntry].shi2_netname] = sLocalPath;
		}

		// cleanup
		NetApiBufferFree(tInfo);
	} 
	while (iReturn == ERROR_MORE_DATA);

	// enumerate the shares and make sure there are no duplicates 
	// or child that are contained within parent paths
	for (std::map<std::wstring, std::wstring>::const_iterator oPathOuter = mPaths.begin(); 
		oPathOuter != mPaths.end(); oPathOuter++)
	{
		bool bAddToPathList = true;
		for (std::map<std::wstring, std::wstring>::const_iterator oPathInner = oPathOuter;
			oPathInner != mPaths.end(); oPathInner++)
		{
			// see if the path is a sub-path of another path
			if (oPathInner->first != oPathOuter->first &&
				oPathOuter->second.find(oPathInner->second) != std::wstring::npos)
			{
				wprintf(L"NOTE: Share '%s' is included in '%s' on '%s'; skipping\n",
					oPathOuter->first.c_str(), oPathInner->first.c_str(), sSubArgs[0].c_str());
				bAddToPathList = false;
				break;
			}
		}

		// add it the resultant array if not found in another path
		if (bAddToPathList)
		{
			InputOutput::ScanPaths().push_back(
				L"\\\\" + sSubArgs[0] + L"\\" + oPathOuter->first);
		}
	}
};