#include <Windows.h>
#include <LMShare.h>
#include <LMAPIbuf.h>

#include <regex>

#pragma comment(lib, "netapi32.lib")

#include "OperationSharePaths.h"
#include "InputOutput.h"

ClassFactory<OperationSharePaths> OperationSharePaths::RegisteredFactory(GetCommand());

OperationSharePaths::OperationSharePaths(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	const std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// if extra arguments are specified, parse them
	bool bDoDeDupe = true;
	bool bStopOnErrors = false;
	bool bAdminOnly = false;
	bool bHiddenIncluded = false;
	std::wregex oMatchRegex = std::wregex(L".*");
	std::wregex oNoMatchRegex = std::wregex(L":");
	if (sSubArgs.size() == 2)
	{
		// further split the second arg into a command delimited list
		std::vector<std::wstring> oShareArgs = SplitArgs(sSubArgs.at(1), L",");

		// enumerate list 
		for (auto& oShareArg : oShareArgs)
		{
			// check to see if a match parameter was passed
			constexpr WCHAR sMatchArg[] = L"MATCH=";
			constexpr WCHAR sNoMatchArg[] = L"NOMATCH=";
			if (_wcsnicmp(oShareArg.c_str(), sMatchArg, _countof(sMatchArg) - 1) == 0 ||
				_wcsnicmp(oShareArg.c_str(), sNoMatchArg, _countof(sNoMatchArg) - 1) == 0)
			{
				// split the NOMATCH/MATCH= sub parameter to get the regular expression part
				std::vector<std::wstring> oMatchArgs = SplitArgs(oShareArg, L"=");

				// verify a regular expression was actually specified
				if (oMatchArgs.size() != 2)
				{
					Print(L"ERROR: No regular expression specified for parameter '{}'", sSubArgs.at(0));
					std::exit(-1);
				}

				try
				{
					// parse the regular expression
					((_wcsnicmp(oShareArg.c_str(), sMatchArg, _countof(sMatchArg) - 1) == 0) ? oMatchRegex : oNoMatchRegex) =
						std::wregex(oMatchArgs.at(1), std::regex_constants::icase);
				}
				catch (std::exception &)
				{
					// regular expression could not be parsed
					Print(L"ERROR: Invalid regular expression '{}'", oMatchArgs.at(1));
					std::exit(-1);
				}
			}
			else if (_wcsicmp(oShareArg.c_str(), L"INCLUDEHIDDEN") == 0)
			{
				bHiddenIncluded = true;
			}
			else if (_wcsicmp(oShareArg.c_str(), L"ADMINONLY") == 0)
			{
				bAdminOnly = true;
			}
			else if (_wcsicmp(oShareArg.c_str(), L"STOPONERROR") == 0)
			{
				bStopOnErrors = true;
			}
			else if (_wcsicmp(oShareArg.c_str(), L"NODEDUPE") == 0)
			{
				bDoDeDupe = false;
			}
			else
			{
				Print(L"ERROR: Unrecognized share lookup option '{}'", oShareArg);
				std::exit(-1);
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
		iReturn = NetShareEnum(const_cast<LPWSTR>(sSubArgs.at(0).c_str()), 2, reinterpret_cast<LPBYTE*>(&tInfo),
			MAX_PREFERRED_LENGTH, &iEntries, &iTotalEntries, &hResumeHandle);

		// check for unknown error
		if (iReturn != ERROR_SUCCESS && iReturn != ERROR_MORE_DATA)
		{
			Print(L"ERROR: Could not enumerate shares on '{}'", sSubArgs.at(0));
			if (bStopOnErrors) std::exit(-1); else return;
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
			const WCHAR * cEnd = (wcsrchr(tInfo[iEntry].shi2_netname, '$'));
			if (!bAdminOnly && !bHiddenIncluded && (cEnd != nullptr && *(cEnd + 1) == '\0')) continue;

			// add a trailing path if the path does not have one
			std::wstring sLocalPath = tInfo[iEntry].shi2_path;
			if (sLocalPath.back() != L'\\') sLocalPath += L'\\';
			ConvertToUpper(sLocalPath);

			// see if the share name matches the regular expression
			if (!std::regex_search(tInfo[iEntry].shi2_netname, oMatchRegex)) continue;

			// see if the share name does not match the regular expression
			if (std::regex_search(tInfo[iEntry].shi2_netname, oNoMatchRegex)) continue;

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
		oPathOuter != mPaths.end(); ++oPathOuter)
	{
		bool bAddToPathList = true;
		for (auto oPathInner = oPathOuter; bDoDeDupe &&
			oPathInner != mPaths.end(); ++oPathInner)
		{
			// see if the path is a sub-path of another path
			if (oPathInner->first != oPathOuter->first &&
				oPathOuter->second.find(oPathInner->second) != std::wstring::npos)
			{
				Print(L"NOTE: Share '{}' is included in '{}' on '{}'; skipping",
					oPathOuter->first, oPathInner->first, sSubArgs.at(0));
				bAddToPathList = false;
				break;
			}
		}

		// add it the resultant array if not found in another path
		const std::wstring sPathToAdd = L"\\\\" + sSubArgs.at(0) + L"\\" + oPathOuter->first;
		if (bAddToPathList && std::ranges::find(InputOutput::ScanPaths(), sPathToAdd) == InputOutput::ScanPaths().end())
		{
			InputOutput::ScanPaths().push_back(sPathToAdd);
		}
	}
};