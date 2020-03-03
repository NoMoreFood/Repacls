#include <windows.h>
#include <lmshare.h>
#include <lmapibuf.h>
#include <iads.h>
#include <adshlp.h>
#include <atlBase.h>
#include <dsgetdc.h>

#pragma comment(lib,"activeds.lib")
#pragma comment(lib,"adsiid.lib")
#pragma comment(lib,"netapi32.lib")

#include "OperationDomainPaths.h"
#include "OperationSharePaths.h"
#include "InputOutput.h"

ClassFactory<OperationDomainPaths> OperationDomainPaths::RegisteredFactory(GetCommand());

OperationDomainPaths::OperationDomainPaths(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// initialize com only
	static HRESULT hComInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if (hComInit != S_OK && hComInit != S_FALSE)
	{
		wprintf(L"ERROR: Could not initialize COM.\n");
		exit(-1);
	}

	// find a domain controller for the specified domain
	PDOMAIN_CONTROLLER_INFO tDomainControllerInfo;
	if (DsGetDcName(nullptr, sSubArgs.at(0).c_str(), nullptr, nullptr,
		DS_IS_FLAT_NAME | DS_RETURN_DNS_NAME | DS_TRY_NEXTCLOSEST_SITE | DS_FORCE_REDISCOVERY,
		&tDomainControllerInfo) != ERROR_SUCCESS)
	{
		wprintf(L"ERROR: Could not locate domain controller for domain '%s'\n", sSubArgs.at(0).c_str());
		exit(-1);
	}

	// create a string 
	std::wstring sPath = std::wstring(L"LDAP://") + (wcsrchr(tDomainControllerInfo->DomainControllerName, '\\') + 1);

	// grab the dns suffix for later use
	std::wstring sSuffix = tDomainControllerInfo->DomainName;
	NetApiBufferFree(tDomainControllerInfo);

	// bind to global catalog
	CComPtr<IDirectorySearch> oSearch;
	if (FAILED(ADsOpenObject(sPath.c_str(), nullptr, NULL, ADS_SECURE_AUTHENTICATION,
		IID_IDirectorySearch, (void**)&oSearch)))
	{
		wprintf(L"ERROR: Could not establish search for domain '%s'\n", sSubArgs.at(0).c_str());
		exit(-1);
	}

	// setup preferences to search entire tree
	ADS_SEARCHPREF_INFO SearchPref;
	SearchPref.dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
	SearchPref.vValue.dwType = ADSTYPE_INTEGER;
	SearchPref.vValue.Integer = ADS_SCOPE_SUBTREE;

	// set the search preference.
	if (FAILED(oSearch->SetSearchPreference(&SearchPref, 1)))
	{
		wprintf(L"ERROR: Could not set search preference for domain '%s'\n", sSubArgs.at(0).c_str());
		exit(-1);

	}

	// create the search filter
	WCHAR sSearchFilter[] = L"(&(objectCategory=computer)(|(operatingSystem=*server*)(operatingSystem=*ontap*)(operatingSystem=*netapp*))" \
		"(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(msDS-isRODC=true)))";

	// execute the search.
	LPWSTR sAttributes[] = { L"cn" };
	ADS_SEARCH_HANDLE hSearch;
	if (FAILED(oSearch->ExecuteSearch(sSearchFilter, sAttributes, _countof(sAttributes), &hSearch)))
	{
		wprintf(L"ERROR: Could not execute search for domain '%s'\n", sSubArgs.at(0).c_str());
		exit(-1);
	}

	// enumerate results
	std::vector<std::wstring> sServers;
	for (HRESULT hResult = oSearch->GetFirstRow(hSearch); hResult == S_OK; hResult = oSearch->GetNextRow(hSearch))
	{
		// get the data from the column
		ADS_SEARCH_COLUMN oColumn;
		if (FAILED(oSearch->GetColumn(hSearch, sAttributes[0], &oColumn)) ||
			oColumn.dwADsType != ADSTYPE_CASE_IGNORE_STRING)
		{
			continue;
		}

		// add the server to our list
		oArgList.push(L"/SharePaths");
		oArgList.push(std::wstring(oColumn.pADsValues->CaseIgnoreString) + L"." + sSuffix + 
			((sSubArgs.size() == 2) ? (L":" + sSubArgs.at(1)) : L""));

		// free the column.
		oSearch->FreeColumn(&oColumn);
	}

	// close search handle
	if (oSearch->CloseSearchHandle(hSearch) != NULL)
	{
		wprintf(L"ERROR: Could not close search for domain '%s'\n", sSubArgs.at(0).c_str());
		exit(-1);
	}
};
