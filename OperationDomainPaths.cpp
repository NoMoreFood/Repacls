#include <WinSock2.h>
#include <WS2tcpip.h>
#include <LMShare.h>
#include <LMAPIbuf.h>
#include <Iads.h>
#include <AdsHlp.h>
#include <atlbase.h>
#include <DsGetDC.h>

#pragma comment(lib,"activeds.lib")
#pragma comment(lib,"adsiid.lib")
#pragma comment(lib,"netapi32.lib")
#pragma comment(lib, "ws2_32.lib")

#include "OperationDomainPaths.h"

#include "OperationSharePaths.h"
#include "InputOutput.h"
#include "Helpers.h"

#include <regex>

ClassFactory<OperationDomainPaths> OperationDomainPaths::RegisteredFactory(GetCommand());
ClassFactory<OperationDomainPaths> OperationDomainPaths::RegisteredFactorySite(GetCommandSite());

OperationDomainPaths::OperationDomainPaths(std::queue<std::wstring>& oArgList, const std::wstring& sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	const std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// address site argument option
	bool bFilterSite = _wcsicmp(sCommand.c_str(), GetCommandSite().c_str()) == 0;
	std::vector<std::wstring> sSiteArgs;
	if (bFilterSite) sSiteArgs = ProcessAndCheckArgs(1, oArgList);

	// initialize com for this thread
	InitThreadCom();

	// initialize windows socket library
	WSADATA tWinSockData;
	if (WSAStartup(MAKEWORD(2, 2), &tWinSockData) != 0)
	{
		wprintf(L"Could not initialize Windows Sockets.\n");
		std::exit(-1);
	}

	// find a domain controller for the specified domain
	PDOMAIN_CONTROLLER_INFO pDomainControllerInfo;
	if (DsGetDcName(nullptr, sSubArgs.at(0).c_str(), nullptr, nullptr,
		DS_IS_FLAT_NAME | DS_RETURN_DNS_NAME | DS_TRY_NEXTCLOSEST_SITE | DS_FORCE_REDISCOVERY,
		&pDomainControllerInfo) != ERROR_SUCCESS)
	{
		wprintf(L"ERROR: Could not locate domain controller for domain '%s'\n", sSubArgs.at(0).c_str());
		std::exit(-1);
	}

	// grab the domain controller name
	const std::wstring sDomainController = pDomainControllerInfo->DomainControllerName;
	const std::wstring sDomainSuffix = pDomainControllerInfo->DomainName;
	NetApiBufferFree(pDomainControllerInfo);

	// create a string 
	std::wstring sPath = std::wstring(L"LDAP://") + (wcsrchr(sDomainController.c_str(), '\\') + 1);

	// bind to global catalog
	CComPtr<IDirectorySearch> oSearch;
	if (FAILED(ADsOpenObject(sPath.c_str(), nullptr, nullptr, ADS_SECURE_AUTHENTICATION,
		IID_IDirectorySearch, (void**)&oSearch)))
	{
		wprintf(L"ERROR: Could not establish search for domain '%s'\n", sSubArgs.at(0).c_str());
		std::exit(-1);
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
		std::exit(-1);

	}

	// create the search filter
	WCHAR sSearchFilter[] = L"(&(objectCategory=computer)(|(operatingSystem=*server*)(operatingSystem=*ontap*)(operatingSystem=*netapp*))" \
		"(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(msDS-isRODC=true)))";

	// execute the search.
	LPCWSTR sAttributes[] = { L"dNSHostName", L"cn" };
	ADS_SEARCH_HANDLE hSearch;
	if (FAILED(oSearch->ExecuteSearch(sSearchFilter, (LPWSTR*)sAttributes, _countof(sAttributes), &hSearch)))
	{
		wprintf(L"ERROR: Could not execute search for domain '%s'\n", sSubArgs.at(0).c_str());
		std::exit(-1);
	}

	// enumerate results
	for (HRESULT hResult = oSearch->GetFirstRow(hSearch); hResult == S_OK; hResult = oSearch->GetNextRow(hSearch))
	{
		// get the data from the column
		std::wstring sHostName;
		ADS_SEARCH_COLUMN oColumn = {};
		if (SUCCEEDED(oSearch->GetColumn(hSearch, (LPWSTR)sAttributes[0], &oColumn)))
		{
			sHostName = std::wstring(oColumn.pADsValues->CaseIgnoreString);
		}
		else if (SUCCEEDED(oSearch->GetColumn(hSearch, (LPWSTR)sAttributes[1], &oColumn)))
		{
			sHostName = std::wstring(oColumn.pADsValues->CaseIgnoreString) + L"." + sDomainSuffix;
		}
		else continue;

		// cleanup ad search column
		oSearch->FreeColumn(&oColumn);

		// filter only allow servers in the specified site
		if (bFilterSite)
		{
			// fetch the the address information
			PADDRINFOW pAddressInfo;
			if (GetAddrInfo(sHostName.c_str(), nullptr, nullptr, &pAddressInfo) != 0) continue;
			SOCKET_ADDRESS tAddressArray[1];
			tAddressArray[0].lpSockaddr = pAddressInfo->ai_addr;
			tAddressArray[0].iSockaddrLength = (int)pAddressInfo->ai_addrlen;

			// fetch the site name associated with the device
			LPWSTR* sSiteName = nullptr;
			bool bMatchSite = false;
			if (DsAddressToSiteNames(sDomainController.c_str(), 1, tAddressArray, &sSiteName) == NO_ERROR)
			{
				if (sSiteName[0] != nullptr) bMatchSite = std::regex_match(std::wstring(sSiteName[0]), std::wregex(sSiteArgs.at(0)));
				NetApiBufferFree(sSiteName);
			}

			// cleanup
			FreeAddrInfo(pAddressInfo);

			// skip this name is not match
			if (!bMatchSite) continue;
		}

		// add the server to our list
		oArgList.emplace(L"/SharePaths");
		oArgList.push(sHostName + ((sSubArgs.size() == 2) ? (L":" + sSubArgs.at(1)) : L""));
	}

	// close search handle
	if (oSearch->CloseSearchHandle(hSearch) != NULL)
	{
		wprintf(L"ERROR: Could not close search for domain '%s'\n", sSubArgs.at(0).c_str());
		std::exit(-1);
	}
};
