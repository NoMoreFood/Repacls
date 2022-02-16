#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#include <windows.h>
#include <cstdio>
#include <queue>
#include <vector>
#include <io.h>
#include <fcntl.h>
#include <lmcons.h>

#include <string>
#include <atomic>
#include <condition_variable>

#include "Operation.h"
#include "InputOutput.h"
#include "ConcurrentQueue.h"
#include "DriverKitPartial.h"
#include "Helpers.h"

#include "OperationDepth.h"
#include "OperationPathMode.h"
#include "ObjectRegistry.h"
#include "ObjectFile.h"
#include "ObjectAds.h"

#pragma comment(lib,"version.lib")

VOID BeginScan(Processor & oProcessor)
{
	// determine the type of processor
	Object* oObject = nullptr;
	if (OperationPathMode::GetPathMode() == SE_FILE_OBJECT) oObject = new ObjectFile(oProcessor);
	if (OperationPathMode::GetPathMode() == SE_REGISTRY_KEY) oObject = new ObjectRegistry(oProcessor);
	if (OperationPathMode::GetPathMode() == SE_DS_OBJECT) oObject = new ObjectAds(oProcessor);

	// startup some threads for processing
	std::vector<std::thread> oThreads;
	oProcessor.GetQueue().SetWaiterCounter(InputOutput::MaxThreads());
	for (USHORT iNum = 0; iNum < InputOutput::MaxThreads(); iNum++)
		oThreads.push_back(std::thread([&oProcessor,oObject]() {
		for (;;)
		{
			ObjectEntry oEntry = oProcessor.GetQueue().Pop();

			// break out if entry flags a termination
			if (oEntry.ObjectType == SE_UNKNOWN_OBJECT_TYPE) return;

			// skip if this would descend below our object depth limit
			if (oEntry.Depth > OperationDepth::MaxDepth()) continue;

			// process next set
			oObject->GetChildObjects(oEntry);
		}
	}));

	// add all items to the queue
	for (auto sPath : InputOutput::ScanPaths())
	{
		oObject->GetBaseObject(sPath);
	}

	// wait for queue to be completely empty
	oProcessor.GetQueue().WaitForEmptyQueues();

	// send in some empty entries to tell the thread to stop waiting
	for (USHORT iNum = 0; iNum < InputOutput::MaxThreads(); iNum++)
	{
		ObjectEntry oEntry = {};
		oEntry.ObjectType = SE_UNKNOWN_OBJECT_TYPE;
		oProcessor.GetQueue().Push(oEntry);
	}

	// wait for the threads to complete
	for (auto& oThread : oThreads)
	{
		oThread.join();
	}
}

int wmain(int iArgs, WCHAR * aArgs[])
{
	// allow output of unicode characters
	std::ignore = _setmode(_fileno(stderr), _O_U16TEXT);
	std::ignore = _setmode(_fileno(stdout), _O_U16TEXT);

	// fetch currently running executable name
	std::wstring sVersion;
	LPWSTR sCurrentExe = nullptr;
	if (_get_wpgmptr(&sCurrentExe) != 0 || sCurrentExe == nullptr)
	{
		wprintf(L"%s\n", L"ERROR: Cannot get currently running executable name.");
		exit(-1);
	}
	
	// fetch the version string
	const DWORD iVersionSize = GetFileVersionInfoSize(sCurrentExe, nullptr);
	UINT iQueriedSize = 0;
	std::vector<BYTE> tVersionInfo = std::vector<BYTE>(iVersionSize);
	VS_FIXEDFILEINFO* pVersion = nullptr;
	if (GetFileVersionInfo(sCurrentExe, 0, iVersionSize, tVersionInfo.data()) != 0 &&
		VerQueryValue(tVersionInfo.data(), L"\\", reinterpret_cast<LPVOID*>(&pVersion), &iQueriedSize) != 0)
	{
		sVersion = std::to_wstring(HIWORD(pVersion->dwFileVersionMS)) + L"." + std::to_wstring(LOWORD(pVersion->dwFileVersionMS)) + 
			L"." + std::to_wstring(HIWORD(pVersion->dwFileVersionLS)) + L"." + std::to_wstring(LOWORD(pVersion->dwFileVersionLS));
	}

	// print standard header
	wprintf(L"===============================================================================\n");
	wprintf(L"= Repacls Version %s by Bryan Berns\n", sVersion.c_str());
	wprintf(L"===============================================================================\n");

	// translate
	std::queue<std::wstring> oArgList;
	for (int iArg = 1; iArg < iArgs; iArg++)
	{
		oArgList.push(aArgs[iArg]);
	}

	// if not parameter was especially the artificially add a help
	// command to the list so the help will display
	if (iArgs <= 1) oArgList.push(L"/?");

	// flag to track if more than one exclusive operation was specified
	bool bExclusiveOperation = false;
	bool bFetchDacl = false;
	bool bFetchSacl = false;
	bool bFetchOwner = false;
	bool bFetchGroup = false;

	// process each argument in the queue
	std::vector<Operation*> oOperationList;
	while (!oArgList.empty())
	{
		// derive the operation based on the current argument
		Operation * oOperation = FactoryPlant::CreateInstance(oArgList);

		// validate the operation was found although this
		// should never happen since the factory itself will complain
		if (oOperation == nullptr) exit(0);

		// add to the processing list if there is an actionable security element
		if (oOperation->AppliesToDacl ||
			oOperation->AppliesToSacl ||
			oOperation->AppliesToOwner ||
			oOperation->AppliesToGroup ||
			oOperation->AppliesToSd || 
			oOperation->AppliesToObject)
		{
			// do exclusivity check and error
			if (bExclusiveOperation && oOperation->ExclusiveOperation)
			{
				wprintf(L"%s\n", L"ERROR: More than one exclusive operation was specified.");
				exit(-1);
			}

			// track exclusivity and data that we must fetch 
			bExclusiveOperation |= oOperation->ExclusiveOperation;
			bFetchDacl |= oOperation->AppliesToDacl;
			bFetchSacl |= oOperation->AppliesToSacl;
			bFetchOwner |= oOperation->AppliesToOwner;
			bFetchGroup |= oOperation->AppliesToGroup;

			// add to the list of operations 
			oOperationList.push_back(oOperation);
		}
	}

	// verify a path was specified
	if (InputOutput::ScanPaths().empty())
	{
		wprintf(L"%s\n", L"ERROR: No path was specified.");
		exit(-1);
	}

	// ensure we have permissions to all files
	EnablePrivs();
	
	// note parameter information
	wprintf(L"\n");
	wprintf(L"===============================================================================\n");
	wprintf(L"= Initial Scan Details\n");
	wprintf(L"===============================================================================\n");
	for (auto& sScanPath : InputOutput::ScanPaths())
		wprintf(L"= Scan Path(s): %s\n", sScanPath.c_str());
	wprintf(L"= Maximum Threads: %d\n", (int)InputOutput::MaxThreads());
	wprintf(L"= What If Mode: %s\n", InputOutput::InWhatIfMode() ? L"Yes" : L"No");
	wprintf(L"= Antivirus Active: %s\n", GetAntivirusStateDescription().c_str());
	wprintf(L"===============================================================================\n");

	// do the scan
	const ULONGLONG iTimeStart = GetTickCount64();
	Processor oProcessor(oOperationList, bFetchDacl, bFetchSacl, bFetchOwner, bFetchGroup);
	BeginScan(oProcessor);
	const ULONGLONG iTimeStop = GetTickCount64();

	// print out statistics
	wprintf(L"===============================================================================\n");
	wprintf(L"= Total Scanned: %llu\n", (ULONGLONG)oProcessor.ItemsScanned);
	wprintf(L"= Read Failures: %llu\n", (ULONGLONG)oProcessor.ItemsEnumerationFailures);
	wprintf(L"= Enumeration Failures: %llu\n", (ULONGLONG)oProcessor.ItemsReadFailures);
	wprintf(L"= Update Successes: %llu\n", (ULONGLONG)oProcessor.ItemsUpdatedSuccess);
	wprintf(L"= Update Failures: %llu\n", (ULONGLONG)oProcessor.ItemsUpdatedFailure);
	wprintf(L"= Time Elapsed: %.3f\n", ((double)(iTimeStop - iTimeStart)) / 1000.0);
	wprintf(L"= Note: Update statistics do not include changes due to inherited rights.\n");
	wprintf(L"===============================================================================\n");
}