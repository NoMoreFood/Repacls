#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#include <Windows.h>
#include <queue>
#include <vector>
#include <lmcons.h>

#include <string>

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
	oThreads.reserve(InputOutput::MaxThreads());
	for (SHORT iNum = 0; iNum < InputOutput::MaxThreads(); iNum++)
		oThreads.emplace_back([&oProcessor,oObject]() {
		for (;;)
		{
			// fetch next entry
			ObjectEntry oEntry = oProcessor.GetQueue().Pop();

			// break out if entry flags a termination
			if (oEntry.ObjectType == SE_UNKNOWN_OBJECT_TYPE) return;

			// skip if this would descend below our object depth limit
			if (oEntry.Depth > OperationDepth::MaxDepth()) continue;

			// process next set
			oObject->GetChildObjects(oEntry);
		}
	});
	
	// add all items to the queue
	for (const auto& sPath : InputOutput::ScanPaths())
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
	// fetch currently running executable name
	std::wstring sVersion;
	LPWSTR sCurrentExe = nullptr;
	if (_get_wpgmptr(&sCurrentExe) != 0 || sCurrentExe == nullptr)
	{
		Print(L"ERROR: Cannot get currently running executable name.");
		std::exit(-1);
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
	Print(L"===============================================================================");
	Print(L"= Repacls Version {} by Bryan Berns", sVersion);
	Print(L"===============================================================================");

	// translate
	std::queue<std::wstring> oArgList;
	for (int iArg = 1; iArg < iArgs; iArg++)
	{
		oArgList.emplace(aArgs[iArg]);
	}

	// if not parameter was especially the artificially add a help
	// command to the list so the help will display
	if (iArgs <= 1) oArgList.emplace(L"/?");

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
		if (oOperation == nullptr) std::exit(0);

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
				Print(L"ERROR: More than one exclusive operation was specified.");
				std::exit(-1);
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
		Print(L"ERROR: No path was specified.");
		std::exit(-1);
	}

	// ensure we have permissions to all files
	EnablePrivs();

	// special case: force what-if move if using Active Directory mode
	if (SE_DS_OBJECT == OperationPathMode::GetPathMode())
	{
		InputOutput::InWhatIfMode() = true;
	}
	
	// note parameter information
	Print(L"");
	Print(L"===============================================================================");
	Print(L"= Initial Scan Details");
	Print(L"===============================================================================");
	for (auto& sScanPath : InputOutput::ScanPaths())
		Print(L"= Scan Path(s): {}", sScanPath);
	Print(L"= Maximum Threads: {}", static_cast<int>(InputOutput::MaxThreads()));
	Print(L"= What If Mode: {}", InputOutput::InWhatIfMode() ? L"Yes" : L"No");
	Print(L"= Antivirus Active: {}", GetAntivirusStateDescription());
	Print(L"===============================================================================");

	// do the scan
	const ULONGLONG iTimeStart = GetTickCount64();
	Processor oProcessor(oOperationList, bFetchDacl, bFetchSacl, bFetchOwner, bFetchGroup);
	BeginScan(oProcessor);
	const ULONGLONG iTimeStop = GetTickCount64();

	// print out statistics
	Print(L"===============================================================================");
	Print(L"= Total Scanned: {}", static_cast<ULONGLONG>(oProcessor.ItemsScanned));
	Print(L"= Read Failures: {}", static_cast<ULONGLONG>(oProcessor.ItemsEnumerationFailures));
	Print(L"= Enumeration Failures: {}", static_cast<ULONGLONG>(oProcessor.ItemsReadFailures));
	Print(L"= Update Successes: {}", static_cast<ULONGLONG>(oProcessor.ItemsUpdatedSuccess));
	Print(L"= Update Failures: {}", static_cast<ULONGLONG>(oProcessor.ItemsUpdatedFailure));
	Print(L"= Time Elapsed: {:.3f}", static_cast<double>(iTimeStop - iTimeStart) / 1000.0);
	Print(L"= Note: Update statistics do not include changes due to inherited rights.");
	Print(L"===============================================================================");
}