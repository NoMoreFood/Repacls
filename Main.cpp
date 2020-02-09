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
#include "OperationHelp.h"
#include "InputOutput.h"
#include "ConcurrentQueue.h"
#include "DriverKitPartial.h"
#include "Functions.h"
#include "Version.h"

#define MAX_DIRECTORY_BUFFER 65536

std::vector<Operation *> oOperationList;

// general statistics
std::atomic<ULONGLONG> iFilesScanned = 0;
std::atomic<ULONGLONG> iFilesUpdatedSuccess = 0;
std::atomic<ULONGLONG> iFilesUpdatedFailure = 0;
std::atomic<ULONGLONG> iFilesEnumerationFailures = 0;
std::atomic<ULONGLONG> iFilesReadFailures = 0;

// used for processing the queue
ConcurrentQueue<ObjectEntry> oScanQueue;
std::condition_variable oSyncVar;
std::mutex oSyncVarMutex;
std::atomic<ULONGLONG> iFilesToProcess;

// populated upon argument processing to determine what data is needed
bool bFetchDacl = false;
bool bFetchSacl = false;
bool bFetchOwner = false;
bool bFetchGroup = false;

void AnalyzeSecurity(ObjectEntry & oEntry)
{
	// update file counter
	++iFilesScanned;

	// print out file name
	InputOutput::AddFile(oEntry.Name);

	// compute information to lookup
	DWORD iInformationToLookup = 0;
	if (bFetchDacl) iInformationToLookup |= DACL_SECURITY_INFORMATION;
	if (bFetchSacl) iInformationToLookup |= SACL_SECURITY_INFORMATION;
	if (bFetchOwner) iInformationToLookup |= OWNER_SECURITY_INFORMATION;
	if (bFetchGroup) iInformationToLookup |= GROUP_SECURITY_INFORMATION;

	// used to determine what we should update
	bool bDaclIsDirty = false;
	bool bSaclIsDirty = false;
	bool bOwnerIsDirty = false;
	bool bGroupIsDirty = false;

	// read security information from the file handle
	PACL tAclDacl = nullptr;
	PACL tAclSacl = nullptr;
	PSID tOwnerSid = nullptr;
	PSID tGroupSid = nullptr;
	PSECURITY_DESCRIPTOR tDesc = nullptr;
	DWORD iError = 0;
	if (iInformationToLookup != 0 &&
		(iError = GetNamedSecurityInfo(oEntry.Name.c_str(), SE_FILE_OBJECT,
		iInformationToLookup, (bFetchOwner) ? &tOwnerSid : nullptr, (bFetchGroup) ? &tGroupSid : nullptr,
		(bFetchDacl) ? &tAclDacl : nullptr, (bFetchSacl) ? &tAclSacl : nullptr, &tDesc)) != ERROR_SUCCESS)
	{
		// attempt to look up error message
		LPWSTR sError = nullptr;
		const size_t iSize = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
			nullptr, iError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&sError, 0, nullptr);
		InputOutput::AddError(L"Unable to read file security", (iSize == 0) ? L"" : sError);
		if (iSize > 0) LocalFree(sError);

		// clear out any remaining data
		InputOutput::WriteToScreen();
		return;
	}

	// some functions will reallocate the area for the acl so we need
	// to make sure we cleanup that memory distinctly from the security descriptor
	bool bDaclCleanupRequired = false;
	bool bSaclCleanupRequired = false;
	bool bOwnerCleanupRequired = false;
	bool bGroupCleanupRequired = false;
	bool bDescCleanupRequired = (tDesc != nullptr);

	// used for one-shot operations like reset children or inheritance
	DWORD iSpecialCommitMergeFlags = 0;

	// loop through the instruction list
	for (auto& oOperation : oOperationList)
	{
		// skip if this operation does not apply to the root/children based on the operation
		if (oOperation->AppliesToRootOnly && !oEntry.IsRoot ||
			oOperation->AppliesToChildrenOnly && oEntry.IsRoot)
		{
			continue;
		}

		// merge any special commit flags
		iSpecialCommitMergeFlags |= oOperation->SpecialCommitFlags;
		
		if (oOperation->AppliesToObject)
		{
			oOperation->ProcessObjectAction(oEntry);
		}
		if (oOperation->AppliesToDacl)
		{
			bDaclIsDirty |= oOperation->ProcessAclAction(L"DACL", oEntry, tAclDacl, bDaclCleanupRequired);
		}
		if (oOperation->AppliesToSacl)
		{
			bSaclIsDirty |= oOperation->ProcessAclAction(L"SACL", oEntry, tAclSacl, bSaclCleanupRequired);
		}
		if (oOperation->AppliesToOwner)
		{
			bOwnerIsDirty |= oOperation->ProcessSidAction(L"OWNER", oEntry, tOwnerSid, bOwnerCleanupRequired);
		}
		if (oOperation->AppliesToGroup)
		{
			bGroupIsDirty |= oOperation->ProcessSidAction(L"GROUP", oEntry, tGroupSid, bGroupCleanupRequired);
		}
		if (oOperation->AppliesToSd)
		{
			if (oOperation->ProcessSdAction(oEntry.Name, oEntry, tDesc, bDescCleanupRequired))
			{
				// cleanup previous operations if necessary
				if (bDaclCleanupRequired)  { LocalFree(tAclDacl); bDaclCleanupRequired = false; };
				if (bSaclCleanupRequired)  { LocalFree(tAclDacl); bSaclCleanupRequired = false; };
				if (bOwnerCleanupRequired) { LocalFree(tAclDacl); bOwnerCleanupRequired = false; };
				if (bGroupCleanupRequired) { LocalFree(tAclDacl); bGroupCleanupRequired = false; };

				// extract the elements from the raw security descriptor
				BOOL bItemPresent = FALSE;
				BOOL bItemDefaulted = FALSE;
				GetSecurityDescriptorDacl(tDesc, &bItemPresent, &tAclDacl, &bItemDefaulted);
				GetSecurityDescriptorSacl(tDesc, &bItemPresent, &tAclSacl, &bItemDefaulted);
				GetSecurityDescriptorOwner(tDesc, &tOwnerSid, &bItemDefaulted);
				GetSecurityDescriptorGroup(tDesc, &tGroupSid, &bItemDefaulted);

				// extract relevant inheritance bits
				DWORD tRevisionInfo;
				SECURITY_DESCRIPTOR_CONTROL tControl;
				GetSecurityDescriptorControl(tDesc, &tControl, &tRevisionInfo);

				// convert inheritance bits to the special flags that control inheritance
				iSpecialCommitMergeFlags = CheckBitSet(SE_DACL_PROTECTED, tControl) ?
					PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION;
				
				// mark all elements as needing to be updated
				bDaclIsDirty = true;
				bSaclIsDirty = true;
				bOwnerIsDirty = true;
				bGroupIsDirty = true;
			}
		}
	}

	// write any pending data to screen before we start setting security 
	// which can sometimes take awhile
	InputOutput::WriteToScreen();

	// compute data to write back
	DWORD iInformationToCommit = iSpecialCommitMergeFlags;
	if (bDaclIsDirty) iInformationToCommit |= DACL_SECURITY_INFORMATION;
	if (bSaclIsDirty) iInformationToCommit |= SACL_SECURITY_INFORMATION;
	if (bOwnerIsDirty) iInformationToCommit |= OWNER_SECURITY_INFORMATION;
	if (bGroupIsDirty) iInformationToCommit |= GROUP_SECURITY_INFORMATION;

	// if data has changed, commit it
	if (iInformationToCommit != 0)
	{
		// only commit changes if not in what-if scenario
		if (!InputOutput::InWhatIfMode())
		{
			if ((iError = SetNamedSecurityInfo((LPWSTR) oEntry.Name.c_str(), SE_FILE_OBJECT, iInformationToCommit,
				(bOwnerIsDirty) ? tOwnerSid : nullptr, (bGroupIsDirty) ? tGroupSid : nullptr,
				(bDaclIsDirty) ? tAclDacl : nullptr, (bSaclIsDirty) ? tAclSacl : nullptr)) != ERROR_SUCCESS)
			{
				// attempt to look up error message
				LPWSTR sError = nullptr;
				const size_t iSize = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
					FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
					nullptr, iError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR) &sError, 0, NULL);
				InputOutput::AddError(L"Unable to update file security", (iSize == 0) ? L"" : sError);
				if (iSize > 0) LocalFree(sError);

				// clear out any remaining data
				InputOutput::WriteToScreen();

				++iFilesUpdatedFailure;
			}
			else
			{
				++iFilesUpdatedSuccess;
			}
		}
	}


	// cleanup
	if (bDaclCleanupRequired) LocalFree(tAclDacl);
	if (bSaclCleanupRequired) LocalFree(tAclSacl);
	if (bOwnerCleanupRequired) LocalFree(tOwnerSid);
	if (bGroupCleanupRequired) LocalFree(tGroupSid);
	if (bDescCleanupRequired) LocalFree(tDesc);
}


void CompleteEntry(ObjectEntry & oEntry, bool bDecreaseCounter = true)
{
	if (bDecreaseCounter)
	{
		if ((iFilesToProcess.fetch_sub(1) - 1) == 0)
		{
			std::unique_lock<std::mutex> oLock(oSyncVarMutex);
			oSyncVar.notify_one();
		}
	}

	// flush any pending data from the last operation
	InputOutput::WriteToScreen();
}

void AnalyzingQueue()
{
	// total files processed
	thread_local BYTE DirectoryInfo[MAX_DIRECTORY_BUFFER];

	// run until the loop is manually broken
	for (;;)
	{
		ObjectEntry oEntry = oScanQueue.pop();

		// break out if entry flags a termination
		if (oEntry.Name.empty()) break;

		// skip if hidden and system
		if (!oEntry.IsRoot && IsHiddenSystem(oEntry.Attributes) 
			&& InputOutput::ExcludeHiddenSystem())
		{
			CompleteEntry(oEntry);
			continue;
		}

		// do security analysis
		AnalyzeSecurity(oEntry);

		// stop processing if not a directory
		if (!IsDirectory(oEntry.Attributes))
		{
			CompleteEntry(oEntry);
			continue;
		};

		// construct a string that can be used in the rtl apis
		UNICODE_STRING tPathU = { (USHORT) oEntry.Name.size() * sizeof(WCHAR),
			(USHORT) oEntry.Name.size() * sizeof(WCHAR), (PWSTR) oEntry.Name.c_str() };

		// update object attributes object
		OBJECT_ATTRIBUTES oAttributes;
		InitializeObjectAttributes(&oAttributes, nullptr, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
		oAttributes.ObjectName = &tPathU;

		// get an open file handle
		HANDLE hFindFile;
		IO_STATUS_BLOCK IoStatusBlock;
		NTSTATUS Status = NtOpenFile(&hFindFile, FILE_LIST_DIRECTORY | SYNCHRONIZE,
			&oAttributes, &IoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT |
			((oEntry.IsRoot) ? 0 : FILE_OPEN_REPARSE_POINT));

		if (Status == STATUS_ACCESS_DENIED)
		{
			InputOutput::AddError(L"Access denied error occurred while enumerating directory");
			CompleteEntry(oEntry);
			++iFilesEnumerationFailures;
			continue;
		}
		else if (Status == STATUS_OBJECT_PATH_NOT_FOUND ||
			Status == STATUS_OBJECT_NAME_NOT_FOUND)
		{
			InputOutput::AddError(L"Path not found error occurred while enumerating directory");
			CompleteEntry(oEntry);
			++iFilesEnumerationFailures;
			continue;
		}
		else if (Status != STATUS_SUCCESS)
		{
			InputOutput::AddError(L"Unknown error occurred while enumerating directory");
			CompleteEntry(oEntry);
			++iFilesEnumerationFailures;
			continue;
		}

		// enumerate files in the directory
		for (bool bFirstRun = true; true; bFirstRun = false)
		{
			Status = NtQueryDirectoryFile(hFindFile, nullptr, nullptr, nullptr, &IoStatusBlock,
				DirectoryInfo, MAX_DIRECTORY_BUFFER, (FILE_INFORMATION_CLASS)FileDirectoryInformation,
				FALSE, nullptr, (bFirstRun) ? TRUE : FALSE);

			// done processing
			if (Status == STATUS_NO_MORE_FILES) break;

			if (Status != 0)
			{
				InputOutput::AddError(L"An error occurred while enumerating items in the directory");
				break;
			}

			for (auto* oInfo = (FILE_DIRECTORY_INFORMATION *)DirectoryInfo;
				oInfo != nullptr; oInfo = (FILE_DIRECTORY_INFORMATION *)((BYTE *)oInfo + oInfo->NextEntryOffset))
			{
				// continue immediately if we get the '.' or '..' entries
				if (IsDirectory(oInfo->FileAttributes))
				{
					if (((oInfo->FileNameLength == 2 * sizeof(WCHAR)) && memcmp(oInfo->FileName, L"..", 2 * sizeof(WCHAR)) == 0) ||
						((oInfo->FileNameLength == 1 * sizeof(WCHAR)) && memcmp(oInfo->FileName, L".", 1 * sizeof(WCHAR)) == 0))
					{
						if (oInfo->NextEntryOffset == 0) break; else continue;
					}
				}

				// construct the entry
				ObjectEntry oSubEntry;
				oSubEntry.IsRoot = false;
				oSubEntry.Attributes = oInfo->FileAttributes;
				oSubEntry.Name += oEntry.Name + ((oEntry.IsRoot && oEntry.Name.back() == '\\') ? L"" : L"\\")
					+ std::wstring(oInfo->FileName, oInfo->FileNameLength / sizeof(WCHAR));

				// if a leaf object, just process immediately and don't worry about putting it on the queue
				if (!IsDirectory(oSubEntry.Attributes) || IsReparsePoint(oSubEntry.Attributes))
				{
					// do security analysis
					AnalyzeSecurity(oSubEntry);
					CompleteEntry(oSubEntry, false);
				}
				else
				{
					++iFilesToProcess;
					oScanQueue.push(oSubEntry);
				}

				// this loop is complete, exit
				if (oInfo->NextEntryOffset == 0) break;
			}
		}

		// cleanup
		NtClose(hFindFile);
		CompleteEntry(oEntry);
	}
}

VOID BeginFileScan()
{
	// startup some threads for processing
	std::vector<std::thread *> oThreads;
	for (USHORT iNum = 0; iNum < InputOutput::MaxThreads(); iNum++)
		oThreads.push_back(new std::thread(AnalyzingQueue));

	for (auto sPath : InputOutput::ScanPaths())
	{
		// to get the process started, we need to have one entry so
		// we will set that to the passed argument
		ObjectEntry oEntryFirst;
		oEntryFirst.IsRoot = true;

		// make a local copy of the path since we may have to alter it
		// handle special case where a drive root is specified
		// we must ensure it takes the form x:\. to resolve correctly
		const size_t iSemiColon = sPath.rfind(L':');
		if (iSemiColon != std::wstring::npos)
		{
			std::wstring sEnd = sPath.substr(iSemiColon);
			if (sEnd == L":" || sEnd == L":\\")
			{
				sPath = sPath.substr(0, iSemiColon) + L":\\.";
			}
		}

		// convert the path to a long path that is compatible with the other call
		UNICODE_STRING tPathU;
		RtlDosPathNameToNtPathName_U(sPath.c_str(), &tPathU, nullptr, nullptr);

		// copy it to a null terminated string
		oEntryFirst.Name = std::wstring(tPathU.Buffer, tPathU.Length / sizeof(WCHAR));
		oEntryFirst.Attributes = GetFileAttributes(oEntryFirst.Name.c_str());

		// free the buffer returned previously
		RtlFreeUnicodeString(&tPathU);

		// add this entry to being processing
		++iFilesToProcess;
		oScanQueue.push(oEntryFirst);
	}

	// wait until all threads complete
	while (iFilesToProcess > 0)
	{
		std::unique_lock<std::mutex> oLock(oSyncVarMutex);
		oSyncVar.wait(oLock);
	}

	// send in some empty entries to tell the thread to stop waiting
	for (USHORT iNum = 0; iNum < InputOutput::MaxThreads(); iNum++)
	{
		ObjectEntry oEntry = { L"", 0, FALSE };
		oScanQueue.push(oEntry);
	}

	// wait for the threads to complete
	for (auto& oThread : oThreads)
	{
		oThread->join();
		delete oThread;
	}
}

int wmain(int iArgs, WCHAR * aArgs[])
{
	// allow output of unicode characters
	_setmode(_fileno(stderr), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);

	// print standard header
	wprintf(L"===============================================================================\n");
	wprintf(L"= Repacls Version %hs by Bryan Berns\n", VERSION_STRING);
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

	// process each argument in the queue
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
	BeginFileScan();
	const ULONGLONG iTimeStop = GetTickCount64();

	// print out statistics
	wprintf(L"===============================================================================\n");
	wprintf(L"= Total Scanned: %llu\n", (ULONGLONG)iFilesScanned);
	wprintf(L"= Read Failures: %llu\n", (ULONGLONG)iFilesEnumerationFailures);
	wprintf(L"= Enumeration Failures: %llu\n", (ULONGLONG)iFilesReadFailures);
	wprintf(L"= Update Successes: %llu\n", (ULONGLONG)iFilesUpdatedSuccess);
	wprintf(L"= Update Failures: %llu\n", (ULONGLONG)iFilesUpdatedFailure);
	wprintf(L"= Time Elapsed: %.3f\n", ((double)(iTimeStop - iTimeStart)) / 1000.0);
	wprintf(L"= Note: Update statistics do not include changes due to inherited rights.\n");
	wprintf(L"===============================================================================\n");
}