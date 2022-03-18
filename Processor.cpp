#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#include <Windows.h>
#include <vector>
#include <lmcons.h>

#include <string>
#include <atomic>

#include "Operation.h"
#include "InputOutput.h"
#include "DriverKitPartial.h"

#include "Object.h"
#include "Processor.h"

Processor::Processor(std::vector<Operation*> poOperationList, bool pbFetchDacl, bool pbFetchSacl, bool pbFetchOwner, bool pbFetchGroup) :
	bFetchDacl(pbFetchDacl), bFetchSacl(pbFetchSacl), bFetchOwner(pbFetchOwner), bFetchGroup(pbFetchGroup),
	iInformationToLookup(0), oOperationList(poOperationList)
{
	if (bFetchDacl) iInformationToLookup |= DACL_SECURITY_INFORMATION;
	if (bFetchSacl) iInformationToLookup |= SACL_SECURITY_INFORMATION;
	if (bFetchOwner) iInformationToLookup |= OWNER_SECURITY_INFORMATION;
	if (bFetchGroup) iInformationToLookup |= GROUP_SECURITY_INFORMATION;
}

void Processor::AnalyzeSecurity(ObjectEntry & oEntry)
{
	// update file counter
	++ItemsScanned;

	// print out file name
	InputOutput::AddFile(oEntry.Name);

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
		(iError = GetNamedSecurityInfo(oEntry.Name.c_str(), oEntry.ObjectType,
		iInformationToLookup, (bFetchOwner) ? &tOwnerSid : nullptr, (bFetchGroup) ? &tGroupSid : nullptr,
		(bFetchDacl) ? &tAclDacl : nullptr, (bFetchSacl) ? &tAclSacl : nullptr, &tDesc)) != ERROR_SUCCESS)
	{
		// attempt to look up error message
		LPWSTR sError = nullptr;
		const size_t iSize = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
			nullptr, iError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&sError, 0, nullptr);
		InputOutput::AddError(L"Unable to read security information", (iSize == 0) ? L"" : sError);
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
		if (oOperation->AppliesToRootOnly && oEntry.Depth != 0 ||
			oOperation->AppliesToChildrenOnly && oEntry.Depth == 0)
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
				if (bDaclCleanupRequired) { LocalFree(tAclDacl); bDaclCleanupRequired = false; }
				if (bSaclCleanupRequired) { LocalFree(tAclDacl); bSaclCleanupRequired = false; }
				if (bOwnerCleanupRequired) { LocalFree(tAclDacl); bOwnerCleanupRequired = false; }
				if (bGroupCleanupRequired) { LocalFree(tAclDacl); bGroupCleanupRequired = false; }

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
			if ((iError = SetNamedSecurityInfo((LPWSTR)oEntry.Name.c_str(), oEntry.ObjectType, iInformationToCommit,
				(bOwnerIsDirty) ? tOwnerSid : nullptr, (bGroupIsDirty) ? tGroupSid : nullptr,
				(bDaclIsDirty) ? tAclDacl : nullptr, (bSaclIsDirty) ? tAclSacl : nullptr)) != ERROR_SUCCESS)
			{
				// attempt to look up error message
				LPWSTR sError = nullptr;
				const size_t iSize = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
					FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
					nullptr, iError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&sError, 0, NULL);
				InputOutput::AddError(L"Unable to update security information", (iSize == 0) ? L"" : sError);
				if (iSize > 0) LocalFree(sError);

				// clear out any remaining data
				InputOutput::WriteToScreen();

				++ItemsUpdatedFailure;
			}
			else
			{
				++ItemsUpdatedSuccess;
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

void Processor::CompleteEntry(ObjectEntry& oEntry)
{
	// flush any pending data from the last operation
	InputOutput::WriteToScreen();
}