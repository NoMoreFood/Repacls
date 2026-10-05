#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#include <Windows.h>
#include <vector>
#include <lmcons.h>

#include <string>
#include <atomic>

#include "Operation.h"
#include "InputOutput.h"
#include "Helpers.h"
#include "DriverKitPartial.h"

#include "Object.h"
#include "Processor.h"

Processor::Processor(const std::vector<Operation*>& poOperationList, bool pbFetchDacl, bool pbFetchSacl, bool pbFetchOwner, bool pbFetchGroup) :
	bFetchDacl(pbFetchDacl), bFetchSacl(pbFetchSacl), bFetchOwner(pbFetchOwner), bFetchGroup(pbFetchGroup),
	oOperationList(poOperationList)
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
		++ItemsReadFailures;
		SmartPointer<WCHAR*> sError(LocalFree, nullptr);
		const size_t iSize = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
			nullptr, iError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&sError), 0, nullptr);
		InputOutput::AddError(L"Unable to read security information", (iSize == 0) ? L"" : *&sError);

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

	// release components allocated separately from the descriptor
	auto ReleaseParts = [&]()
	{
		if (bDaclCleanupRequired) { LocalFree(tAclDacl); bDaclCleanupRequired = false; }
		if (bSaclCleanupRequired) { LocalFree(tAclSacl); bSaclCleanupRequired = false; }
		if (bOwnerCleanupRequired) { LocalFree(tOwnerSid); bOwnerCleanupRequired = false; }
		if (bGroupCleanupRequired) { LocalFree(tGroupSid); bGroupCleanupRequired = false; }
	};

	// bind working components, clearing pointers for absent acls
	auto ReadParts = [&]()
	{
		tAclDacl = nullptr;
		tAclSacl = nullptr;
		BOOL bItemPresent = FALSE;
		BOOL bItemDefaulted = FALSE;
		GetSecurityDescriptorDacl(tDesc, &bItemPresent, &tAclDacl, &bItemDefaulted);
		GetSecurityDescriptorSacl(tDesc, &bItemPresent, &tAclSacl, &bItemDefaulted);
		GetSecurityDescriptorOwner(tDesc, &tOwnerSid, &bItemDefaulted);
		GetSecurityDescriptorGroup(tDesc, &tGroupSid, &bItemDefaulted);
	};

	// used for one-shot operations like reset children or inheritance
	DWORD iSpecialCommitMergeFlags = 0;

	// loop through the instruction list
	for (const auto& oOperation : oOperationList)
	{
		// skip if this operation does not apply to the root/children based on the operation
		if (oOperation->AppliesToRootOnly && oEntry.Depth != 0 ||
			oOperation->AppliesToChildrenOnly && oEntry.Depth == 0)
		{
			continue;
		}

		// merge any special commit flags
		constexpr DWORD iDaclProtection = PROTECTED_DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION;
		constexpr DWORD iSaclProtection = PROTECTED_SACL_SECURITY_INFORMATION | UNPROTECTED_SACL_SECURITY_INFORMATION;
		if (oOperation->SpecialCommitFlags & iDaclProtection) iSpecialCommitMergeFlags &= ~iDaclProtection;
		if (oOperation->SpecialCommitFlags & iSaclProtection) iSpecialCommitMergeFlags &= ~iSaclProtection;
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
			// publish pending component changes before reading or replacing the whole descriptor
			if (bDaclIsDirty || bSaclIsDirty || bOwnerIsDirty || bGroupIsDirty || iSpecialCommitMergeFlags != 0)
			{
				SECURITY_DESCRIPTOR tCurrentDesc{};
				InitializeSecurityDescriptor(&tCurrentDesc, SECURITY_DESCRIPTOR_REVISION);
				DWORD iRevision = 0;
				GetSecurityDescriptorControl(tDesc, &tCurrentDesc.Control, &iRevision);
				tCurrentDesc.Control &= ~SE_SELF_RELATIVE;
				GetSecurityDescriptorRMControl(tDesc, &tCurrentDesc.Sbz1);
				SetSecurityDescriptorOwner(&tCurrentDesc, tOwnerSid,
					!bOwnerIsDirty && CheckBitSet(tCurrentDesc.Control, SE_OWNER_DEFAULTED));
				SetSecurityDescriptorGroup(&tCurrentDesc, tGroupSid,
					!bGroupIsDirty && CheckBitSet(tCurrentDesc.Control, SE_GROUP_DEFAULTED));
				SetSecurityDescriptorDacl(&tCurrentDesc,
					bDaclIsDirty || CheckBitSet(tCurrentDesc.Control, SE_DACL_PRESENT), tAclDacl,
					!bDaclIsDirty && CheckBitSet(tCurrentDesc.Control, SE_DACL_DEFAULTED));
				SetSecurityDescriptorSacl(&tCurrentDesc,
					bSaclIsDirty || CheckBitSet(tCurrentDesc.Control, SE_SACL_PRESENT), tAclSacl,
					!bSaclIsDirty && CheckBitSet(tCurrentDesc.Control, SE_SACL_DEFAULTED));
				if (iSpecialCommitMergeFlags & PROTECTED_DACL_SECURITY_INFORMATION)
					tCurrentDesc.Control |= SE_DACL_PROTECTED;
				if (iSpecialCommitMergeFlags & UNPROTECTED_DACL_SECURITY_INFORMATION)
					tCurrentDesc.Control &= ~SE_DACL_PROTECTED;
				if (iSpecialCommitMergeFlags & PROTECTED_SACL_SECURITY_INFORMATION)
					tCurrentDesc.Control |= SE_SACL_PROTECTED;
				if (iSpecialCommitMergeFlags & UNPROTECTED_SACL_SECURITY_INFORMATION)
					tCurrentDesc.Control &= ~SE_SACL_PROTECTED;

				// copy all components before releasing their current storage
				DWORD iDescSize = 0;
				MakeSelfRelativeSD(&tCurrentDesc, nullptr, &iDescSize);
				SmartPointer<PSECURITY_DESCRIPTOR> tUpdatedDesc(LocalFree, LocalAlloc(LMEM_FIXED, iDescSize));
				if (!tUpdatedDesc || !MakeSelfRelativeSD(&tCurrentDesc, tUpdatedDesc, &iDescSize))
				{
					InputOutput::AddError(L"Unable to assemble security descriptor.");
					continue;
				}
				ReleaseParts();
				if (bDescCleanupRequired) LocalFree(tDesc);
				tDesc = tUpdatedDesc;
				*tUpdatedDesc = nullptr;
				bDescCleanupRequired = true;
				ReadParts();
			}

			if (oOperation->ProcessSdAction(oEntry.Name, oEntry, tDesc, bDescCleanupRequired))
			{
				// cleanup previous operations if necessary
				ReleaseParts();

				// extract the elements from the raw security descriptor
				ReadParts();

				// extract relevant inheritance bits
				DWORD tRevisionInfo;
				SECURITY_DESCRIPTOR_CONTROL tControl;
				GetSecurityDescriptorControl(tDesc, &tControl, &tRevisionInfo);

				// convert inheritance bits to the special flags that control inheritance
				iSpecialCommitMergeFlags = CheckBitSet(SE_DACL_PROTECTED, tControl) ?
					PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION;
				iSpecialCommitMergeFlags |= CheckBitSet(SE_SACL_PROTECTED, tControl) ?
					PROTECTED_SACL_SECURITY_INFORMATION : UNPROTECTED_SACL_SECURITY_INFORMATION;

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
			if ((iError = SetNamedSecurityInfo(oEntry.Name.data(), oEntry.ObjectType, iInformationToCommit,
				(bOwnerIsDirty) ? tOwnerSid : nullptr, (bGroupIsDirty) ? tGroupSid : nullptr,
				(bDaclIsDirty) ? tAclDacl : nullptr, (bSaclIsDirty) ? tAclSacl : nullptr)) != ERROR_SUCCESS)
			{
				// attempt to look up error message
				SmartPointer<WCHAR*> sError(LocalFree, nullptr);
				const size_t iSize = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
					FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
					nullptr, iError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&sError), 0, nullptr);
				InputOutput::AddError(L"Unable to update security information", (iSize == 0) ? L"" : *&sError);

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
	ReleaseParts();
	if (bDescCleanupRequired) LocalFree(tDesc);
}

void Processor::CompleteEntry(ObjectEntry& oEntry)
{
	// flush any pending data from the last operation
	InputOutput::WriteToScreen();
}