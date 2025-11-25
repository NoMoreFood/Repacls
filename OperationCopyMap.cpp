#include "OperationCopyMap.h"
#include "OperationCheckCanonical.h"
#include "InputOutput.h"
#include "Helpers.h"

#include <fstream>
#include <locale>
#include <codecvt>

ClassFactory<OperationCopyMap> OperationCopyMap::RegisteredFactory(GetCommand());

OperationCopyMap::OperationCopyMap(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	const std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList, L"\\0");

	// open the file
	std::wifstream fFile(sSubArgs.at(0).c_str());

	// adapt the stream to read windows unicode files
	(void) fFile.imbue(std::locale(fFile.getloc(), new std::codecvt_utf8<wchar_t,
		0x10ffff, std::consume_header>));

	// read the file line-by-line
	std::wstring sLine;
	while (std::getline(fFile, sLine))
	{
		// parse the search and replace account which are separated by a ':' character
		// also, sometimes a carriage return appears in the input stream so adding
		// it here ensures it is stripped from the very end
		std::vector<std::wstring> oLineItems = SplitArgs(sLine, L":|\r");

		// verify the line contains at least two elements
		if (oLineItems.size() != 2)
		{
			Print(L"ERROR: The replacement map line '{}' is invalid.", sLine);
			std::exit(-1);
		}
		
		// verify search sid
		const PSID tSearchSid = GetSidFromName(oLineItems.at(0));
		if (tSearchSid == nullptr)
		{
			Print(L"ERROR: The map search value '{}' is invalid.", oLineItems.at(0));
			std::exit(-1);
		}

		// verify replace sid
		const PSID tReplaceSid = GetSidFromName(oLineItems.at(1));
		if (tReplaceSid == nullptr)
		{
			Print(L"ERROR: The map replace value '{}' is invalid.", oLineItems.at(1));
			std::exit(-1);
		}

		// get the reverse lookup for the search - since the ACE could contain a sid history sid
		// we rely on doing a reverse lookup to normalize any accounts to update
		std::wstring sSearchAccount = GetNameFromSidEx(tSearchSid);

		// update the map
		oCopyMap[sSearchAccount] = tReplaceSid;
	}

	// cleanup
	fFile.close();

	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
}

bool OperationCopyMap::ProcessAclAction(const WCHAR* const sSdPart, ObjectEntry& tObjectEntry, PACL& tCurrentAcl, bool& bAclReplacement)
{
	// check on canonicalization status so it can error if the acl needs to be updated
	const bool bAclIsCanonical = OperationCheckCanonical::IsAclCanonical(tCurrentAcl);

	// check explicit effective rights from sid (no groups)
	bool bAclIsDirty = false;
	if (tCurrentAcl != nullptr)
	{
		PACE_ACCESS_HEADER tAceDacl = FirstAce(tCurrentAcl);
		for (LONG iEntry = 0; iEntry < tCurrentAcl->AceCount; tAceDacl =
			(iEntry == -1) ? FirstAce(tCurrentAcl) : NextAce(tAceDacl), iEntry++)
		{
			// do not bother with inherited aces
			if (IsInherited(tAceDacl)) continue;

			// see if this ace matches a sid in the copy list
			const PSID tSid = GetSidFromAce(tAceDacl);
			std::wstring sSourceAccountName = GetNameFromSidEx(tSid);
			const auto oInteractor = oCopyMap.find(sSourceAccountName);
			if (oInteractor == oCopyMap.end()) continue;

			// translate the old sid to an account name
			std::wstring sTargetAccountName = GetNameFromSidEx(oInteractor->second, nullptr);
			if (sTargetAccountName.empty())	continue;

			// record the status to report
			std::wstring sInfoToReport = L"Copying '" + sSourceAccountName + L"' to '" + sTargetAccountName + L"'";

			// determine access mode
			ACCESS_MODE tMode = NOT_USED_ACCESS;
			if (tAceDacl->AceType == ACCESS_ALLOWED_ACE_TYPE)
			{
				tMode = GRANT_ACCESS;
			}
			else if (tAceDacl->AceType == ACCESS_DENIED_ACE_TYPE)
			{
				tMode = DENY_ACCESS;
			}
			else if (tAceDacl->AceType == SYSTEM_AUDIT_ACE_TYPE)
			{
				if (CheckBitSet(tAceDacl->AceFlags, SUCCESSFUL_ACCESS_ACE_FLAG))
				{
					tMode = static_cast<ACCESS_MODE>(tMode | SET_AUDIT_SUCCESS);
				}
				if (CheckBitSet(tAceDacl->AceFlags, FAILED_ACCESS_ACE_FLAG))
				{
					tMode = static_cast<ACCESS_MODE>(tMode | SET_AUDIT_FAILURE);
				}
			}
			else
			{
				// unknown type; skipping
				continue;
			}

			// since SetEntriesInAcl reacts poorly / unexpectedly in cases where the
			// acl is not canonical, just error out and continue on
			if (!bAclIsCanonical)
			{
				InputOutput::AddError(L"Could not copy account '" + sTargetAccountName + 
					L"' because access control list is not canonical.", sSdPart);
				continue;
			}

			// create a structure to add the missing permissions
			EXPLICIT_ACCESS tEa;
			tEa.grfAccessPermissions = tAceDacl->Mask;
			tEa.grfAccessMode = tMode;
			tEa.grfInheritance = VALID_INHERIT_FLAGS & tAceDacl->AceFlags;
			tEa.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			tEa.Trustee.pMultipleTrustee = nullptr;
			tEa.Trustee.ptstrName = static_cast<LPWSTR>(oInteractor->second);
			tEa.Trustee.TrusteeForm = TRUSTEE_IS_SID;
			tEa.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;

			// special case since SetEntriesInAcl does not handle setting both success
			// and failure types together
			PACL tNewDacl = nullptr;
			DWORD iError = 0;
			if (CheckBitSet(tEa.grfAccessMode, SET_AUDIT_SUCCESS) &&
				CheckBitSet(tEa.grfAccessMode, SET_AUDIT_FAILURE))
			{
				PACL tNewDaclTmp = nullptr;
				tEa.grfAccessMode = SET_AUDIT_SUCCESS;
				iError = SetEntriesInAcl(1, &tEa, tCurrentAcl, &tNewDaclTmp);
				tEa.grfAccessMode = SET_AUDIT_FAILURE;
				if (iError == ERROR_SUCCESS) {
					SetEntriesInAcl(1, &tEa, tNewDaclTmp, &tNewDacl);
					LocalFree(tNewDaclTmp);
				}
			}
			else
			{
				// merge the new trustee into the dacl
				iError = SetEntriesInAcl(1, &tEa, tCurrentAcl, &tNewDacl);
			}

			// verify the new acl could be generated
			if (iError != ERROR_SUCCESS || tNewDacl == nullptr)
			{
				//std::wstring sTargetAccountName = GetNameFromSid(tTargetAccountSid);
				InputOutput::AddError(L"Could not copy '" + sTargetAccountName + 
					L"' to access control list (" + std::to_wstring(iError) + L").", sSdPart);
				continue;
			}

			// see if the old and new acl match
			if (tCurrentAcl->AclSize == tNewDacl->AclSize &&
				memcmp(tCurrentAcl, tNewDacl, tCurrentAcl->AclSize) == 0)
			{
				// if acls match then no change was made and we do not need
				// to mark this as dirty or restart the enumeration 
				LocalFree(tNewDacl);
			}
			else
			{
				// report status
				InputOutput::AddInfo(sInfoToReport, sSdPart);

				// cleanup the old dacl (if necessary) and assign our new active dacl
				if (bAclReplacement) LocalFree(tCurrentAcl);
				tCurrentAcl = tNewDacl;
				bAclReplacement = true;
				bAclIsDirty = true;
				iEntry = -1;
			}
		}
	}

	return bAclIsDirty;
}