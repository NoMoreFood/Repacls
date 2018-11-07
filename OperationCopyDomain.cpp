#include "OperationCopyDomain.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationCopyDomain> * OperationCopyDomain::RegisteredFactory =
new ClassFactory<OperationCopyDomain>(GetCommand());

OperationCopyDomain::OperationCopyDomain(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(2, oArgList);

	// fetch params
	tSourceDomain = GetSidFromName(sSubArgs[0]);
	tTargetDomain = GetSidFromName(sSubArgs[1]);

	// see if names could be resolved
	if (tSourceDomain == nullptr)
	{
		// complain
		wprintf(L"ERROR: Invalid source domain '%s' specified for parameter '%s'.\n", sSubArgs[0].c_str(), GetCommand().c_str());
		exit(0);
	}

	// see if names could be resolved
	if (tTargetDomain == nullptr)
	{
		// complain
		wprintf(L"ERROR: Invalid target domain '%s' specified for parameter '%s'.\n", sSubArgs[1].c_str(), GetCommand().c_str());
		exit(0);
	}

	// store the domain strings
	sSourceDomain = GetDomainNameFromSid(tSourceDomain);
	sTargetDomain = GetDomainNameFromSid(tTargetDomain);

	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;

	// target certain parts of the security descriptor
	if (sSubArgs.size() > 2) ProcessGranularTargetting(sSubArgs[2]);
}

bool OperationCopyDomain::ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	// check explicit effective rights from sid (no groups)
	bool bAclIsDirty = false;
	if (tCurrentAcl != NULL)
	{
		ACCESS_ACE * tAceDacl = FirstAce(tCurrentAcl);
		for (LONG iEntry = 0; iEntry < tCurrentAcl->AceCount; tAceDacl = 
			(iEntry == -1) ? FirstAce(tCurrentAcl) : NextAce(tAceDacl), iEntry++)
		{
			// see if this sid in the source domain
			BOOL bDomainSidsEqual = FALSE;
			if (EqualDomainSid(&tAceDacl->Sid, tSourceDomain, &bDomainSidsEqual) == 0 ||
				bDomainSidsEqual == FALSE)
			{
				// no match - cease processing this instruction
				continue;
			}

			const PISID tSidStruct = (PISID) &tAceDacl->Sid;
			const PISID tSidTargetDomain = (PISID)tTargetDomain;
			PSID tTargetAccountSid = NULL;
			std::wstring sInfoToReport = L"";
			if (tSidStruct->SubAuthorityCount == 5 &&
				tSidStruct->SubAuthority[0] == 21 &&
				tSidStruct->SubAuthority[4] < 1000)
			{
				// create a new sid that has the domain identifier of the target domain
				PSID tSidTmp = NULL;
				AllocateAndInitializeSid(&tSidStruct->IdentifierAuthority, tSidStruct->SubAuthorityCount,
					tSidStruct->SubAuthority[0], tSidTargetDomain->SubAuthority[1], tSidTargetDomain->SubAuthority[2],
					tSidTargetDomain->SubAuthority[3], tSidStruct->SubAuthority[4], 0, 0, 0, &tSidTmp);

				// lookup the target name and see if it exists
				std::wstring sTargetAccountName = GetNameFromSid(tSidTmp);
				FreeSid(tSidTmp);
				if (sTargetAccountName.size() == 0)	continue;

				// do a forward lookup on the name in order to get a reference to the 
				// SID that we do not have to worry about cleaning up
				tTargetAccountSid = GetSidFromName(sTargetAccountName);

				// lookup the source name for reporting
				std::wstring sSourceAccountName = GetNameFromSidEx(&tAceDacl->Sid);

				// record the status to report
				sInfoToReport = L"Copying Well Known '" + sSourceAccountName + L"' to '" + sTargetAccountName + L"'";
			}
			else
			{
				// translate the old sid to an account name
				std::wstring sSourceAccountName = GetNameFromSid(&tAceDacl->Sid, NULL);
				if (sSourceAccountName.size() == 0)	continue;

				// check to see if an equivalent account exists in the target domain
				std::wstring sTargetAccountName = sTargetDomain + (wcsstr(sSourceAccountName.c_str(), L"\\") + 1);
				tTargetAccountSid = GetSidFromName(sTargetAccountName);

				// continue if no match was found
				if (tTargetAccountSid == nullptr) continue;

				// do a reverse lookup to see if this might be a sid history item
				if (GetNameFromSidEx(tTargetAccountSid) == sSourceAccountName) continue;

				// stop processing if the account does not exist
				if (tTargetAccountSid == nullptr) continue;

				// record the status to report
				sInfoToReport = L"Copying '" + sSourceAccountName + L"' to '" + sTargetAccountName + L"'";
			}

			// determine access mode
			ACCESS_MODE tMode = NOT_USED_ACCESS;
			if (tAceDacl->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
			{
				tMode = GRANT_ACCESS;
			}
			else if (tAceDacl->Header.AceType == ACCESS_DENIED_ACE_TYPE)
			{
				tMode = DENY_ACCESS;
			}
			else if (tAceDacl->Header.AceType == SYSTEM_AUDIT_ACE_TYPE)
			{
				if (CheckBitSet(tAceDacl->Header.AceFlags, SUCCESSFUL_ACCESS_ACE_FLAG))
				{
					tMode = (ACCESS_MODE) (tMode | SET_AUDIT_SUCCESS);
				}
				if (CheckBitSet(tAceDacl->Header.AceFlags, FAILED_ACCESS_ACE_FLAG))
				{
					tMode = (ACCESS_MODE) (tMode | SET_AUDIT_FAILURE);
				}
			}
			else
			{
				// unknown type; skipping
				continue;
			}

			// create a structure to add the missing permissions
			EXPLICIT_ACCESS tEa;
			tEa.grfAccessPermissions = tAceDacl->Mask;
			tEa.grfAccessMode = tMode;
			tEa.grfInheritance = VALID_INHERIT_FLAGS & tAceDacl->Header.AceFlags;
			tEa.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			tEa.Trustee.pMultipleTrustee = NULL;
			tEa.Trustee.ptstrName = (LPWSTR) tTargetAccountSid;
			tEa.Trustee.TrusteeForm = TRUSTEE_IS_SID;
			tEa.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;

			// special case since SetEntriesInAcl does not handle setting both success
			// and failure types together
			PACL tNewDacl;
			if (CheckBitSet(tEa.grfAccessMode, SET_AUDIT_SUCCESS) &&
				CheckBitSet(tEa.grfAccessMode, SET_AUDIT_FAILURE))
			{
				PACL tNewDaclTmp;
				tEa.grfAccessMode = SET_AUDIT_SUCCESS;
				SetEntriesInAcl(1, &tEa, tCurrentAcl, &tNewDaclTmp);
				tEa.grfAccessMode = SET_AUDIT_FAILURE;
				SetEntriesInAcl(1, &tEa, tNewDaclTmp, &tNewDacl);
				LocalFree(tNewDaclTmp);
			}
			else
			{
				// merge the new trustee into the dacl
				SetEntriesInAcl(1, &tEa, tCurrentAcl, &tNewDacl);
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
