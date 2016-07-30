#include "OperationAddAccountIfMissing.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationAddAccountIfMissing> * OperationAddAccountIfMissing::RegisteredFactory =
new ClassFactory<OperationAddAccountIfMissing>(GetCommand());

OperationAddAccountIfMissing::OperationAddAccountIfMissing(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// exit if there are not enough arguments to part
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// fetch params
	tAddSid = GetSidFromName(sSubArgs[0]);

	// see if names could be resolved
	if (tAddSid == NULL)
	{
		// complain
		wprintf(L"ERROR: Invalid account '%s' specified for parameter '%s'.\n", sSubArgs[0].c_str(), GetCommand().c_str());
		exit(-1);
	}

	// do a reverse lookup on the name for info messages
	sAddSid = GetNameFromSidEx(tAddSid);

	// flag this as being an ace-level action
	AppliesToDacl = true;
}

bool OperationAddAccountIfMissing::ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	// check explicit effective rights from sid (no groups)
	DWORD iPermissionMask = 0;
	DWORD iInheritMask = 0;
	if (tCurrentAcl != NULL)
	{
		ACCESS_ACE * tAceDacl = FirstAce(tCurrentAcl);
		for (ULONG iEntry = 0; iEntry < tCurrentAcl->AceCount; tAceDacl = NextAce(tAceDacl), iEntry++)
		{
			// skip other ace types that are not allowing accessing
			if (tAceDacl->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) continue;

			// do not look at sids that are not the specified account
			if (SidNotMatch(&tAceDacl->Sid, tAddSid)) continue;

			// merge if the effective permissions
			// ignore the inherited ace flag since its not relevant
			iPermissionMask |= tAceDacl->Mask;
			iInheritMask |= (tAceDacl->Header.AceFlags & ~INHERITED_ACE);
		}
	}

	// define what constitutes 'full control' based on the object
	const DWORD iDesiredInheritMask = IsDirectory(tObjectEntry.Attributes) 
		? (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE) : 0;

	// only attempt to add permissions if our flags do not match
	if (iPermissionMask != FILE_ALL_ACCESS || iInheritMask != iDesiredInheritMask)
	{
		EXPLICIT_ACCESS tEa;
		tEa.grfAccessPermissions = FILE_ALL_ACCESS;
		tEa.grfAccessMode = GRANT_ACCESS;
		tEa.grfInheritance = iDesiredInheritMask;
		tEa.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
		tEa.Trustee.pMultipleTrustee = NULL;
		tEa.Trustee.ptstrName = (LPWSTR) tAddSid;
		tEa.Trustee.TrusteeForm = TRUSTEE_IS_SID;
		tEa.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;

		// merge the new trustee into the dacl
		PACL tNewDacl;
		SetEntriesInAcl(1, &tEa, tCurrentAcl, &tNewDacl);

		// cleanup the old dacl (if necessary) and assign our new active dacl
		if (bAclReplacement) LocalFree(tCurrentAcl);
		tCurrentAcl = tNewDacl;

		// flag to commit tag and cleanup dacl
		InputOutput::AddInfo(L"Adding full control for '" + sAddSid + L"'", sSdPart);
		bAclReplacement = true;
		return true;
	}

	return false;
}
