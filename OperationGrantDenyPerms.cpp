#include "OperationGrantDenyPerms.h"
#include "OperationCheckCanonical.h"
#include "InputOutput.h"
#include "Helpers.h"

#include <map>
#include <regex>

ClassFactory<OperationGrantDenyPerms> OperationGrantDenyPerms::RegisteredFactoryGrant(GetCommandAdd());
ClassFactory<OperationGrantDenyPerms> OperationGrantDenyPerms::RegisteredFactoryDeny(GetCommandDeny());

OperationGrantDenyPerms::OperationGrantDenyPerms(std::queue<std::wstring>& oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(2, oArgList);

	// store off variables for reporting later
	sIdentity = sSubArgs.at(0);
	sPerms = sSubArgs.at(1);
	
	// constructor extract the list of perm strings
	ConvertToUpper(sPerms);
	std::vector<std::wstring> aPermList;
	const std::wregex oPermsRegex(LR"(\(([A-Z]+)\))");
	for (std::wsregex_iterator oPermsIterator(sPerms.begin(), sPerms.end(), oPermsRegex,
		std::regex_constants::match_continuous); oPermsIterator != std::wsregex_iterator(); ++oPermsIterator) {
		aPermList.push_back((*oPermsIterator).str(1));
	}

	// error if no options set
	if (aPermList.empty())
	{
		wprintf(L"ERROR: Invalid or no permissions string specified for parameter '%s'.\n", GetCommandAdd().c_str());
		exit(-1);
	}

	// populate default values
	tEa.grfAccessMode = (_wcsicmp(sCommand.c_str(), GetCommandAdd().c_str()) == 0) ? GRANT_ACCESS : DENY_ACCESS;
	tEa.grfInheritance = NO_INHERITANCE;
	tEa.grfAccessPermissions = 0;
	tEa.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
	tEa.Trustee.pMultipleTrustee = nullptr;
	tEa.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	tEa.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;

	// see if names could be resolved
	tEa.Trustee.ptstrName = (LPWCH) GetSidFromName(sIdentity);
	if (tEa.Trustee.ptstrName == nullptr)
	{
		wprintf(L"ERROR: Invalid account '%s' specified for parameter '%s'.\n", 
			sIdentity.c_str(), GetCommandAdd().c_str());
		exit(-1);
	}

	// list for easily parsing icacls permissions access syntax
	const std::map<const std::wstring, DWORD> aPermsMap = 
	{
		/* combo perms */
		{ L"N", 0 },
		{ L"F", FILE_ALL_ACCESS },
		{ L"M", FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE },
		{ L"RX", FILE_GENERIC_READ | FILE_GENERIC_EXECUTE },
		{ L"R", FILE_GENERIC_READ },
		{ L"W", FILE_GENERIC_WRITE },
		{ L"D", SYNCHRONIZE | DELETE },

		/* itemized perms */
		{ L"DE", DELETE },
		{ L"RC", READ_CONTROL },
		{ L"WDAC", WRITE_DAC },
		{ L"WO", WRITE_OWNER },
		{ L"S", SYNCHRONIZE },
		{ L"AS", ACCESS_SYSTEM_SECURITY },
		{ L"MA", MAXIMUM_ALLOWED },
		{ L"GR", GENERIC_READ },
		{ L"GW", GENERIC_WRITE },
		{ L"GE", GENERIC_EXECUTE },
		{ L"GA", GENERIC_ALL },
		{ L"RD", FILE_READ_DATA | FILE_LIST_DIRECTORY },
		{ L"WD", FILE_WRITE_DATA | FILE_ADD_FILE },
		{ L"AD", FILE_APPEND_DATA | FILE_ADD_SUBDIRECTORY },
		{ L"REA", FILE_READ_EA },
		{ L"WEA", FILE_WRITE_EA },
		{ L"X", FILE_EXECUTE | FILE_EXECUTE },
		{ L"DC", FILE_DELETE_CHILD },
		{ L"RA", FILE_READ_ATTRIBUTES },
		{ L"WA", FILE_WRITE_ATTRIBUTES }
	};

	// list for easily parsing icacls inheritance syntax
	const std::map<const std::wstring, DWORD> aInheritMap =
	{
		{ L"OI", OBJECT_INHERIT_ACE },
		{ L"CI", CONTAINER_INHERIT_ACE },
		{ L"IO", NO_PROPAGATE_INHERIT_ACE },
		{ L"NP", INHERIT_ONLY_ACE }
	};

	// decode the permissions string to their binary values
	for (const std::wstring & sKey : aPermList)
	{
		if (aInheritMap.find(sKey) != aInheritMap.end()) tEa.grfInheritance |= aInheritMap.at(sKey);
		else if (aPermsMap.find(sKey) != aPermsMap.end()) tEa.grfAccessPermissions |= aPermsMap.at(sKey);
		else
		{
			// complain
			wprintf(L"ERROR: Invalid permission string '%s' specified for parameter '%s'.\n", sPerms.c_str(), GetCommandAdd().c_str());
			exit(-1);
		}
	}
	
	// do a reverse lookup on the name for info messages
	sIdentity = GetNameFromSidEx((PSID)tEa.Trustee.ptstrName);

	// flag this as being an ace-level action
	AppliesToDacl = true;
}

bool OperationGrantDenyPerms::ProcessAclAction(const WCHAR* const sSdPart, ObjectEntry& tObjectEntry, PACL& tCurrentAcl, bool& bAclReplacement)
{
	// define what constitutes 'full control' based on the object
	const DWORD iObjectTypeMask = IsDirectory(tObjectEntry.Attributes)
		? ~0 : ~(CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE);

	// verify this is not already part of the ace as an inherited or explicit entry
	if (tCurrentAcl != nullptr)
	{
		PACE_ACCESS_HEADER tAceDacl = FirstAce(tCurrentAcl);
		for (ULONG iEntry = 0; iEntry < tCurrentAcl->AceCount; tAceDacl = NextAce(tAceDacl), iEntry++)
		{
			// skip other ace types that are not allowing accessing
			if ((tAceDacl->AceType == ACCESS_ALLOWED_ACE_TYPE &&
				tEa.grfAccessMode != GRANT_ACCESS) ||
				(tAceDacl->AceType == ACCESS_DENIED_ACE_TYPE &&
				tEa.grfAccessMode != DENY_ACCESS)) continue;

			// do not look at sids that are not the specified account
			const PSID tSid = GetSidFromAce(tAceDacl);
			if (SidNotMatch(tSid, ((PSID) tEa.Trustee.ptstrName))) continue;

			// skip if access mask is not exactly the same
			if (tAceDacl->Mask != tEa.grfAccessPermissions) continue;

			// skip this ace inheritance mask is not the same except if it is inherited
			if ((tAceDacl->AceFlags & ((DWORD) ~INHERITED_ACE)) != 
				(tEa.grfInheritance & iObjectTypeMask)) continue;

			// if we got this far, it means we have a duplicate ace so just skip it
			return false;
		}
	}

	// since SetEntriesInAcl reacts poorly / unexpectedly in cases where the
	// acl is not canonical, just error out and continue on
	if (!OperationCheckCanonical::IsAclCanonical(tCurrentAcl))
	{
		InputOutput::AddError(L"Could not modify permissions for because access control list is not canonical.", sSdPart);
		return false;
	}

	// merge the new trustee into the dacl
	PACL tNewDacl;
	if (SetEntriesInAcl(1, &tEa, tCurrentAcl, &tNewDacl) != ERROR_SUCCESS)
	{
		InputOutput::AddError(L"Could not modify permissions due to a system error.", sSdPart);
		return false;
	}

	// do not commit change is no actual change was made
	if (tCurrentAcl->AclSize == tNewDacl->AclSize &&
		memcmp(tCurrentAcl, tNewDacl, tCurrentAcl->AclSize) == 0)
	{
		LocalFree(tNewDacl);
		return false;
	}

	// cleanup the old dacl (if necessary) and assign our new active dacl
	if (bAclReplacement) LocalFree(tCurrentAcl);
	tCurrentAcl = tNewDacl;
	bAclReplacement = true;

	// flag to commit tag and cleanup dacl
	InputOutput::AddInfo(((tEa.grfAccessMode == GRANT_ACCESS) ? L"Granting '" : L"Denying '") 
		+ sIdentity + L"' with perms '" + sPerms + L"'", sSdPart);
	return true;
}
