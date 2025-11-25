#include "Operation.h"
#include "InputOutput.h"
#include "Helpers.h"

#include <regex>

PSID Operation::GetSidFromAce(PACE_ACCESS_HEADER tAce) noexcept
{
	PSID pSid = &reinterpret_cast<ACCESS_ALLOWED_ACE*>(tAce)->SidStart;
	if (tAce->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
		tAce->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE ||
		tAce->AceType == SYSTEM_AUDIT_OBJECT_ACE_TYPE)
	{
		ACCESS_ALLOWED_OBJECT_ACE* oObjectAce = reinterpret_cast<ACCESS_ALLOWED_OBJECT_ACE*>(tAce);
		LPBYTE pSidStart = reinterpret_cast<LPBYTE>(&oObjectAce->ObjectType);
		if (oObjectAce->Flags & ACE_OBJECT_TYPE_PRESENT) pSidStart += sizeof(GUID);
		if (oObjectAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) pSidStart += sizeof(GUID);
		pSid = (SID*)pSidStart;
	}
	return pSid;
}

bool Operation::ProcessAclAction(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	// return immediately if acl is null
	if (tCurrentAcl == nullptr) return false;

	// flag to note whether a change was actually made
	bool bMadeChange = false;
	bool bSkipIncrement = false;

	PACE_ACCESS_HEADER tAce = FirstAce(tCurrentAcl);
	for (ULONG iEntry = 0; iEntry < tCurrentAcl->AceCount;
		tAce = (bSkipIncrement) ? tAce : NextAce(tAce), iEntry += (bSkipIncrement) ? 0 : 1)
	{
		// reset skip increment variable
		bSkipIncrement = false;

		// do not bother with inherited aces
		if (IsInherited(tAce)) continue;

		// convenience variable for sid associated with ace
		PSID const tCurrentSid = GetSidFromAce(tAce);

		PSID tResultantSid;
		const SidActionResult tResult = DetermineSid(sSdPart, tObjectEntry, tCurrentSid, tResultantSid);

		if (tResult == Remove)
		{
			DeleteAce(tCurrentAcl, iEntry);
			bMadeChange = true;
			bSkipIncrement = true;
			continue;
		}
		else if (tResult == Replace)
		{
			PSID const tOldSid = GetSidFromAce(tAce);
			PSID const tNewSid = tResultantSid;
			const DWORD iOldLen = SidGetLength(tOldSid);
			const DWORD iNewLen = SidGetLength(tNewSid);

			// if the old sid in the ace matches the new sid, just return immediately
			if (SidMatch(tOldSid, tNewSid)) return false;

			// at this point, we know we are going to make a change so set the flag
			bMadeChange = true;

			// if lengths are equals just overwrite the old sid with the new sid
			if (iOldLen == iNewLen)
			{
				memcpy(tOldSid, tNewSid, iNewLen);
				continue;
			}

			// casted convenience variables
			PACL const tAcl = tCurrentAcl;
			PBYTE const tAclLoc = (PBYTE)tAcl;
			PBYTE const tAceLoc = (PBYTE)tAce;
			PBYTE const tOldSidLoc = static_cast<PBYTE>(tOldSid);

			// if the new length is less than the old length, then copy the new sid
			// and then shift the remaining bytes in the acl down to collapse the gap
			if (iNewLen < iOldLen)
			{
				memcpy(tOldSid, tNewSid, iNewLen);
				memmove(tOldSidLoc + iNewLen, tOldSidLoc + iOldLen, tAcl->AclSize - ((tOldSidLoc - tAclLoc) + iOldLen));
			}

			// if the size is bigger than we should expand the acl to accommodate the
			// new size and then copy the various parts into the new memory
			else
			{
				PBYTE const tNewAcl = static_cast<PBYTE>(LocalAlloc(LMEM_FIXED, tAcl->AclSize + (iNewLen - iOldLen)));
				if (tNewAcl == nullptr)
				{
					Print(L"ERROR: Unable to allocate memory for new SID.");
					std::exit(-1);
				}

				memcpy(tNewAcl, tAclLoc, tOldSidLoc - tAclLoc);
				memcpy(tNewAcl + (tOldSidLoc - tAclLoc), tNewSid, iNewLen);
				memcpy(tNewAcl + (tOldSidLoc - tAclLoc) + iNewLen, tOldSidLoc + iOldLen, tAcl->AclSize - ((tOldSidLoc - tAclLoc) + iOldLen));

				// free the existing pointer and update the value that was passed
				if (bAclReplacement) LocalFree(tAcl);
				tAce = (PACE_ACCESS_HEADER)(tNewAcl + (tAceLoc - tAclLoc));
				tCurrentAcl = (PACL)tNewAcl;
				bAclReplacement = true;
			}

			// update size in ace header
			tAce->AceSize += static_cast<WORD>(iNewLen - iOldLen);

			// update size in acl header and return size differential
			tCurrentAcl->AclSize += static_cast<WORD>(iNewLen - iOldLen);
		}
	}

	// return flag to indicate something has actually changed
	return bMadeChange;
}

std::vector<std::wstring> Operation::SplitArgs(std::wstring sInput, const std::wstring & sDelimiter)
{
	const std::wregex oRegex(sDelimiter);
	const std::wsregex_token_iterator oFirst{ sInput.begin(), sInput.end(), oRegex, -1 }, oLast;
	return { oFirst, oLast };
}

bool Operation::ProcessSidAction(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID & tCurrentSid, bool & bSidReplacement)
{
	PSID tResultantSid;
	const SidActionResult tResult = DetermineSid(sSdPart, tObjectEntry, tCurrentSid, tResultantSid);
	bool bMadeChange = false;

	if (tResult == Remove)
	{
		// populate the default sid value to be used if the sid is empty
		tCurrentSid = DefaultSidWhenEmpty;
		bMadeChange = true;
	}
	else if (tResult == Replace)
	{
		// only process change if sid is actually different
		if (SidNotMatch(tCurrentSid, tResultantSid))
		{
			// substitute sid
			tCurrentSid = tResultantSid;
			bMadeChange = true;
		}
	}

	// return flag to indicate something has actually changed
	return bMadeChange;
}

Operation::Operation(std::queue<std::wstring> & oArgList) 
{
	SID_IDENTIFIER_AUTHORITY tAuthNt = SECURITY_NT_AUTHORITY;
	AllocateAndInitializeSid(&tAuthNt, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &DefaultSidWhenEmpty);
};

std::vector<std::wstring> Operation::ProcessAndCheckArgs(int iArgsRequired, std::queue<std::wstring> & oArgList, const std::wstring & sDelimiter)
{
	// check if around arguments exist yet
	if (iArgsRequired > 0 && oArgList.empty())
	{
		Print(L"ERROR: An option that was specified is missing a required parameter.");
		std::exit(-1);
	}

	// parse the parameters, splitting on :
	const std::wstring sArg = oArgList.front(); oArgList.pop();
	std::vector<std::wstring> oSubArgs = SplitArgs(sArg, sDelimiter);

	// verify we have enough parameters
	if (oSubArgs.size() < static_cast<size_t>(iArgsRequired))
	{
		Print(L"ERROR: An option that was specified is missing a required parameter.");
		std::exit(-1);
	}

	// return the parsed args
	return oSubArgs;
}

void Operation::ProcessGranularTargetting(std::wstring sScope)
{
	// parse the parameters, splitting on :
	const std::wregex oRegex(L",");
	const std::wsregex_token_iterator oFirst{ sScope.begin(), sScope.end(), oRegex, -1 }, oLast;
	const std::vector<std::wstring> sScopeOpts = { oFirst, oLast };

	// default all to false if calling this method
	AppliesToDacl = false;
	AppliesToSacl = false;
	AppliesToOwner = false;
	AppliesToGroup = false;
	AppliesToObject = false;

	for (auto& sScopeOpt : sScopeOpts)
	{
		if (sScopeOpt == L"DACL") AppliesToDacl = true;
		else if (sScopeOpt == L"SACL") AppliesToSacl = true;
		else if (sScopeOpt == L"OWNER") AppliesToOwner = true;
		else if (sScopeOpt == L"GROUP") AppliesToGroup = true;
		else
		{
			// complain
			Print(L"ERROR: Unrecognized scope qualifier '{}'", sScopeOpt);
			std::exit(-1);
		}
	}
}
