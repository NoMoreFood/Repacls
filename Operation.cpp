#include "Operation.h"
#include "InputOutput.h"
#include "Functions.h"

#include <regex>

bool Operation::ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	// return immediately if acl is null
	if (tCurrentAcl == NULL) return false;

	// flag to note whether a change was actually made
	bool bMadeChange = false;
	bool bSkipIncrement = false;

	ACCESS_ACE * tAce = FirstAce(tCurrentAcl);
	for (ULONG iEntry = 0; iEntry < tCurrentAcl->AceCount;
		tAce = (bSkipIncrement) ? tAce : NextAce(tAce), iEntry += (bSkipIncrement) ? 0 : 1)
	{
		// reset skip increment variable
		bSkipIncrement = false;

		// do not bother with inherited aces
		if (IsInherited(tAce)) continue;

		// convenience variable for sid associated with ace
		PSID const tCurrentSid = &tAce->Sid;

		PSID tResultantSid;
		SidActionResult tResult = DetermineSid(sSdPart, tObjectEntry, tCurrentSid, tResultantSid);

		if (tResult == SidActionResult::Remove)
		{
			DeleteAce(tCurrentAcl, iEntry);
			bMadeChange = true;
			bSkipIncrement = true;
			continue;
		}
		else if (tResult == SidActionResult::Replace)
		{
			PSID const tOldSid = &tAce->Sid;
			PSID const tNewSid = tResultantSid;
			const DWORD iOldLen = GetLengthSid(tOldSid);
			const DWORD iNewLen = GetLengthSid(tNewSid);

			// if the old sid in the ace matches the new sid, just return immediately
			if (SidMatch(&tAce->Sid, tNewSid)) return false;

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
			PBYTE const tOldSidLoc = (PBYTE)tOldSid;

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
				PBYTE const tNewAcl = (PBYTE)LocalAlloc(LMEM_FIXED, tAcl->AclSize + (iNewLen - iOldLen));
				memcpy(tNewAcl, tAclLoc, tOldSidLoc - tAclLoc);
				memcpy(tNewAcl + (tOldSidLoc - tAclLoc), tNewSid, iNewLen);
				memcpy(tNewAcl + (tOldSidLoc - tAclLoc) + iNewLen, tOldSidLoc + iOldLen, tAcl->AclSize - ((tOldSidLoc - tAclLoc) + iOldLen));

				// free the existing pointer and update the value that was passed
				if (bAclReplacement) LocalFree(tAcl);
				tAce = (PACCESS_ACE)(tNewAcl + (tAceLoc - tAclLoc));
				tCurrentAcl = (PACL)tNewAcl;
				bAclReplacement = true;
			}

			// update size in ace header
			tAce->Header.AceSize += (WORD)(iNewLen - iOldLen);

			// update size in acl header and return size differential
			tCurrentAcl->AclSize += (WORD)(iNewLen - iOldLen);
		}
	}

	// return flag to indicate something has actually changed
	return bMadeChange;
}

std::vector<std::wstring> Operation::SplitArgs(std::wstring sInput, std::wstring sDelimiter)
{
	std::wregex oRegex(sDelimiter);
	std::wsregex_token_iterator oFirst{ sInput.begin(), sInput.end(), oRegex, -1 }, oLast;
	return { oFirst, oLast };
}

bool Operation::ProcessSidAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID & tCurrentSid, bool & bSidReplacement)
{
	PSID tResultantSid;
	SidActionResult tResult = DetermineSid(sSdPart, tObjectEntry, tCurrentSid, tResultantSid);
	bool bMadeChange = false;

	if (tResult == SidActionResult::Remove)
	{
		// populate the default sid value to be used if the sid is empty
		tCurrentSid = DefaultSidWhenEmpty;
		bMadeChange = true;
	}
	else if (tResult == SidActionResult::Replace)
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

std::vector<std::wstring> Operation::ProcessAndCheckArgs(int iArgsRequired, std::queue<std::wstring> & oArgList, std::wstring sDelimiter)
{
	// check if around arguments exist yet
	if (iArgsRequired > 0 && oArgList.size() == 0)
	{
		exit(-1);
	}

	// parse the parameters, splitting on :
	std::wstring sArg = oArgList.front(); oArgList.pop();
	std::vector<std::wstring> oSubArgs = SplitArgs(sArg, sDelimiter);

	// verify we have enough parameters
	if (oSubArgs.size() < (size_t) iArgsRequired)
	{
		exit(-1);
	}

	// return the parsed args
	return oSubArgs;
}

void Operation::ProcessGranularTargetting(std::wstring sScope)
{
	// parse the parameters, splitting on :
	std::wregex oRegex(L",");
	std::wsregex_token_iterator oFirst{ sScope.begin(), sScope.end(), oRegex, -1 }, oLast;
	std::vector<std::wstring> sScopeOpts = { oFirst, oLast };

	// default all to false if calling this method
	AppliesToDacl = false;
	AppliesToSacl = false;
	AppliesToOwner = false;
	AppliesToGroup = false;

	for (std::vector<std::wstring>::iterator oScope = sScopeOpts.begin();
		oScope != sScopeOpts.end(); oScope++)
	{
		if (*oScope == L"DACL") AppliesToDacl = true;
		else if (*oScope == L"SACL") AppliesToSacl = true;
		else if (*oScope == L"OWNER") AppliesToOwner = true;
		else if (*oScope == L"GROUP") AppliesToGroup = true;
		else
		{
			// complain
			wprintf(L"ERROR: Unrecognized scope qualifier '%s'\n", (*oScope).c_str());
			exit(-1);
		}
	}
}
