#include "OperationCanonicalizeAcls.h"
#include "OperationCheckCanonical.h"
#include "DriverKitPartial.h"
#include "InputOutput.h"

ClassFactory<OperationCanonicalizeAcls> OperationCanonicalizeAcls::RegisteredFactory(GetCommand());

OperationCanonicalizeAcls::OperationCanonicalizeAcls(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// flag this as being an ace-level action
	AppliesToDacl = true;
}

bool OperationCanonicalizeAcls::ProcessAclAction(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	// sanity check (null acl is considered valid)
	if (tCurrentAcl == nullptr) return false;

	// if no problem, then no need to perform a reorder
	if (OperationCheckCanonical::IsAclCanonical(tCurrentAcl))
	{
		return false;
	}	

	BYTE tNewAclBuffer[MAXWORD];
	PACE_ACCESS_HEADER tNewAce = (PACE_ACCESS_HEADER) &tNewAclBuffer;
	for (int iAceOrder = 0; iAceOrder < OperationCheckCanonical::MaxAceOrder; iAceOrder++)
	{
		PACE_ACCESS_HEADER tAce = FirstAce(tCurrentAcl);
		for (ULONG iEntry = 0; iEntry < tCurrentAcl->AceCount; tAce = NextAce(tAce), iEntry++)
		{
			// copy the ace if it matches the sequential order (explicit deny, explicit allow, ...)
			if (iAceOrder == OperationCheckCanonical::DetermineAceOrder(tAce))
			{
				memcpy(tNewAce, tAce, tAce->AceSize);
				tNewAce = NextAce(tNewAce);
			}
		}
	}
	
	// recopy the updated list back into the original dacl memory space
	memcpy(FirstAce(tCurrentAcl), &tNewAclBuffer, (PBYTE) tNewAce - (PBYTE) &tNewAclBuffer);
	InputOutput::AddInfo(L"Access control list was canonicalized", sSdPart);
	return true;
}
