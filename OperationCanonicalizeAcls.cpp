#include "OperationCanonicalizeAcls.h"
#include "OperationCheckCanonical.h"
#include "DriverKitPartial.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationCanonicalizeAcls> * OperationCanonicalizeAcls::RegisteredFactory =
new ClassFactory<OperationCanonicalizeAcls>(GetCommand());

OperationCanonicalizeAcls::OperationCanonicalizeAcls(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// flag this as being an ace-level action
	AppliesToDacl = true;
}

bool OperationCanonicalizeAcls::ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	// sanity check (null acl is considered valid)
	if (tCurrentAcl == NULL) return false;

	// if no problem, then no need to perform a reorder
	if (OperationCheckCanonical::IsAclCanonical(tCurrentAcl))
	{
		return false;
	}	

	BYTE tNewAclBuffer[MAXWORD];
	ACCESS_ACE * tNewAce = (ACCESS_ACE *) &tNewAclBuffer;
	for (int iAceOrder = 0; iAceOrder < OperationCheckCanonical::MaxAceOrder; iAceOrder++)
	{
		ACCESS_ACE * tAce = FirstAce(tCurrentAcl);
		for (ULONG iEntry = 0; iEntry < tCurrentAcl->AceCount; tAce = NextAce(tAce), iEntry++)
		{
			// determine the overall over type of this ace
			OperationCheckCanonical::AceOrder oThisAceOrder = OperationCheckCanonical::DetermineAceOrder(tAce);

			// copy the ace if it matches the sequential order (explicit deny, explicit allow, ...)
			if (iAceOrder == oThisAceOrder)
			{
				memcpy(tNewAce, tAce, tAce->Header.AceSize);
				tNewAce = NextAce(tNewAce);
			}
		}
	}
	
	// recopy the updated list back into the original dacl memory space
	memcpy(FirstAce(tCurrentAcl), &tNewAclBuffer, (PBYTE) tNewAce - (PBYTE) &tNewAclBuffer);
	InputOutput::AddInfo(L"Access control list was canonicalized", sSdPart);
	return true;
}
