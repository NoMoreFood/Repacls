#include "OperationCheckCanonical.h"
#include "DriverKitPartial.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationCheckCanonical> * OperationCheckCanonical::RegisteredFactory =
new ClassFactory<OperationCheckCanonical>(GetCommand());

OperationCheckCanonical::OperationCheckCanonical(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// flag this as being an ace-level action
	AppliesToDacl = true;
}

bool OperationCheckCanonical::ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	// sanity check (null acl is considered valid)
	if (tCurrentAcl == NULL) return false;

	enum AceOrder : unsigned char
	{
		Unspecified = 0,
		Explicit = 1 << 0,
		Deny = 1 << 1,
		Allow = 1 << 2,
		Inherited = 1 << 3
	};

	unsigned char oOrderOverall = Unspecified;
	ACCESS_ACE * tAce = FirstAce(tCurrentAcl);
	for (ULONG iEntry = 0; iEntry < tCurrentAcl->AceCount; tAce = NextAce(tAce), iEntry++)
	{
		// check inheritance bits
		unsigned char oThisAceOrder = (IsInherited(tAce)) ? Inherited : Unspecified;

		// check allow/deny
		oThisAceOrder |= (tAce->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) ? Allow : Unspecified;
		oThisAceOrder |= (tAce->Header.AceType == ACCESS_DENIED_ACE_TYPE) ? Deny : Unspecified;

		// make sure this order is not less then the current order
		if (oThisAceOrder < oOrderOverall)
		{
			InputOutput::AddInfo(L"Access control list is not canonical", sSdPart);
			return false;
		}
		oOrderOverall = oThisAceOrder;
	}

	// report the
	return false;
}
