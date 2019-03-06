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

	AceOrder oOrderOverall = Unspecified;
	ACCESS_ACE * tAce = FirstAce(tCurrentAcl);
	for (ULONG iEntry = 0; iEntry < tCurrentAcl->AceCount; tAce = NextAce(tAce), iEntry++)
	{
		// check inheritance bits
		AceOrder oThisAceOrder = DetermineAceOrder(tAce);

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

OperationCheckCanonical::AceOrder OperationCheckCanonical::DetermineAceOrder(ACCESS_ACE * tAce)
{
	// determine ace order
	if (IsInherited(tAce))
	{
		if (tAce->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) return InheritedAllow;
		if (tAce->Header.AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE) return InheritedAllow;
		if (tAce->Header.AceType == ACCESS_DENIED_ACE_TYPE) return InheritedDeny;
		if (tAce->Header.AceType == ACCESS_DENIED_CALLBACK_ACE_TYPE) return InheritedDeny;
	}
	else
	{
		if (tAce->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) return ExplicitAllow;
		if (tAce->Header.AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE) return ExplicitAllow;
		if (tAce->Header.AceType == ACCESS_DENIED_ACE_TYPE) return ExplicitDeny;
		if (tAce->Header.AceType == ACCESS_DENIED_CALLBACK_ACE_TYPE) return ExplicitDeny;
	}

	return Unspecified;
}