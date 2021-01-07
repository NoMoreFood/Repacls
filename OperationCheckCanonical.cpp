#include "OperationCheckCanonical.h"
#include "DriverKitPartial.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationCheckCanonical> OperationCheckCanonical::RegisteredFactory(GetCommand());

OperationCheckCanonical::OperationCheckCanonical(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// flag this as being an ace-level action
	AppliesToDacl = true;
}

bool OperationCheckCanonical::ProcessAclAction(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	// sanity check (null acl is considered valid)
	if (tCurrentAcl == nullptr) return false;

	// do the check and report
	if (!IsAclCanonical(tCurrentAcl))
	{
		InputOutput::AddInfo(L"Access control list is not canonical", sSdPart);
	}

	// report the
	return false;
}

bool OperationCheckCanonical::IsAclCanonical(PACL & tAcl)
{
	// sanity check (null acl is considered valid)
	if (tAcl == nullptr) return true;

	AceOrder oOrderOverall = Unspecified;
	ACCESS_ACE * tAce = FirstAce(tAcl);
	for (ULONG iEntry = 0; iEntry < tAcl->AceCount; tAce = NextAce(tAce), iEntry++)
	{
		// check inheritance bits
		const AceOrder oThisAceOrder = DetermineAceOrder(tAce);

		// make sure this order is not less then the current order
		if (oThisAceOrder < oOrderOverall)
		{
			return false;
		}
		oOrderOverall = oThisAceOrder;
	}

	return true;
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