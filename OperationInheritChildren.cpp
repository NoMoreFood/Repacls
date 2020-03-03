#include "OperationInheritChildren.h"
#include "DriverKitPartial.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationInheritChildren> OperationInheritChildren::RegisteredFactory(GetCommand());

OperationInheritChildren::OperationInheritChildren(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToChildrenOnly = true;
	ExclusiveOperation = true;
	SpecialCommitFlags = UNPROTECTED_SACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION;
}

bool OperationInheritChildren::ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	// nothing to do -- the special commit flags will take care of it
	return true;
}
