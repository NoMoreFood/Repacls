#include "OperationResetChildren.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationResetChildren> OperationResetChildren::RegisteredFactory(GetCommand());

OperationResetChildren::OperationResetChildren(std::queue<std::wstring> & oArgList, std::wstring sCommand) : Operation(oArgList)
{
	// setup null ace for allowing inheritance
	InitializeAcl(&tAclNull, sizeof(tAclNull), ACL_REVISION);

	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToChildrenOnly = true;
	ExclusiveOperation = true;
	SpecialCommitFlags = UNPROTECTED_SACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION;
}

bool OperationResetChildren::ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	// cleanup existing if it had been reallocated
	if (bAclReplacement) LocalFree(tCurrentAcl);
	bAclReplacement = false;

	// setting the null acl will overwrite all explicit entires
	tCurrentAcl = &tAclNull;

	// nothing to do -- the special commit flags will take care of it
	return true;
}
