#include "OperationFindNullAcl.h"
#include "DriverKitPartial.h"
#include "InputOutput.h"

ClassFactory<OperationFindNullAcl> * OperationFindNullAcl::RegisteredFactory =
new ClassFactory<OperationFindNullAcl>(GetCommand());

OperationFindNullAcl::OperationFindNullAcl(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// flag this as being an ace-level action
	AppliesToDacl = true;
}

bool OperationFindNullAcl::ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	// sanity check (null acl is considered valid)
	if (tCurrentAcl == NULL)
	{
		InputOutput::AddInfo(L"Access control list is null", sSdPart);
	}

	// report the
	return false;
}
