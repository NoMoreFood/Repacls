#include "OperationFindNullAcl.h"
#include "DriverKitPartial.h"
#include "InputOutput.h"

ClassFactory<OperationFindNullAcl> OperationFindNullAcl::RegisteredFactory(GetCommand());

OperationFindNullAcl::OperationFindNullAcl(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// flag this as being an ace-level action
	AppliesToDacl = true;
}

bool OperationFindNullAcl::ProcessAclAction(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	if (tCurrentAcl == nullptr)
	{
		InputOutput::AddInfo(L"Access control list is null", sSdPart);
	}

	return false;
}
