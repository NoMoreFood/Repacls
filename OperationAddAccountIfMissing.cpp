#include "OperationAddAccountIfMissing.h"
#include "OperationCheckCanonical.h"
#include "InputOutput.h"
#include "Helpers.h"

ClassFactory<OperationAddAccountIfMissing> OperationAddAccountIfMissing::RegisteredFactory(GetCommand());

OperationAddAccountIfMissing::OperationAddAccountIfMissing(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);
	
	// defer construction to delegate
	std::queue<std::wstring> oArgListAlt;
	oArgListAlt.push(sSubArgs.at(0) + L":(OI)(CI)(F)");
	oDelegate = new OperationGrantDenyPerms(oArgListAlt, L"AddPerms");

	// flag this as being an ace-level action
	AppliesToDacl = true;
}

bool OperationAddAccountIfMissing::ProcessAclAction(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	return oDelegate->ProcessAclAction(sSdPart, tObjectEntry, tCurrentAcl, bAclReplacement);
}
