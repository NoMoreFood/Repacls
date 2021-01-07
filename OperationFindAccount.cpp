#include "OperationFindAccount.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationFindAccount> OperationFindAccount::RegisteredFactory(GetCommand());

OperationFindAccount::OperationFindAccount(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// decode the passed parameter to an account name
	tFindSid = GetSidFromName(sSubArgs.at(0));

	// see if names could be resolved
	if (tFindSid == nullptr)
	{
		// complain
		wprintf(L"ERROR: Invalid account '%s' specified for parameter '%s'.\n", sSubArgs.at(0).c_str(), GetCommand().c_str());
		exit(0);
	}

	// reverse lookup the sid for reporting
	sFindSid = GetNameFromSidEx(tFindSid);

	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToGroup = true;
	AppliesToOwner = true;

	// target certain parts of the security descriptor
	if (sSubArgs.size() > 1) ProcessGranularTargetting(sSubArgs.at(1));
}

SidActionResult OperationFindAccount::DetermineSid(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid)
{ 
	// check if the sid matches the ace
	if (SidMatch(tCurrentSid, tFindSid))
	{
		InputOutput::AddInfo(L"Found identifier '" + sFindSid + L"'", sSdPart, true);
	};

	return SidActionResult::Nothing; 
}
