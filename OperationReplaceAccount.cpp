#include "OperationReplaceAccount.h"
#include "InputOutput.h"
#include "Helpers.h"

ClassFactory<OperationReplaceAccount> OperationReplaceAccount::RegisteredFactory(GetCommand());

OperationReplaceAccount::OperationReplaceAccount(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(2, oArgList);

	// fetch params
	tSearchAccount = GetSidFromName(sSubArgs.at(0));
	tReplaceAccount = GetSidFromName(sSubArgs.at(1));

	// see if names could be resolved
	if (tSearchAccount == nullptr)
	{
		// complain
		wprintf(L"ERROR: Invalid search account '%s' specified for parameter '%s'.\n", sSubArgs.at(0).c_str(), GetCommand().c_str());
		exit(0);
	}

	// see if names could be resolved
	if (tReplaceAccount == nullptr)
	{
		// complain
		wprintf(L"ERROR: Invalid replace account '%s' specified for parameter '%s'.\n", sSubArgs.at(1).c_str(), GetCommand().c_str());
		exit(0);
	}

	// store off the names for those entries
	sSearchAccount = GetNameFromSidEx(tSearchAccount);
	sReplaceAccount = GetNameFromSidEx(tReplaceAccount);

	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToGroup = true;
	AppliesToOwner = true;

	// target certain parts of the security descriptor
	if (sSubArgs.size() > 2) ProcessGranularTargetting(sSubArgs.at(2));
}

SidActionResult OperationReplaceAccount::DetermineSid(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid)
{
	// check if the sid matches the ace
	if (SidMatch(tCurrentSid, tSearchAccount))
	{
		InputOutput::AddInfo(L"Replacing account '" + sSearchAccount + L"' with '" + sReplaceAccount + L"'", sSdPart);
		tResultantSid = tReplaceAccount;
		return SidActionResult::Replace;
	};

	return SidActionResult::Nothing;
}
