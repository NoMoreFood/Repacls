#include "OperationRemoveAccount.h"
#include "InputOutput.h"
#include "Helpers.h"

ClassFactory<OperationRemoveAccount> OperationRemoveAccount::RegisteredFactory(GetCommand());

OperationRemoveAccount::OperationRemoveAccount(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// fetch params
	tRemoveSid = GetSidFromName(sSubArgs.at(0));

	// see if names could be resolved
	if (tRemoveSid == nullptr)
	{
		// complain
		wprintf(L"ERROR: Invalid account '%s' specified for parameter '%s'.\n", sSubArgs.at(0).c_str(), GetCommand().c_str());
		exit(-1);
	}

	// do a reverse lookup on the name for info messages
	sRemoveSid = GetNameFromSidEx(tRemoveSid);

	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToGroup = true;
	AppliesToOwner = true;

	// target certain parts of the security descriptor
	if (sSubArgs.size() > 1) ProcessGranularTargetting(sSubArgs.at(1));
}

SidActionResult OperationRemoveAccount::DetermineSid(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid)
{
	// only process if sid matches
	if (SidNotMatch(tCurrentSid, tRemoveSid))
	{
		return SidActionResult::Nothing;
	}

	// update the sid in the ace
	InputOutput::AddInfo(L"Removing account '" + sRemoveSid + L"'", sSdPart);
	tResultantSid = nullptr;
	return SidActionResult::Remove;
}
