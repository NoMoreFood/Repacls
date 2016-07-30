#include "OperationRemoveAccount.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationRemoveAccount> * OperationRemoveAccount::RegisteredFactory =
new ClassFactory<OperationRemoveAccount>(GetCommand());

OperationRemoveAccount::OperationRemoveAccount(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// exit if there are not enough arguments to part
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// fetch params
	tRemoveSid = GetSidFromName(sSubArgs[0]);

	// see if names could be resolved
	if (tRemoveSid == nullptr)
	{
		// complain
		wprintf(L"ERROR: Invalid account '%s' specified for parameter '%s'.\n", sSubArgs[0].c_str(), GetCommand().c_str());
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
	if (sSubArgs.size() > 1) ProcessGranularTargetting(sSubArgs[1]);
}

SidActionResult OperationRemoveAccount::DetermineSid(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid)
{
	// only process if sid matches
	if (SidNotMatch(tCurrentSid, tRemoveSid))
	{
		return SidActionResult::Nothing;
	}

	// update the sid in the ace
	InputOutput::AddInfo(L"Removing account '" + sRemoveSid + L"'", sSdPart);
	tResultantSid = NULL;
	return SidActionResult::Remove;
}
