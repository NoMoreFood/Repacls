#include "OperationSetOwner.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationSetOwner> OperationSetOwner::RegisteredFactory(GetCommand());

OperationSetOwner::OperationSetOwner(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// fetch params
	tOwnerSid = GetSidFromName(sSubArgs.at(0));

	// see if names could be resolved
	if (tOwnerSid == nullptr)
	{
		// complain
		wprintf(L"ERROR: Invalid account '%s' specified for parameter '%s'.\n", sSubArgs.at(0).c_str(), GetCommand().c_str());
		exit(-1);
	}

	// do a reverse lookup on the name for info messages
	sOwnerSid = GetNameFromSidEx(tOwnerSid);

	// flag this as being an ace-level action
	AppliesToOwner = true;

	// target certain parts of the security descriptor
	if (sSubArgs.size() > 1) ProcessGranularTargetting(sSubArgs.at(1));
}

SidActionResult OperationSetOwner::DetermineSid(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid)
{
	// only process if sid does not matches
	if (SidMatch(tCurrentSid, tOwnerSid))
	{
		return SidActionResult::Nothing;
	}

	// update the sid in the ace
	InputOutput::AddInfo(L"Set owner to account '" + sOwnerSid + L"'", sSdPart);
	tResultantSid = tOwnerSid;
	return SidActionResult::Replace;
}
