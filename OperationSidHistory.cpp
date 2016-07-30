#include "OperationSidHistory.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationSidHistory> * OperationSidHistory::RegisteredFactory =
new ClassFactory<OperationSidHistory>(GetCommand());

OperationSidHistory::OperationSidHistory(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToGroup = true;
	AppliesToOwner = true;
}

SidActionResult OperationSidHistory::DetermineSid(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid)
{
	// lookup the textual name for this account and
	// return if it is not found
	std::wstring sAccountName = GetNameFromSid(tCurrentSid, NULL);
	if (sAccountName == L"") return SidActionResult::Nothing;

	// now do a forward lookup on that same account name to see what the
	// primary sid for the account actually is
	PSID tNewSid = GetSidFromName(sAccountName);
	if (tNewSid == nullptr) return SidActionResult::Nothing;

	// if two sid are the same then there is no need to
	// make an update to the access control entry
	if (SidMatch(tCurrentSid, tNewSid)) return SidActionResult::Nothing;

	// update the sid in the ace
	InputOutput::AddInfo(L"Updating SID history reference for '" + sAccountName + L"'", sSdPart);
	tResultantSid = tNewSid;
	return SidActionResult::Replace;
}
