#include "OperationRemoveDomain.h"
#include "InputOutput.h"
#include "Helpers.h"

ClassFactory<OperationRemoveDomain> OperationRemoveDomain::RegisteredFactory(GetCommand());

OperationRemoveDomain::OperationRemoveDomain(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	const std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// decode the passed parameter to an account name
	tDomainSid = GetSidFromName(sSubArgs.at(0));

	// see if names could be resolved
	if (tDomainSid == nullptr)
	{
		// complain
		Print(L"ERROR: Invalid domain '{}' specified for parameter '{}'.", sSubArgs.at(0), GetCommand());
		std::exit(0);
	}

	// do a reverse lookup of the name for reporting
	sDomainName = GetDomainNameFromSid(tDomainSid);

	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToGroup = true;
	AppliesToOwner = true;

	// target certain parts of the security descriptor
	if (sSubArgs.size() > 1) ProcessGranularTargetting(sSubArgs.at(1));
}

SidActionResult OperationRemoveDomain::DetermineSid(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid)
{
	// see if this sid in the source domain
	BOOL bDomainSidsEqual = FALSE;
	if (EqualDomainSid(tCurrentSid, tDomainSid, &bDomainSidsEqual) == 0 ||
		bDomainSidsEqual == FALSE)
	{
		// no match - cease processing this instruction
		return Nothing;
	}

	// update the sid in the ace
	const std::wstring sSid = GetNameFromSidEx(tCurrentSid);
	InputOutput::AddInfo(L"Removing account or sid reference '" + sSid + L"' from domain '" + sDomainName + L"'", sSdPart);
	tResultantSid = nullptr;
	return Remove;
}
