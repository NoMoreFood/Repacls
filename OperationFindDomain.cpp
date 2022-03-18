#include "OperationFindDomain.h"
#include "InputOutput.h"
#include "Helpers.h"

ClassFactory<OperationFindDomain> OperationFindDomain::RegisteredFactory(GetCommand());

OperationFindDomain::OperationFindDomain(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	const std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// decode the passed parameter to an account name
	tDomainSid = GetSidFromName(sSubArgs.at(0));

	// see if names could be resolved
	if (tDomainSid == nullptr)
	{
		// complain
		wprintf(L"ERROR: Invalid domain '%s' specified for parameter '%s'.\n", sSubArgs.at(0).c_str(), GetCommand().c_str());
		std::exit(0);
	}

	// do a reverse lookup of the name for reporting
	sDomainName = GetDomainNameFromSid(tDomainSid);
	sDomainName = sDomainName.substr(0, sDomainName.find(L'\\'));

	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToGroup = true;
	AppliesToOwner = true;

	// target certain parts of the security descriptor
	if (sSubArgs.size() > 1) ProcessGranularTargetting(sSubArgs.at(1));
}

SidActionResult OperationFindDomain::DetermineSid(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid)
{
	// see if this sid in the source domain
	BOOL bDomainSidsEqual = FALSE;
	if (EqualDomainSid(tCurrentSid, tDomainSid, &bDomainSidsEqual) == 0 ||
		bDomainSidsEqual == FALSE)
	{
		// no match - cease processing this instruction
		return SidActionResult::Nothing;
	}
	
	// resolve the sid for reporting
	const std::wstring sAccount = GetNameFromSidEx(tCurrentSid);

	// report the
	InputOutput::AddInfo(L"Found domain identifier '" + sDomainName + L"' on account '" + sAccount + L"'", sSdPart);
	return SidActionResult::Nothing;
}
