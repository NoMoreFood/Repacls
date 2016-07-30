#include "OperationFindDomain.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationFindDomain> * OperationFindDomain::RegisteredFactory =
new ClassFactory<OperationFindDomain>(GetCommand());

OperationFindDomain::OperationFindDomain(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// exit if there are not enough arguments to part
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// decode the passed parameter to an account name
	tDomainSid = GetSidFromName(sSubArgs[0]);

	// see if names could be resolved
	if (tDomainSid == nullptr)
	{
		// complain
		wprintf(L"ERROR: Invalid domain '%s' specified for parameter '%s'.\n", sSubArgs[0].c_str(), GetCommand().c_str());
		exit(0);
	}

	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToGroup = true;
	AppliesToOwner = true;

	// target certain parts of the security descriptor
	if (sSubArgs.size() > 1) ProcessGranularTargetting(sSubArgs[1]);
}

SidActionResult OperationFindDomain::DetermineSid(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid)
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
	std::wstring sAccount = GetNameFromSidEx(tCurrentSid);

	// report the
	InputOutput::AddInfo(L"Found domain identifier '" + sDomainSid + L"' on account '" + sAccount + L"'", sSdPart);
	return SidActionResult::Nothing;
}
