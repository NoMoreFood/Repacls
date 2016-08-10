#include "OperationMigrateDomain.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationMigrateDomain> * OperationMigrateDomain::RegisteredFactory =
new ClassFactory<OperationMigrateDomain>(GetCommand());

OperationMigrateDomain::OperationMigrateDomain(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// exit if there are not enough arguments to part
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(2, oArgList);

	// fetch params
	tSourceDomain = GetSidFromName(sSubArgs[0]);
	tTargetDomain = GetSidFromName(sSubArgs[1]);

	// see if names could be resolved
	if (tSourceDomain == nullptr)
	{
		// complain
		wprintf(L"ERROR: Invalid source domain '%s' specified for parameter '%s'.\n", sSourceDomain.c_str(), GetCommand().c_str());
		exit(0);
	}

	// see if names could be resolved
	if (tTargetDomain == nullptr)
	{
		// complain
		wprintf(L"ERROR: Invalid target domain'%s' specified for parameter '%s'.\n", sTargetDomain.c_str(), GetCommand().c_str());
		exit(0);
	}

	// store the domain strings
	sSourceDomain = GetNameFromSidEx(tSourceDomain);
	sTargetDomain = GetNameFromSidEx(tTargetDomain);

	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToGroup = true;
	AppliesToOwner = true;

	// target certain parts of the security descriptor
	if (sSubArgs.size() > 2) ProcessGranularTargetting(sSubArgs[2]);
}

SidActionResult OperationMigrateDomain::DetermineSid(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid)
{
	// see if this sid in the source domain
	BOOL bDomainSidsEqual = FALSE;
	if (EqualDomainSid(tCurrentSid, tSourceDomain, &bDomainSidsEqual) == 0 ||
		bDomainSidsEqual == FALSE)
	{
		// no match - cease processing this instruction
		return SidActionResult::Nothing;
	}

	// translate the old sid to an account name
	std::wstring sSourceAccountName = GetNameFromSid(tCurrentSid, NULL);
	if (sSourceAccountName.size() == 0)	return SidActionResult::Nothing;

	// check to see if an equivalent account exists in the target domain
	std::wstring sTargetAccountName = sTargetDomain + (wcsstr(sSourceAccountName.c_str(), L"\\") + 1);
	PSID tTargetAccountSid = GetSidFromName(sTargetAccountName);

	// do a reverse lookup to see if this might be a sid history item
	if (GetNameFromSidEx(tTargetAccountSid) == sSourceAccountName) return SidActionResult::Nothing;

	// stop processing if the account does not exist
	if (tTargetAccountSid == nullptr) return SidActionResult::Nothing;

	// update the sid in the ace
	InputOutput::AddInfo(L"Migrating '" + sSourceAccountName + L"' to '" + sTargetAccountName + L"'", sSdPart);
	tResultantSid = tTargetAccountSid;
	return SidActionResult::Replace;
}
