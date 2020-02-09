#include "OperationMoveDomain.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationMoveDomain> OperationMoveDomain::RegisteredFactory(GetCommand());

OperationMoveDomain::OperationMoveDomain(std::queue<std::wstring> & oArgList, std::wstring sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(2, oArgList);

	// fetch params
	tSourceDomain = GetSidFromName(sSubArgs.at(0));
	tTargetDomain = GetSidFromName(sSubArgs.at(1));

	// see if names could be resolved
	if (tSourceDomain == nullptr)
	{
		// complain
		wprintf(L"ERROR: Invalid source domain '%s' specified for parameter '%s'.\n", sSubArgs.at(0).c_str(), GetCommand().c_str());
		exit(0);
	}

	// see if names could be resolved
	if (tTargetDomain == nullptr)
	{
		// complain
		wprintf(L"ERROR: Invalid target domain '%s' specified for parameter '%s'.\n", sSubArgs.at(1).c_str(), GetCommand().c_str());
		exit(0);
	}

	// store the domain strings
	sSourceDomain = GetDomainNameFromSid(tSourceDomain);
	sTargetDomain = GetDomainNameFromSid(tTargetDomain);

	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToGroup = true;
	AppliesToOwner = true;

	// target certain parts of the security descriptor
	if (sSubArgs.size() > 2) ProcessGranularTargetting(sSubArgs.at(2));
}

SidActionResult OperationMoveDomain::DetermineSid(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid)
{
	// see if this sid in the source domain
	BOOL bDomainSidsEqual = FALSE;
	if (EqualDomainSid(tCurrentSid, tSourceDomain, &bDomainSidsEqual) == 0 ||
		bDomainSidsEqual == FALSE)
	{
		// no match - cease processing this instruction
		return SidActionResult::Nothing;
	}

	// see if this SID is a well-known, built-in SID in the form S-1-5-21-<domain>-(<1000)
	const PISID tSidStruct = (PISID) tCurrentSid;
	const PISID tSidTargetDomain = (PISID) tTargetDomain;
	if (tSidStruct->SubAuthorityCount == 5 &&
		tSidStruct->SubAuthority[0] == 21 &&
		tSidStruct->SubAuthority[4] < 1000)
	{
		// create a new sid that has the domain identifier of the target domain
		PSID tSidTmp = nullptr;
		AllocateAndInitializeSid(&tSidStruct->IdentifierAuthority, tSidStruct->SubAuthorityCount,
			tSidStruct->SubAuthority[0], tSidTargetDomain->SubAuthority[1], tSidTargetDomain->SubAuthority[2],
			tSidTargetDomain->SubAuthority[3], tSidStruct->SubAuthority[4], 0, 0, 0, &tSidTmp);

		// lookup the target name and see if it exists
		std::wstring sTargetAccountName = GetNameFromSid(tSidTmp);
		FreeSid(tSidTmp);
		if (sTargetAccountName.empty())	return SidActionResult::Nothing;

		// do a forward lookup on the name in order to get a reference to the 
		// SID that we do not have to worry about cleaning up
		tResultantSid = GetSidFromName(sTargetAccountName);

		// lookup the source name for reporting
		std::wstring sSourceAccountName = GetNameFromSidEx(tCurrentSid);

		// update the sid in the ace
		InputOutput::AddInfo(L"Changing Well Known '" + sSourceAccountName + L"' to '" + sTargetAccountName + L"'", sSdPart);
	}
	else
	{
		// translate the old sid to an account name
		std::wstring sSourceAccountName = GetNameFromSid(tCurrentSid, nullptr);
		if (sSourceAccountName.empty())	return SidActionResult::Nothing;

		// check to see if an equivalent account exists in the target domain
		std::wstring sTargetAccountName = sTargetDomain + (wcsstr(sSourceAccountName.c_str(), L"\\") + 1);
		tResultantSid = GetSidFromName(sTargetAccountName);

		// exit if no match was found
		if (tResultantSid == nullptr)
		{
			InputOutput::AddWarning(L"Could not find matching account in target domain '" +
				sTargetDomain + L"' for '" + sSourceAccountName + L"'", sSdPart);
			return SidActionResult::Nothing;
		}

		// do a reverse lookup to see if this might be a sid history item
		if (GetNameFromSidEx(tResultantSid) == sSourceAccountName) return SidActionResult::Nothing;

		// stop processing if the account does not exist
		if (tResultantSid == nullptr) return SidActionResult::Nothing;

		// update the sid in the ace
		InputOutput::AddInfo(L"Changing '" + sSourceAccountName + L"' to '" + sTargetAccountName + L"'", sSdPart);

	}

	// update the sid in the ace
	return SidActionResult::Replace;
}
