#include "OperationReport.h"
#include "InputOutput.h"
#include "Helpers.h"

ClassFactory<OperationReport> OperationReport::RegisteredFactory(GetCommand());

OperationReport::OperationReport(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	const std::vector<std::wstring> sReportFile = ProcessAndCheckArgs(1, oArgList, L"\\0");
	const std::vector<std::wstring> sMatchAndArgs = ProcessAndCheckArgs(1, oArgList, L":");

	// fetch params
	HANDLE hFile = CreateFile(sReportFile.at(0).c_str(), GENERIC_WRITE,
		FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	// see if names could be resolved
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// complain
		Print(L"ERROR: Could not create file '{}' specified for parameter '{}'.", sReportFile.at(0), GetCommand());
		std::exit(-1);
	}

	// register the file handle
	hReportFile = RegisterFileHandle(hFile, GetCommand());

	// if this is the first handle using this file, write out a header
	if (hFile == hReportFile)
	{
		// write out the file type marker
		constexpr BYTE hHeader[] = { 0xEF,0xBB,0xBF };
		DWORD iBytes = 0;
		if (WriteFile(hFile, &hHeader, _countof(hHeader), &iBytes, nullptr) == 0)
		{
			Print(L"ERROR: Could not write out file type marker '{}'.", GetCommand());
			std::exit(-1);
		}

		// write out the header
		if (WriteToFile(OutToCsv(L"Path", L"Descriptor Part", L"Account Name", 
			L"Permissions", L"Inheritance", L"Object Type"), hReportFile) == 0)
		{
			Print(L"ERROR: Could not write header to report file for parameter '{}'.", GetCommand());
			std::exit(-1);
		}
	}

	// compile the regular expression
	try
	{
		tRegex = std::wregex(sMatchAndArgs.at(0), std::wregex::icase | std::wregex::optimize);
	}
	catch (const std::regex_error &)
	{
		Print(L"ERROR: Invalid regular expression '{}' specified for parameter '{}'.", sMatchAndArgs.at(0), GetCommand());
		std::exit(-1);
	}

	// flag that all parts of security descriptor are necessary
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToGroup = true;
	AppliesToOwner = true;

	// target certain parts of the security descriptor
	if (sMatchAndArgs.size() > 1) ProcessGranularTargetting(sMatchAndArgs.at(1));
}

SidActionResult OperationReport::DetermineSid(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid)
{
	// do not report null sids
	if (tCurrentSid == nullptr) return Nothing;

	// fetch the account from the sid
	const std::wstring sAccount = GetNameFromSidEx(tCurrentSid);

	// skip any accounts that do not match the regex
	if (!std::regex_match(sAccount, tRegex)) return Nothing;

	// write the string to a file
	if (WriteToFile(OutToCsv(tObjectEntry.Name, sSdPart, sAccount), hReportFile) == 0)
	{
		InputOutput::AddError(L"Unable to write security information to report file.");
	}

	return Nothing;
}

bool OperationReport::ProcessAclAction(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	// do not report null acls
	if (tCurrentAcl == nullptr) return false;
	
	// enumerate access control entries
	PACE_ACCESS_HEADER tAce = FirstAce(tCurrentAcl);
	for (ULONG iEntry = 0; iEntry < tCurrentAcl->AceCount; tAce = NextAce(tAce), iEntry++)
	{
		// skip inherited ace and invalid sids
		if (IsInherited(tAce)) continue;

		// get the sid from the ace
		const PSID pSid = GetSidFromAce(tAce);

		// fetch the account from the sid
		std::wstring sAccount = GetNameFromSidEx(pSid);

		// skip any accounts that do not match the regex
		if (!std::regex_search(sAccount, tRegex)) continue;
		
		// get the string versions of the access mask and inheritance
		const std::wstring sMask = GenerateAccessMask(tAce->Mask);
		const std::wstring sFlags = GenerateInheritanceFlags(tAce->AceFlags);
		const std::wstring sType = (tObjectEntry.Attributes & FILE_ATTRIBUTE_DIRECTORY) ? L"Container" : L"Leaf";

		// write the string to a file
		if (WriteToFile(OutToCsv(tObjectEntry.Name, sSdPart, sAccount, sMask, sFlags, sType), hReportFile) == 0)
		{
			InputOutput::AddError(L"Unable to write security information to report file.");
		}
	}

	return false;
}