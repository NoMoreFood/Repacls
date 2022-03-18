#include "OperationReplaceMap.h"
#include "InputOutput.h"
#include "Helpers.h"

#include <fstream>
#include <locale>
#include <codecvt>

ClassFactory<OperationReplaceMap> OperationReplaceMap::RegisteredFactory(GetCommand());

OperationReplaceMap::OperationReplaceMap(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	const std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList, L"\\|");

	// open the file
	std::wifstream fFile(sSubArgs.at(0).c_str());

	// adapt the stream to read windows unicode files
	(void) fFile.imbue(std::locale(fFile.getloc(), new std::codecvt_utf8<wchar_t,
		0x10ffff, std::consume_header>));

	// read the file line-by-line
	std::wstring sLine;
	while (std::getline(fFile, sLine))
	{
		// parse the search and replace account which are separated by a ':' character
		// also, sometimes a carriage return appears in the input stream so adding
		// it here ensures it is stripped from the very end
		std::vector<std::wstring> oLineItems = SplitArgs(sLine, L":|\r");

		// verify the line contains at least two elements
		if (oLineItems.size() != 2)
		{
			wprintf(L"ERROR: The replacement map line '%s' is invalid.", sLine.c_str());
			std::exit(-1);
		}
		
		// verify search sid
		const PSID tSearchSid = GetSidFromName(oLineItems.at(0));
		if (tSearchSid == nullptr)
		{
			wprintf(L"ERROR: The map search value '%s' is invalid.", oLineItems.at(0).c_str());
			std::exit(-1);
		}

		// verify replace sid
		const PSID tReplaceSid = GetSidFromName(oLineItems.at(1));
		if (tReplaceSid == nullptr)
		{
			wprintf(L"ERROR: The map replace value '%s' is invalid.", oLineItems.at(1).c_str());
			std::exit(-1);
		}

		// update the map
		oReplaceMap[tSearchSid] = tReplaceSid;
	}

	// cleanup
	fFile.close();

	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToGroup = true;
	AppliesToOwner = true;

	// target certain parts of the security descriptor
	if (sSubArgs.size() > 1) ProcessGranularTargetting(sSubArgs.at(1));
}

SidActionResult OperationReplaceMap::DetermineSid(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid)
{
	// check if the sid matches the ace
	auto oInteractor = oReplaceMap.find(tCurrentSid);
	if (oInteractor == oReplaceMap.end()) return SidActionResult::Nothing;
	
	// return the replacement sid
	const std::wstring sSearchAccount = GetNameFromSidEx(oInteractor->first);
	const std::wstring sReplaceAccount = GetNameFromSidEx(oInteractor->second);
	InputOutput::AddInfo(L"Replacing '" + sSearchAccount + L"' with '" + sReplaceAccount + L"'", sSdPart);
	tResultantSid = oInteractor->second;
	return SidActionResult::Replace;
}