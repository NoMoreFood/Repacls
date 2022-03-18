#include "OperationRestoreSecurity.h"
#include "InputOutput.h"
#include "Helpers.h"

#include <fstream>
#include <locale>
#include <codecvt>

ClassFactory<OperationRestoreSecurity> OperationRestoreSecurity::RegisteredFactory(GetCommand());

OperationRestoreSecurity::OperationRestoreSecurity(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	const std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList, L"\\0");

	// open the file
	std::wifstream fFile(sSubArgs.at(0).c_str());

	// adapt the stream to read windows unicode files
	(void) fFile.imbue(std::locale(fFile.getloc(), new std::codecvt_utf8<wchar_t,
		0x10ffff, std::consume_header>));

	// read the file line-by-line
	std::wstring sLine;
	while (std::getline(fFile, sLine))
	{
		// parse the file name and descriptor which are separated by a '|' character
		// also, sometimes a carriage return appears in the input stream so adding 
		// it here ensures it is stripped from the very end
		std::vector<std::wstring> oLineItems = SplitArgs(sLine, L"\\||\r");

		// convert the long string descriptor its binary equivalent
		PSECURITY_DESCRIPTOR tDesc;
		if (oLineItems.size() != 2 ||
			ConvertStringSecurityDescriptorToSecurityDescriptor(oLineItems.at(1).c_str(),
			SDDL_REVISION_1, &tDesc, NULL) == 0)
		{
			wprintf(L"ERROR: Unable to parse string security descriptor file for restoration.");
			std::exit(-1);
		}

		// update the map
		oImportMap[oLineItems.at(0)] = tDesc;
	}

	// cleanup
	fFile.close();

	// flag this as being an ace-level action
	AppliesToSd = true;
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToOwner = true;
	AppliesToGroup = true;
}

bool OperationRestoreSecurity::ProcessSdAction(std::wstring & sFileName, ObjectEntry & tObjectEntry, PSECURITY_DESCRIPTOR & tDescriptor, bool & bDescReplacement)
{
	auto oSecInfo = oImportMap.find(sFileName);
	if (oSecInfo != oImportMap.end())
	{
		// lookup the string in the map
		if (bDescReplacement) LocalFree(tDescriptor);
		tDescriptor = oSecInfo->second;
		bDescReplacement = true;
	}
	else
	{
		// update the sid in the ace
		InputOutput::AddError(L"Import File Did Not Contain Descriptor");
	}

	// cleanup
	return true;
}
