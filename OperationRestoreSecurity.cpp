#include "OperationRestoreSecurity.h"
#include "InputOutput.h"
#include "Functions.h"

#include <fstream>
#include <iostream>
#include <locale>
#include <codecvt>

ClassFactory<OperationRestoreSecurity> * OperationRestoreSecurity::RegisteredFactory =
new ClassFactory<OperationRestoreSecurity>(GetCommand());

OperationRestoreSecurity::OperationRestoreSecurity(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// exit if there are not enough arguments to part
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList, L"\\0");

	// open the file
	std::wifstream fFile(sSubArgs[0].c_str());

	// adapt the stream to read windows unicode files
	fFile.imbue(std::locale(fFile.getloc(), new std::codecvt_utf16<wchar_t,
		0x10ffff, std::consume_header>));

	// read the file line-by-line
	std::wstring sLine;
	while (std::getline(fFile, sLine))
	{
		// parse the file name and descriptor which are separated by a '|' character
		// also, sometimes a character return appears in the input stream so adding 
		// it here ensures it is stripped from the very end
		std::vector<std::wstring> oLineItems = SplitArgs(sLine, L"=|\r");

		// convert the long string descriptor its binary equivalent
		PSECURITY_DESCRIPTOR tDesc;
		if (oLineItems.size() != 2 ||
			ConvertStringSecurityDescriptorToSecurityDescriptor(oLineItems.at(1).c_str(),
			SDDL_REVISION_1, &tDesc, NULL) == 0)
		{
			wprintf(L"ERROR: Unable to parse string security descriptor file for restoration.");
			exit(-1);
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
	std::map<std::wstring, PSECURITY_DESCRIPTOR>::iterator oSecInfo = oImportMap.find(sFileName);
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
