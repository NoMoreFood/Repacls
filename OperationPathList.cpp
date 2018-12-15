#include "OperationPathList.h"
#include "InputOutput.h"
#include "Functions.h"

#include <fstream>
#include <iostream>
#include <locale>
#include <codecvt>

ClassFactory<OperationPathList> * OperationPathList::RegisteredFactory =
new ClassFactory<OperationPathList>(GetCommand());

OperationPathList::OperationPathList(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList, L"\\0");

	// open the file
	std::wifstream fFile(sSubArgs[0].c_str());

	// adapt the stream to read windows unicode files
	(void) fFile.imbue(std::locale(fFile.getloc(), new std::codecvt_utf8<wchar_t,
		0x10ffff, std::consume_header>));

	// read the file line-by-line
	std::wstring sLine;
	while (std::getline(fFile, sLine))
	{
		// sometimes a carriage return appears in the input stream so adding 
		// it here ensures it is stripped from the very end
		std::vector<std::wstring> oLineItems = SplitArgs(sLine, L"\r");
		if (oLineItems.size() != 1)
		{
			wprintf(L"ERROR: Unable to parse string path list file.");
			exit(-1);
		}

		// store off the argument
		InputOutput::ScanPaths().push_back(oLineItems[0]);
	}

	// cleanup
	fFile.close();
};