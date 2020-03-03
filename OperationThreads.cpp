#include "OperationThreads.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationThreads> OperationThreads::RegisteredFactory(GetCommand());

OperationThreads::OperationThreads(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// store off the argument
	InputOutput::MaxThreads() = (short)_wtoi(sSubArgs.at(0).c_str());
	if (InputOutput::MaxThreads() == 0 || InputOutput::MaxThreads() > 100)
	{
		// complain
		wprintf(L"ERROR: Invalid number of threads specified for parameter '%s'.\n", GetCommand().c_str());
		exit(-1);
	}
};
