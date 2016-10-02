#include "OperationThreads.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationThreads> * OperationThreads::RegisteredFactory =
new ClassFactory<OperationThreads>(GetCommand());

OperationThreads::OperationThreads(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// exit if there are not enough arguments to part
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// store off the argument
	InputOutput::MaxThreads() = (short)_wtoi(sSubArgs[0].c_str());
	if (InputOutput::MaxThreads() == 0 || InputOutput::MaxThreads() > 100)
	{
		// complain
		wprintf(L"ERROR: Invalid number of threads specified for parameter '%s'.\n", GetCommand().c_str());
		exit(-1);
	}
};
