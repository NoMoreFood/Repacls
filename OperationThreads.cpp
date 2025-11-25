#include "OperationThreads.h"
#include "InputOutput.h"
#include "Helpers.h"

ClassFactory<OperationThreads> OperationThreads::RegisteredFactory(GetCommand());

OperationThreads::OperationThreads(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	const std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// store off the argument
	InputOutput::MaxThreads() = static_cast<short>(_wtoi(sSubArgs.at(0).c_str()));
	if (InputOutput::MaxThreads() == 0 || InputOutput::MaxThreads() > 100)
	{
		// complain
		Print(L"ERROR: Invalid number of threads specified for parameter '{}'.", GetCommand());
		std::exit(-1);
	}
};
