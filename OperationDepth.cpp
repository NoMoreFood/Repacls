#include "OperationDepth.h"
#include "InputOutput.h"
#include "Helpers.h"

ClassFactory<OperationDepth> OperationDepth::RegisteredFactory(GetCommand());

OperationDepth::OperationDepth(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// store off the argument
	OperationDepth::MaxDepth() = _wtoi(sSubArgs.at(0).c_str());
	if (OperationDepth::MaxDepth() < 0)
	{
		// complain
		wprintf(L"ERROR: Invalid depth specified for parameter '%s'.\n", GetCommand().c_str());
		exit(-1);
	}
};
