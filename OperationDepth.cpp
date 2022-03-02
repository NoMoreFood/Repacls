#include "OperationDepth.h"
#include "InputOutput.h"
#include "Helpers.h"

ClassFactory<OperationDepth> OperationDepth::RegisteredFactory(GetCommand());

OperationDepth::OperationDepth(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList);

	// parse the argument off the argument
	const int iDepth = _wtoi(sSubArgs.at(0).c_str());
	if (iDepth < 0)
	{
		// complain
		wprintf(L"ERROR: Invalid depth specified for parameter '%s'.\n", GetCommand().c_str());
		exit(-1);
	}

	// store for dynamic lookup
	OperationDepth::MaxDepth() = iDepth;
};
