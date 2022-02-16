#include "OperationPath.h"
#include "InputOutput.h"
#include "Helpers.h"

ClassFactory<OperationPath> OperationPath::RegisteredFactory(GetCommand());

OperationPath::OperationPath(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList, L"\\0");

	// store off the argument
	InputOutput::ScanPaths().push_back(sSubArgs.at(0));
};