#include "OperationPath.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationPath> * OperationPath::RegisteredFactory =
	new ClassFactory<OperationPath>(GetCommand());

OperationPath::OperationPath(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// exit if there are not enough arguments to part
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList, L"\\0");

	// store off the argument
	InputOutput::ScanPaths().push_back(sSubArgs[0]);
};