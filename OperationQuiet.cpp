#include "OperationQuiet.h"
#include "InputOutput.h"

ClassFactory<OperationQuiet> OperationQuiet::RegisteredFactory(GetCommand());

OperationQuiet::OperationQuiet(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	InputOutput::InQuietMode() = true;
}