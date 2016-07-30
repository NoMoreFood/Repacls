#include "OperationQuiet.h"
#include "InputOutput.h"

ClassFactory<OperationQuiet> * OperationQuiet::RegisteredFactory =
new ClassFactory<OperationQuiet>(GetCommand());

OperationQuiet::OperationQuiet(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	InputOutput::InQuietMode() = true;
}