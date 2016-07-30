#include "OperationNoHiddenSystem.h"
#include "InputOutput.h"

ClassFactory<OperationNoHiddenSystem> * OperationNoHiddenSystem::RegisteredFactory =
new ClassFactory<OperationNoHiddenSystem>(GetCommand());

OperationNoHiddenSystem::OperationNoHiddenSystem(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	InputOutput::ExcludeHiddenSystem() = true;
}