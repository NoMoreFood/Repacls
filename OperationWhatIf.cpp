#include "OperationWhatIf.h"
#include "InputOutput.h"

ClassFactory<OperationWhatIf> OperationWhatIf::RegisteredFactory(GetCommand());

OperationWhatIf::OperationWhatIf(std::queue<std::wstring> & oArgList, std::wstring sCommand) : Operation(oArgList)
{
	InputOutput::InWhatIfMode() = true;
}