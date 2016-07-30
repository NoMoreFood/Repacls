#include "OperationWhatIf.h"
#include "InputOutput.h"

ClassFactory<OperationWhatIf> * OperationWhatIf::RegisteredFactory =
new ClassFactory<OperationWhatIf>(GetCommand());

OperationWhatIf::OperationWhatIf(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	InputOutput::InWhatIfMode() = true;
}