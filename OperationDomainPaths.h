#pragma once

#include "Operation.h"

class OperationDomainPaths : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"DomainPaths"; }
	static ClassFactory<OperationDomainPaths> RegisteredFactory;

public:

	// constructors
	OperationDomainPaths(std::queue<std::wstring> & oArgList, std::wstring sCommand);
};