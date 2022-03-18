#pragma once

#include "Operation.h"

class OperationPath final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"Path"; }
	static ClassFactory<OperationPath> RegisteredFactory;

public:

	// constructors
	OperationPath(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};