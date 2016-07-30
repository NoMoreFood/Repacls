#pragma once

#include "Operation.h"

class OperationQuiet : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"Quiet"; }
	static ClassFactory<OperationQuiet> * RegisteredFactory;

public:

	// constructors
	OperationQuiet(std::queue<std::wstring> & oArgList);
};