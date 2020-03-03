#pragma once

#include "Operation.h"

class OperationThreads : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"Threads"; }
	static ClassFactory<OperationThreads> RegisteredFactory;

public:

	// constructors
	OperationThreads(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};