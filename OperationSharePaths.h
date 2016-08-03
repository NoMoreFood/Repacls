#pragma once

#include "Operation.h"

class OperationSharePaths : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"SharePaths"; }
	static ClassFactory<OperationSharePaths> * RegisteredFactory;

public:

	// constructors
	OperationSharePaths(std::queue<std::wstring> & oArgList);
};