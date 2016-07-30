#pragma once

#include "Operation.h"

class OperationNoHiddenSystem : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"NoHiddenSystem"; }
	static ClassFactory<OperationNoHiddenSystem> * RegisteredFactory;

public:

	// constructors
	OperationNoHiddenSystem(std::queue<std::wstring> & oArgList);
};