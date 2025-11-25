#pragma once

#include "Operation.h"

class OperationNoHiddenSystem final : public Operation
{

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"NoHiddenSystem"; }
	static ClassFactory<OperationNoHiddenSystem> RegisteredFactory;

public:

	// constructors
	OperationNoHiddenSystem(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};