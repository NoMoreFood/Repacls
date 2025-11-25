#pragma once

#include "Operation.h"

class OperationWhatIf final : public Operation
{

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"WhatIf"; }
	static ClassFactory<OperationWhatIf> RegisteredFactory;

public:

	// constructors
	OperationWhatIf(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};