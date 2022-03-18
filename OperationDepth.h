#pragma once

#include "Operation.h"

class OperationDepth final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"MaxDepth"; }
	static ClassFactory<OperationDepth> RegisteredFactory;

public:

	// constructors
	OperationDepth(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);

	// public functions
	static unsigned int& MaxDepth() noexcept { static unsigned int iMaxDepth = UINT_MAX; return iMaxDepth; }
};