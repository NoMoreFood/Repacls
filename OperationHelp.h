#pragma once

#include "Operation.h"

class OperationHelp : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"Help"; }
	static std::wstring GetCommandAltOne() { return L"?"; }
	static std::wstring GetCommandAltTwo() { return L"H"; }
	static ClassFactory<OperationHelp> * RegisteredFactory;
	static ClassFactory<OperationHelp> * RegisteredFactoryAltOne;
	static ClassFactory<OperationHelp> * RegisteredFactoryAltTwo;

public:

	// constructors
	OperationHelp(std::queue<std::wstring> & oArgList);
};