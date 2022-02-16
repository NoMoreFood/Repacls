#pragma once

#include "Operation.h"

class OperationPathMode : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"PathMode"; }
	static ClassFactory<OperationPathMode> RegisteredFactory;

public:

	// constructors
	OperationPathMode(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);

	// public functions
	static SE_OBJECT_TYPE& GetPathMode() noexcept { static SE_OBJECT_TYPE iPathMode = SE_FILE_OBJECT; return iPathMode; };
};