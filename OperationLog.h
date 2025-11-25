#pragma once

#include "Operation.h"

class OperationLog final : public Operation
{

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"Log"; }
	static ClassFactory<OperationLog> RegisteredFactory;

	static HANDLE hLogHandle;

public:

	// constructors
	OperationLog(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);

	// functions
	static void LogFileItem(const std::wstring & sInfoLevel, const std::wstring & sPath, const std::wstring & sMessage);
};
