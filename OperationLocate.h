#pragma once

#include <regex>

#include "Operation.h"

class OperationLocate final : public Operation
{

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"Locate"; }
	static ClassFactory<OperationLocate> RegisteredFactory;

	// operation specific
	HANDLE hReportFile = INVALID_HANDLE_VALUE;
	std::wregex tRegex;

public:

	// overrides
	void ProcessObjectAction(ObjectEntry & tObjectEntry) override;

	// constructors
	OperationLocate(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};