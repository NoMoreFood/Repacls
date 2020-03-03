#pragma once

#include <regex>

#include "Operation.h"

class OperationLocateShortcut : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"LocateShortcut"; }
	static ClassFactory<OperationLocateShortcut> RegisteredFactory;

	// operation specific
	HANDLE hReportFile = INVALID_HANDLE_VALUE;
	std::wregex tRegexTarget;
	std::wregex tRegexLink;

public:

	// overrides
	void ProcessObjectAction(ObjectEntry & tObjectEntry) override;

	// constructors
	OperationLocateShortcut(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};