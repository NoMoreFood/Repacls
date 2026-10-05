#pragma once

#include <regex>

#include "Operation.h"

class OperationLocateText final : public Operation
{

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"LocateText"; }
	static ClassFactory<OperationLocateText> RegisteredFactory;

	// operation specific
	HANDLE hReportFile = INVALID_HANDLE_VALUE;
	std::wregex tFileRegex;
	std::wregex tTextRegex;

public:

	// overrides
	void ProcessObjectAction(ObjectEntry & tObjectEntry) override;

	// constructors
	OperationLocateText(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};
