#pragma once

#include "Operation.h"

class OperationSidHistory : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"UpdateHistoricalSids"; }
	static ClassFactory<OperationSidHistory> RegisteredFactory;

public:

	// overrides
	SidActionResult DetermineSid(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationSidHistory(std::queue<std::wstring> & oArgList, std::wstring sCommand);
};
