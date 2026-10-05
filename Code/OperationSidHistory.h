#pragma once

#include "Operation.h"

class OperationSidHistory final : public Operation
{

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"UpdateHistoricalSids"; }
	static ClassFactory<OperationSidHistory> RegisteredFactory;

public:

	// overrides
	SidActionResult DetermineSid(const WCHAR * sSdPart, ObjectEntry & tObjectEntry, PSID tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationSidHistory(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};
