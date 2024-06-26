#pragma once

#include "Operation.h"

class OperationFindAccount final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"FindAccount";  }
	static ClassFactory<OperationFindAccount> RegisteredFactory;

	// operation specific
	PSID tFindSid = nullptr;
	std::wstring sFindSid;

public:

	// overrides
	SidActionResult DetermineSid(const WCHAR * sSdPart, ObjectEntry & tObjectEntry, PSID tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationFindAccount(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};