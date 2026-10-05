#pragma once

#include "Operation.h"

class OperationRemoveAccount final : public Operation
{

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"RemoveAccount"; }
	static ClassFactory<OperationRemoveAccount> RegisteredFactory;

	// operation specific
	PSID tRemoveSid = nullptr;
	std::wstring sRemoveSid;

public:

	// overrides
	SidActionResult DetermineSid(const WCHAR * sSdPart, ObjectEntry & tObjectEntry, PSID tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationRemoveAccount(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};