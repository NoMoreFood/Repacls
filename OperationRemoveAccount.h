#pragma once

#include "Operation.h"

class OperationRemoveAccount final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"RemoveAccount"; }
	static ClassFactory<OperationRemoveAccount> RegisteredFactory;

	// operation specific
	PSID tRemoveSid = nullptr;
	std::wstring sRemoveSid = L"";

public:

	// overrides
	SidActionResult DetermineSid(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationRemoveAccount(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};