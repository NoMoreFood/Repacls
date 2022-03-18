#pragma once

#include "Operation.h"

class OperationReplaceAccount final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"ReplaceAccount"; }
	static ClassFactory<OperationReplaceAccount> RegisteredFactory;

	// operation specific
	PSID tSearchAccount = nullptr;
	std::wstring sSearchAccount = L"";
	PSID tReplaceAccount = nullptr;
	std::wstring sReplaceAccount = L"";

public:

	// overrides
	SidActionResult DetermineSid(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationReplaceAccount(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};