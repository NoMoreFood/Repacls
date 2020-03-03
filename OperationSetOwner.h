#pragma once

#include "Operation.h"

class OperationSetOwner : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"SetOwner"; }
	static ClassFactory<OperationSetOwner> RegisteredFactory;

	// operation specific
	PSID tOwnerSid = nullptr;
	std::wstring sOwnerSid = L"";

public:

	// overrides
	SidActionResult DetermineSid(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationSetOwner(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};
