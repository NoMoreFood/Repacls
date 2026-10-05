#pragma once

#include "Operation.h"

class OperationSetOwner final : public Operation
{

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"SetOwner"; }
	static ClassFactory<OperationSetOwner> RegisteredFactory;

	// operation specific
	PSID tOwnerSid = nullptr;
	std::wstring sOwnerSid;

public:

	// overrides
	SidActionResult DetermineSid(const WCHAR * sSdPart, ObjectEntry & tObjectEntry, PSID tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationSetOwner(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};
