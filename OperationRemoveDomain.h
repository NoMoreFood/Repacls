#pragma once

#include "Operation.h"

class OperationRemoveDomain final : public Operation
{

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"RemoveDomain"; }
	static ClassFactory<OperationRemoveDomain> RegisteredFactory;

	// operation specific
	PSID tDomainSid = nullptr;
	std::wstring sDomainName;

public:

	// overrides
	SidActionResult DetermineSid(const WCHAR * sSdPart, ObjectEntry & tObjectEntry, PSID tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationRemoveDomain(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};