#pragma once

#include "Operation.h"

class OperationFindDomain final : public Operation
{

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"FindDomain"; }
	static ClassFactory<OperationFindDomain> RegisteredFactory;

	// operation specific
	PSID tDomainSid = nullptr;
	std::wstring sDomainName;

public:

	// overrides
	SidActionResult DetermineSid(const WCHAR * sSdPart, ObjectEntry & tObjectEntry, PSID tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationFindDomain(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};
