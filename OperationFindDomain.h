#pragma once

#include "Operation.h"

class OperationFindDomain : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"FindDomain"; }
	static ClassFactory<OperationFindDomain> RegisteredFactory;

	// operation specific
	PSID tDomainSid = nullptr;
	std::wstring sDomainName = L"";

public:

	// overrides
	SidActionResult DetermineSid(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationFindDomain(std::queue<std::wstring> & oArgList, std::wstring sCommand);
};
