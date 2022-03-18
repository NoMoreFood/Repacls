#pragma once

#include "Operation.h"

class OperationRemoveDomain final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"RemoveDomain"; }
	static ClassFactory<OperationRemoveDomain> RegisteredFactory;

	// operation specific
	PSID tDomainSid = nullptr;
	std::wstring sDomainName = L"";

public:

	// overrides
	SidActionResult DetermineSid(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationRemoveDomain(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};