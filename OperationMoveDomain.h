#pragma once

#include "Operation.h"

class OperationMoveDomain final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"MoveDomain"; }
	static ClassFactory<OperationMoveDomain> RegisteredFactory;

	// operation specific
	PSID tSourceDomain = nullptr;
	std::wstring sSourceDomain;
	PSID tTargetDomain = nullptr;
	std::wstring sTargetDomain;

public:

	// overrides
	SidActionResult DetermineSid(const WCHAR * sSdPart, ObjectEntry & tObjectEntry, PSID tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationMoveDomain(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};