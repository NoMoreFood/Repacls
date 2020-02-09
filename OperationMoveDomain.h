#pragma once

#include "Operation.h"

class OperationMoveDomain : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"MoveDomain"; }
	static ClassFactory<OperationMoveDomain> RegisteredFactory;

	// operation specific
	PSID tSourceDomain = nullptr;
	std::wstring sSourceDomain = L"";
	PSID tTargetDomain = nullptr;
	std::wstring sTargetDomain = L"";

public:

	// overrides
	SidActionResult DetermineSid(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationMoveDomain(std::queue<std::wstring> & oArgList, std::wstring sCommand);
};