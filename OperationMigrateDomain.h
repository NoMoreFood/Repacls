#pragma once

#include "Operation.h"

class OperationMigrateDomain : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"MigrateDomain"; }
	static ClassFactory<OperationMigrateDomain> * RegisteredFactory;

	// operation specific
	PSID tSourceDomain = nullptr;
	std::wstring sSourceDomain = L"";
	PSID tTargetDomain = nullptr;
	std::wstring sTargetDomain = L"";

public:

	// overrides
	SidActionResult DetermineSid(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationMigrateDomain(std::queue<std::wstring> & oArgList);
};