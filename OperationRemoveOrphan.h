#pragma once

#include "Operation.h"

class OperationRemoveOrphan final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"RemoveOrphans"; }
	static ClassFactory<OperationRemoveOrphan> RegisteredFactory;

	// operation specific
	PSID tDomainSid = nullptr;
	std::wstring sDomainName;

public:

	// overrides
	SidActionResult DetermineSid(const WCHAR * sSdPart, ObjectEntry & tObjectEntry, PSID tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationRemoveOrphan(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};