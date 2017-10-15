#pragma once

#include "Operation.h"

class OperationReplaceMap : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"ReplaceMap"; }
	static ClassFactory<OperationReplaceMap> * RegisteredFactory;

	// operation specific
	std::map<PSID, PSID, SidCompare> oReplaceMap;

public:

	// overrides
	SidActionResult DetermineSid(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid) override;

	// constructors
	OperationReplaceMap(std::queue<std::wstring> & oArgList);
};