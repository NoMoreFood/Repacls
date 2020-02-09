#pragma once

#include <regex>

#include "Operation.h"

class OperationReport : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"Report"; }
	static ClassFactory<OperationReport> RegisteredFactory;

	// operation specific
	HANDLE hReportFile = INVALID_HANDLE_VALUE;
	std::wregex tRegex;

public:

	// overrides
	SidActionResult DetermineSid(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid) override;
	bool ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationReport(std::queue<std::wstring> & oArgList, std::wstring sCommand);
};