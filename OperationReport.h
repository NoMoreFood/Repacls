#pragma once

#include <regex>

#include "Operation.h"

class OperationReport final : public Operation
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
	SidActionResult DetermineSid(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid) override;
	bool ProcessAclAction(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationReport(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};