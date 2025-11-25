#pragma once

#include "Operation.h"

class OperationCanonicalizeAcls final : public Operation
{

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"CanonicalizeAcls"; }
	static ClassFactory<OperationCanonicalizeAcls> RegisteredFactory;

public:

	// overrides
	bool ProcessAclAction(const WCHAR * sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationCanonicalizeAcls(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};

