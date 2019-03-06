#pragma once

#include "Operation.h"

class OperationCanonicalizeAcls : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"CanonicalizeAcls"; }
	static ClassFactory<OperationCanonicalizeAcls> * RegisteredFactory;

public:

	// overrides
	bool ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationCanonicalizeAcls(std::queue<std::wstring> & oArgList);
};

