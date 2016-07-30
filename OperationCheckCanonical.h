#pragma once

#include "Operation.h"

class OperationCheckCanonical : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"CheckCanonical"; }
	static ClassFactory<OperationCheckCanonical> * RegisteredFactory;

public:

	// overrides
	bool ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationCheckCanonical(std::queue<std::wstring> & oArgList);
};

