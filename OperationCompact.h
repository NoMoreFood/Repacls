#pragma once

#include "Operation.h"

class OperationCompact : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"Compact"; }
	static ClassFactory<OperationCompact> * RegisteredFactory;

public:

	// overrides
	bool ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationCompact(std::queue<std::wstring> & oArgList);
};

