#pragma once

#include "Operation.h"

class OperationResetChildren : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"ResetChildren"; }
	static ClassFactory<OperationResetChildren> * RegisteredFactory;

	// used for clearing out explicit aces
	ACL tAclNull = { 0, 0, 0, 0, 0 };

public:

	// overrides
	bool ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationResetChildren(std::queue<std::wstring> & oArgList);
};

