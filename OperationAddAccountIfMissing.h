#pragma once

#include "Operation.h"
#include "OperationGrantDenyPerms.h"

class OperationAddAccountIfMissing : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"AddAccountIfMissing"; }
	static ClassFactory<OperationAddAccountIfMissing> RegisteredFactory;

	// operation specific
	OperationGrantDenyPerms * oDelegate;

public:

	// overrides
	bool ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationAddAccountIfMissing(std::queue<std::wstring> & oArgList, std::wstring sCommand);
};