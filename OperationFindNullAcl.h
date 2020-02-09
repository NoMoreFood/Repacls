#pragma once

#include "Operation.h"

class OperationFindNullAcl : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"FindNullAcl"; }
	static ClassFactory<OperationFindNullAcl> RegisteredFactory;

public:

	// overrides
	bool ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationFindNullAcl(std::queue<std::wstring> & oArgList, std::wstring sCommand);
};

