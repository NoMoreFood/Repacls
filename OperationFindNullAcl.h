#pragma once

#include "Operation.h"

class OperationFindNullAcl final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"FindNullAcl"; }
	static ClassFactory<OperationFindNullAcl> RegisteredFactory;

public:

	// overrides
	bool ProcessAclAction(const WCHAR * sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationFindNullAcl(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};

