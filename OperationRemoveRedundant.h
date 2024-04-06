#pragma once

#include "Operation.h"

class OperationRemoveRedundant final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"RemoveRedundant"; }
	static ClassFactory<OperationRemoveRedundant> RegisteredFactory;

public:

	// overrides
	bool ProcessAclAction(const WCHAR * sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationRemoveRedundant(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};

