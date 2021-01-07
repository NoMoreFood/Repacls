#pragma once

#include "Operation.h"

class OperationInheritChildren : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"InheritChildren"; }
	static ClassFactory<OperationInheritChildren> RegisteredFactory;

public:

	// overrides
	bool ProcessAclAction(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationInheritChildren(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};

