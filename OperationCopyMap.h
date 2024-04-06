#pragma once

#include "Operation.h"

class OperationCopyMap final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"CopyMap"; }
	static ClassFactory<OperationCopyMap> RegisteredFactory;

	// operation specific
	std::map<std::wstring, PSID> oCopyMap;

public:

	// overrides
	bool ProcessAclAction(const WCHAR* sSdPart, ObjectEntry& tObjectEntry, PACL& tCurrentAcl, bool& bAclReplacement) override;

	// constructors
	OperationCopyMap(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};