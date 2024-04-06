#pragma once

#include "Operation.h"

class OperationGrantDenyPerms final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommandAdd() { return L"GrantPerms"; }
	static std::wstring GetCommandDeny() { return L"DenyPerms"; }
	static ClassFactory<OperationGrantDenyPerms> RegisteredFactoryGrant;
	static ClassFactory<OperationGrantDenyPerms> RegisteredFactoryDeny;

	// operation specific
	EXPLICIT_ACCESS tEa;
	std::wstring sIdentity;
	std::wstring sPerms;

public:

	// overrides
	bool ProcessAclAction(const WCHAR* sSdPart, ObjectEntry& tObjectEntry, PACL& tCurrentAcl, bool& bAclReplacement) override;

	// constructors
	OperationGrantDenyPerms(std::queue<std::wstring>& oArgList, const std::wstring & sCommand);
};