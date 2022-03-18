#pragma once

#include "Operation.h"

class OperationCheckCanonical final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"CheckCanonical"; }
	static ClassFactory<OperationCheckCanonical> RegisteredFactory;

public:

	// public enums
	enum AceOrder : unsigned char
	{
		Unspecified = 0,
		ExplicitDeny = 1,
		ExplicitAllow = 2,
		InheritedDeny = 3,
		InheritedAllow = 4,
		MaxAceOrder
	};

	// public functions
	static AceOrder DetermineAceOrder(PACE_ACCESS_HEADER tAce);
	static bool IsAclCanonical(PACL & tCurrentAcl);

	// overrides
	bool ProcessAclAction(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationCheckCanonical(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};

