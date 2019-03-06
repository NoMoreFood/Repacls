#pragma once

#include "Operation.h"

class OperationCheckCanonical : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"CheckCanonical"; }
	static ClassFactory<OperationCheckCanonical> * RegisteredFactory;

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
	static AceOrder DetermineAceOrder(ACCESS_ACE * tAce);

	// overrides
	bool ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationCheckCanonical(std::queue<std::wstring> & oArgList);
};

