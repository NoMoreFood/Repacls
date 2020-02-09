#pragma once

#include "Operation.h"

class OperationCopyDomain : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"CopyDomain"; }
	static ClassFactory<OperationCopyDomain> RegisteredFactory;

	// operation specific
	PSID tSourceDomain = nullptr;
	std::wstring sSourceDomain = L"";
	PSID tTargetDomain = nullptr;
	std::wstring sTargetDomain = L"";

public:

	// overrides
	bool ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationCopyDomain(std::queue<std::wstring> & oArgList, std::wstring sCommand);
};