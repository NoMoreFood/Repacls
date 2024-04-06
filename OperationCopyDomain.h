#pragma once

#include "Operation.h"

class OperationCopyDomain final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"CopyDomain"; }
	static ClassFactory<OperationCopyDomain> RegisteredFactory;

	// operation specific
	PSID tSourceDomain = nullptr;
	std::wstring sSourceDomain;
	PSID tTargetDomain = nullptr;
	std::wstring sTargetDomain;

public:

	// overrides
	bool ProcessAclAction(const WCHAR * sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement) override;

	// constructors
	OperationCopyDomain(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};