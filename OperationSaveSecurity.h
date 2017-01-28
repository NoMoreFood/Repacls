#pragma once

#include "Operation.h"

class OperationSaveSecurity : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"SaveSecurity"; }
	static ClassFactory<OperationSaveSecurity> * RegisteredFactory;

	HANDLE hFile = INVALID_HANDLE_VALUE;
	std::wstring sFile = L"";

public:

	// overrides
	bool ProcessSdAction(std::wstring & sFileName, ObjectEntry & tObjectEntry, PSECURITY_DESCRIPTOR & tDescriptor, bool & bDescReplacement) override;

	// constructors
	OperationSaveSecurity(std::queue<std::wstring> & oArgList);
};

