#pragma once

#include "Operation.h"

class OperationRestoreSecurity : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"RestoreSecurity"; }
	static ClassFactory<OperationRestoreSecurity> RegisteredFactory;

	std::map<std::wstring, PSECURITY_DESCRIPTOR> oImportMap;
	std::wstring sFile = L"";

public:

	// overrides
	bool ProcessSdAction(std::wstring & sFileName, ObjectEntry & tObjectEntry, PSECURITY_DESCRIPTOR & tDescriptor, bool & bDescReplacement) override;

	// constructors
	OperationRestoreSecurity(std::queue<std::wstring> & oArgList, std::wstring sCommand);
};

