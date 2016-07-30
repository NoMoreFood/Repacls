#pragma once

#include "Operation.h"

class OperationExportDescriptor : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"ExportDescriptor"; }
	static ClassFactory<OperationExportDescriptor> * RegisteredFactory;

	HANDLE hFile = INVALID_HANDLE_VALUE;
	std::wstring sFile = L"";

public:

	// overrides
	bool ProcessSdAction(std::wstring & sFileName, ObjectEntry & tObjectEntry, PSECURITY_DESCRIPTOR const tSecurityDescriptor) override;

	// constructors
	OperationExportDescriptor(std::queue<std::wstring> & oArgList);
};

