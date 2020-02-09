#pragma once

#include "Operation.h"

class OperationPrintDescriptor : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"PrintDescriptor"; }
	static ClassFactory<OperationPrintDescriptor> RegisteredFactory;

public:

	// overrides
	bool ProcessSdAction(std::wstring & sFileName, ObjectEntry & tObjectEntry, PSECURITY_DESCRIPTOR & tDescriptor, bool & bDescReplacement) override;

	// constructors
	OperationPrintDescriptor(std::queue<std::wstring> & oArgList, std::wstring sCommand);
};

