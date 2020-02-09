#pragma once

#include "Operation.h"

class OperationBackupSecurity : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"BackupSecurity"; }
	static ClassFactory<OperationBackupSecurity> RegisteredFactory;

	HANDLE hFile = INVALID_HANDLE_VALUE;
	std::wstring sFile = L"";

public:

	// overrides
	bool ProcessSdAction(std::wstring & sFileName, ObjectEntry & tObjectEntry, PSECURITY_DESCRIPTOR & tDescriptor, bool & bDescReplacement) override;

	// constructors
	OperationBackupSecurity(std::queue<std::wstring> & oArgList, std::wstring sCommand);
};

