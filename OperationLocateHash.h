#pragma once

#include <regex>

#include "Operation.h"

class OperationLocateHash final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"LocateHash"; }
	static ClassFactory<OperationLocateHash> RegisteredFactory;

	// operation specific
	static constexpr int HASH_IN_BYTES = (256 / 8);
	static constexpr int HASH_IN_HEXCHARS = (HASH_IN_BYTES * 2);
	HANDLE hReportFile = INVALID_HANDLE_VALUE;
	std::wregex tRegex;
	PBYTE aHashToMatch = nullptr;
	LONGLONG iSizeToMatch = -1;

public:

	// overrides
	void ProcessObjectAction(ObjectEntry & tObjectEntry) override;

	// constructors
	OperationLocateHash(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};