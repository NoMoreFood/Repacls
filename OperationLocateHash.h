#pragma once

#include <Windows.h>
#include <regex>
#include <vector>

#include "Operation.h"

class OperationLocateHash final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"LocateHash"; }
	static ClassFactory<OperationLocateHash> RegisteredFactory;

	// operation specific
	HANDLE hReportFile = INVALID_HANDLE_VALUE;
	std::wregex tRegex;
	std::vector<BYTE> aHashToMatch;
	LONGLONG iSizeToMatch = -1;

	// hashing environment
	BCRYPT_ALG_HANDLE hAlgHandle = nullptr;
	BCRYPT_HASH_HANDLE hHashHandle = nullptr;
	std::vector<BYTE> aHash;
	std::vector<BYTE> aFileBuffer;
	DWORD iHashLength = 0;

public:

	// overrides
	void ProcessObjectAction(ObjectEntry & tObjectEntry) override;

	// constructors
	OperationLocateHash(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);

	// destructor
	~OperationLocateHash();
};