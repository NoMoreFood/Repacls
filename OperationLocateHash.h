#pragma once

#include <Windows.h>
#include <regex>
#include <vector>

#include "Operation.h"

class OperationLocateHash final : public Operation
{

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"LocateHash"; }
	static ClassFactory<OperationLocateHash> RegisteredFactory;

	// operation specific
	HANDLE hReportFile = INVALID_HANDLE_VALUE;
	std::wregex tRegex;
	std::vector<BYTE> aHashToMatch;
	LONGLONG iSizeToMatch = -1;

	// hashing environment (algorithm handle and hash length are read-only after construction;
	// per-thread hash/buffer state lives as thread_local inside ProcessObjectAction)
	BCRYPT_ALG_HANDLE hAlgHandle = nullptr;
	DWORD iHashLength = 0;

public:

	// overrides
	void ProcessObjectAction(ObjectEntry & tObjectEntry) override;

	// constructors
	OperationLocateHash(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);

	// destructor
	~OperationLocateHash() override;
};