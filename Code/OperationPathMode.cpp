#include "OperationPathMode.h"
#include "InputOutput.h"
#include "Helpers.h"

ClassFactory<OperationPathMode> OperationPathMode::RegisteredFactory(GetCommand());

OperationPathMode::OperationPathMode(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	const std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList, L"\\0");

	// see what mode the argument
	if (_wcsicmp(sSubArgs.at(0).c_str(), L"REG") == 0 || _wcsicmp(sSubArgs.at(0).c_str(), L"REGISTRY") == 0) GetPathMode() = SE_REGISTRY_KEY;
	else if (_wcsicmp(sSubArgs.at(0).c_str(), L"ADS") == 0 || _wcsicmp(sSubArgs.at(0).c_str(), L"ACTIVEDIRECTORY") == 0) GetPathMode() = SE_DS_OBJECT;
	else if (_wcsicmp(sSubArgs.at(0).c_str(), L"FILE") == 0) GetPathMode() = SE_FILE_OBJECT;
	else
	{
		// complain
		Print(L"ERROR: Invalid path mode specified for parameter '{}'.", GetCommand());
		std::exit(-1);
	}
};