#pragma once

#include "Operation.h"

class OperationDomainPaths final : public Operation
{
private:

	// statics used by command registration utility
	static std::wstring GetCommand() { return L"DomainPaths"; }
	static std::wstring GetCommandSite() { return L"DomainPathsWithSite"; }
	static ClassFactory<OperationDomainPaths> RegisteredFactory;
	static ClassFactory<OperationDomainPaths> RegisteredFactorySite;

public:

	// constructors
	OperationDomainPaths(std::queue<std::wstring> & oArgList, const std::wstring & sCommand);
};