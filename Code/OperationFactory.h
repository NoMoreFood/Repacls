#pragma once

#include "Operation.h"

class FactoryPlant
{
protected:

	virtual Operation * CreateInstanceSub(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) = 0;

	static std::map<std::wstring, FactoryPlant *> & GetCommands()
	{
		static std::map<std::wstring, FactoryPlant *> vCommands;
		return vCommands;
	}

public:
	
	virtual ~FactoryPlant() = default;

	static Operation * CreateInstance(std::queue<std::wstring> & oArgList)
	{
		// get the first element off the list
		std::wstring sCommand = oArgList.front(); oArgList.pop();

		// error if the string is at least one character long
		if (sCommand.empty()) return nullptr;

		// error if the string does not start with "/" or "-"
		if (sCommand.at(0) != '/' && sCommand.at(0) != '-')
		{
			Print(L"ERROR: Unrecognized parameter '{}'", sCommand);
			std::exit(-1);
		}

		// convert to uppercase for map matching
		ConvertToUpper(sCommand);

		// remove the first character
		sCommand.erase(0, 1);

		// see if there's a class that matches this
		const auto oCommand = GetCommands().find(sCommand);

		// error if there is no matching command
		if (oCommand == GetCommands().end())
		{
			Print(L"ERROR: Unrecognized parameter '{}'", sCommand);
			std::exit(-1);
		}

		// create the new class
		return GetCommands()[sCommand]->CreateInstanceSub(oArgList, sCommand);
	}
};

template <class SubType> class ClassFactory final : public FactoryPlant
{

	Operation * CreateInstanceSub(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) override
	{
		return new SubType(oArgList, sCommand);
	}

public:

	ClassFactory(std::wstring sCommand)
	{
		ConvertToUpper(sCommand);
		GetCommands()[sCommand] = this;
	}
};
