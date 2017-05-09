#pragma once

#include "Operation.h"

class FactoryPlant
{
protected:

	virtual Operation * CreateInstanceSub(std::queue<std::wstring> & oArgList) = 0;

	static std::map<std::wstring, FactoryPlant *> & GetCommands()
	{
		static std::map<std::wstring, FactoryPlant *> vCommands;
		return vCommands;
	}

public:

	static Operation * CreateInstance(std::queue<std::wstring> & oArgList)
	{
		// get the first element off the list
		std::wstring sCommand = oArgList.front(); oArgList.pop();

		// error if the string is least one character long
		if (sCommand.size() == 0) return nullptr;

		// error if the string does not start with "/" or "-"
		if (sCommand.at(0) != '/' && sCommand.at(0) != '-')
		{
			wprintf(L"ERROR: Unrecognized parameter '%s'\n", sCommand.c_str());
			exit(-1);
		}

		// convert to uppercase for map matching
		std::transform(sCommand.begin(), sCommand.end(), sCommand.begin(), 
			[](const WCHAR c) { return static_cast<WCHAR>(::toupper(c)); });

		// remove the first character
		sCommand.erase(0, 1);

		// see if there's a class that matches this
		std::map<std::wstring, FactoryPlant *>::iterator
			oCommand = GetCommands().find(sCommand);

		// error if there is no matching command
		if (oCommand == GetCommands().end())
		{
			wprintf(L"ERROR: Unrecognized parameter '%s'\n", sCommand.c_str());
			exit(-1);
		}

		// create the the new class
		return GetCommands()[sCommand]->CreateInstanceSub(oArgList);
	}
};

template <class SubType> class ClassFactory : public FactoryPlant
{
private:

	Operation * CreateInstanceSub(std::queue<std::wstring> & oArgList)
	{
		return new SubType(oArgList);
	}

public:

	ClassFactory(std::wstring sCommand)
	{
		std::transform(sCommand.begin(), sCommand.end(), sCommand.begin(), 
			[](const WCHAR c) { return static_cast<WCHAR>(::toupper(c)); });
		GetCommands()[sCommand] = this;
	};
};
