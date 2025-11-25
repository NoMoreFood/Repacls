#include "InputOutput.h"
#include "ObjectRegistry.h"

void ObjectRegistry::GetBaseObject(std::wstring sPath)
{
	const static std::map<std::wstring_view, std::pair<HKEY, std::wstring>> oRegMap = {
	{ L"HKLM",                   { HKEY_LOCAL_MACHINE, L"MACHINE"     }},
	{ L"HKEY_LOCAL_MACHINE",     { HKEY_LOCAL_MACHINE, L"MACHINE"     }},
	{ L"HKU",                    { HKEY_USERS, L"MACHINE"             }},
	{ L"HKEY_USERS",             { HKEY_USERS, L"MACHINE"             }},
	{ L"HKCU",                   { HKEY_CURRENT_USER, L"CURRENT_USER" }},
	{ L"HKEY_CURRENT_USER",      { HKEY_CURRENT_USER, L"CURRENT_USER" }},
	{ L"HKCC",                   { HKEY_CURRENT_CONFIG, L"CONFIG"     }},
	{ L"HKEY_CURRENT_CONFIG",    { HKEY_CURRENT_CONFIG, L"CONFIG"     }},
	{ L"HKCR",                   { HKEY_CLASSES_ROOT, L"CLASSES_ROOT" }},
	{ L"HKEY_CLASSES_ROOT",      { HKEY_CLASSES_ROOT, L"CLASSES_ROOT" }}
	};

	// attempt to translate the string path to a key and subpath
	ObjectEntry tReg = {};
	std::wstring sRootName = sPath;
	const size_t iBackSlash = sPath.find(L'\\');
	if (iBackSlash != std::wstring::npos)
	{
		sRootName = sPath.substr(0, iBackSlash);
		tReg.NameExtended = sPath.substr(iBackSlash + 1);
	}

	const auto oRootEntry = oRegMap.find(sRootName);
	if (oRootEntry == oRegMap.end())
	{
		Print(L"ERROR: Could not parse registry path: {}", sPath);
		std::exit(-1);
	}

	tReg.Depth = 0;
	tReg.ObjectType = SE_REGISTRY_KEY;
	tReg.Name = oRootEntry->second.second + L"\\" + tReg.NameExtended;
	tReg.hObject = oRootEntry->second.first;
	tReg.Attributes = FILE_ATTRIBUTE_DIRECTORY;
	oProcessor.GetQueue().Push(tReg);
}

void ObjectRegistry::GetChildObjects(ObjectEntry& oEntry)
{
	// open handle so we can enumerate subkeys
	HKEY hParentKey = nullptr;
	if (RegOpenKeyEx(static_cast<HKEY>(oEntry.hObject), oEntry.NameExtended.c_str(), REG_OPTION_OPEN_LINK, 
		KEY_ENUMERATE_SUB_KEYS, &hParentKey) != ERROR_SUCCESS)
	{
		InputOutput::AddError(L"Access denied error occurred while enumerating registry key");
		Processor::CompleteEntry(oEntry);
		++oProcessor.ItemsEnumerationFailures;
		return;
	}

	// analyze security on this node
	oProcessor.AnalyzeSecurity(oEntry);

	// enumerate children
	HRESULT hResult = ERROR_SUCCESS;
	WCHAR sKeyName[MAX_PATH];
	DWORD iKeyName = _countof(sKeyName);
	for (DWORD iIndex = 0; (hResult = RegEnumKeyEx(hParentKey, iIndex, sKeyName, &iKeyName, nullptr,
			nullptr, nullptr, &oEntry.ModifiedTime)) != ERROR_NO_MORE_ITEMS; ++iIndex, iKeyName = _countof(sKeyName))
	{
		if (hResult != S_OK && hResult != ERROR_MORE_DATA)
		{
			continue;
		}

		const LPCWSTR sSeperator = oEntry.NameExtended.empty() ? L"" : L"\\";
		ObjectEntry tReg = {};
		tReg.Depth = oEntry.Depth + 1;
		tReg.ObjectType = SE_REGISTRY_KEY;
		tReg.hObject = oEntry.hObject;
		tReg.Name = oEntry.Name + sSeperator + sKeyName;
		tReg.NameExtended = oEntry.NameExtended + sSeperator + sKeyName;
		tReg.Attributes = FILE_ATTRIBUTE_DIRECTORY;
		oProcessor.GetQueue().Push(tReg);
	}

	// cleanup and commit
	RegCloseKey(hParentKey);
	Processor::CompleteEntry(oEntry);
}
