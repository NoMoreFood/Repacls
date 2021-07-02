#include "OperationBackupSecurity.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationBackupSecurity> OperationBackupSecurity::RegisteredFactory(GetCommand());

OperationBackupSecurity::OperationBackupSecurity(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList, L"\\0");

	// fetch params
	hFile = CreateFile(sSubArgs.at(0).c_str(), GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	// see if names could be resolved
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// complain
		wprintf(L"ERROR: Could not create file '%s' specified for parameter '%s'.\n", sSubArgs.at(0).c_str(), GetCommand().c_str());
		exit(-1);
	}

	// write out the file type marker
	const BYTE hHeader[] = { 0xEF,0xBB,0xBF };
	DWORD iBytes = 0;
	if (WriteFile(hFile, &hHeader, _countof(hHeader), &iBytes, nullptr) == 0)
	{
		wprintf(L"ERROR: Could not write out file type marker '%s'.\n", GetCommand().c_str());
		exit(-1);
	}

	// flag this as being an ace-level action
	AppliesToSd = true;
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToOwner = true;
	AppliesToGroup = true;
}

bool OperationBackupSecurity::ProcessSdAction(std::wstring & sFileName, ObjectEntry & tObjectEntry, PSECURITY_DESCRIPTOR & tDescriptor, bool & bDescReplacement)
{
	// convert the current security descriptor to a string
	WCHAR * sInfo = NULL;
	if (ConvertSecurityDescriptorToStringSecurityDescriptor(tDescriptor, SDDL_REVISION_1,
		DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
		&sInfo, NULL) == 0)
	{
		InputOutput::AddError(L"Unable to generate string security descriptor.");
		return false;
	}

	// write the string to a file
	std::wstring sToWrite = sFileName + L"|" + sInfo + L"\r\n";
	if (WriteToFile(sToWrite, hFile) == 0)
	{
		LocalFree(sInfo);
		InputOutput::AddError(L"Unable to write security descriptor to file.");
		return false;
	}

	// cleanup
	LocalFree(sInfo);
	return false;
}
