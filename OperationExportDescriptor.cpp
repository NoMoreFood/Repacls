#include "OperationExportDescriptor.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationExportDescriptor> * OperationExportDescriptor::RegisteredFactory =
new ClassFactory<OperationExportDescriptor>(GetCommand());

OperationExportDescriptor::OperationExportDescriptor(std::queue<std::wstring> & oArgList) : Operation(oArgList)
{
	// exit if there are not enough arguments to part
	std::vector<std::wstring> sSubArgs = ProcessAndCheckArgs(1, oArgList, L"\\0");

	// fetch params
	hFile = CreateFile(sSubArgs[0].c_str(), GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// see if names could be resolved
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// complain
		wprintf(L"ERROR: Could not create file '%s' specified for parameter '%s'.\n", sSubArgs[0].c_str(), GetCommand().c_str());
		exit(-1);
	}

	// flag this as being an ace-level action
	AppliesToSd = true;
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToOwner = true;
	AppliesToGroup = true;
}

bool OperationExportDescriptor::ProcessSdAction(std::wstring & sFileName, ObjectEntry & tObjectEntry, PSECURITY_DESCRIPTOR const tSecurityDescriptor)
{
	// convert the current security descriptor to a string
	WCHAR * sInfo = NULL;
	if (ConvertSecurityDescriptorToStringSecurityDescriptor(tSecurityDescriptor, SDDL_REVISION_1,
		DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
		&sInfo, NULL) == 0)
	{
		InputOutput::AddError(L"ERROR: Unable to generate string security descriptor.");
		return false;
	}

	// write the string to a file
	DWORD iBytes = 0;
	std::wstring sToWrite = sFileName + L"|" + sInfo + L"\r\n";
	if (WriteFile(hFile, sToWrite.c_str(), (DWORD)sToWrite.size() * sizeof(WCHAR), &iBytes, NULL) == 0)
	{
		LocalFree(sInfo);
		InputOutput::AddError(L"ERROR: Unable to write security descriptor to file.");
		return false;
	}

	// cleanup
	LocalFree(sInfo);
	return false;
}
