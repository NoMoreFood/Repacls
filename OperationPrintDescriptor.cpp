#include "OperationPrintDescriptor.h"
#include "DriverKitPartial.h"
#include "InputOutput.h"
#include "Helpers.h"

ClassFactory<OperationPrintDescriptor> OperationPrintDescriptor::RegisteredFactory(GetCommand());

OperationPrintDescriptor::OperationPrintDescriptor(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// flag this as being an ace-level action
	AppliesToSd = true;
	AppliesToDacl = true;
	AppliesToSacl = true;
	AppliesToOwner = true;
	AppliesToGroup = true;
}

bool OperationPrintDescriptor::ProcessSdAction(std::wstring & sFileName, ObjectEntry & tObjectEntry, PSECURITY_DESCRIPTOR & tDescriptor, bool & bDescReplacement)
{
	// convert the current security descriptor to a string
	WCHAR * sInfo = nullptr;
	if (ConvertSecurityDescriptorToStringSecurityDescriptor(tDescriptor, SDDL_REVISION_1,
		DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
		&sInfo, nullptr) == 0)
	{
		InputOutput::AddError(L"Unable to generate string security descriptor.");
		return false;
	}

	// write to screen
	InputOutput::AddInfo(L"SD: " + std::wstring(sInfo), L"", true);
	LocalFree(sInfo);
	return false;
}
