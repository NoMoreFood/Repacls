#include "OperationLocateShortcut.h"
#include "InputOutput.h"
#include "Helpers.h"

#include <atlbase.h>
#include <ShlObj.h>

ClassFactory<OperationLocateShortcut> OperationLocateShortcut::RegisteredFactory(GetCommand());

#define Q(x) L"\"" + (x) + L"\""

OperationLocateShortcut::OperationLocateShortcut(std::queue<std::wstring>& oArgList, const std::wstring& sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sReportFile = ProcessAndCheckArgs(1, oArgList, L"\\0");
	std::vector<std::wstring> sMatchAndArgs = ProcessAndCheckArgs(1, oArgList, L"\\0");

	// fetch params
	HANDLE hFile = CreateFile(sReportFile.at(0).c_str(), GENERIC_WRITE,
		FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	// see if names could be resolved
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// complain
		wprintf(L"ERROR: Could not create file '%s' specified for parameter '%s'.\n", sReportFile.at(0).c_str(), GetCommand().c_str());
		std::exit(-1);
	}

	// register the file handle
	hReportFile = RegisterFileHandle(hFile, GetCommand());

	// if this is the first handle using this file, write out a header
	if (hFile == hReportFile)
	{
		// write out the file type marker
		constexpr BYTE hHeader[] = { 0xEF,0xBB,0xBF };
		DWORD iBytes = 0;
		if (WriteFile(hFile, &hHeader, _countof(hHeader), &iBytes, nullptr) == 0)
		{
			wprintf(L"ERROR: Could not write out file type marker '%s'.\n", GetCommand().c_str());
			std::exit(-1);
		}

		// write out the header
		std::wstring sToWrite = std::wstring(L"") + Q(L"Path") + L"," + Q(L"Creation Time") + L"," +
			Q(L"Modified Time") + L"," + Q(L"Size") + L"," + Q(L"Attributes") + L"," +
			Q(L"Target Path") + L"," + Q(L"Working Directory") + L"\r\n";
		if (WriteToFile(sToWrite, hReportFile) == 0)
		{
			wprintf(L"ERROR: Could not write header to report file for parameter '%s'.\n", GetCommand().c_str());
			std::exit(-1);
		}
	}

	// only flag this to apply to the core object with the file name
	AppliesToObject = true;

	// compile the regular expression
	try
	{
		tRegexTarget = std::wregex(sMatchAndArgs.at(0), std::wregex::icase | std::wregex::optimize);
		tRegexLink = std::wregex(L".*\\.lnk", std::wregex::icase | std::wregex::optimize);
	}
	catch (const std::regex_error&)
	{
		wprintf(L"ERROR: Invalid regular expression '%s' specified for parameter '%s'.\n", sMatchAndArgs.at(0).c_str(), GetCommand().c_str());
		std::exit(-1);
	}
}

void OperationLocateShortcut::ProcessObjectAction(ObjectEntry& tObjectEntry)
{
	// skip directories
	if (IsDirectory(tObjectEntry.Attributes)) return;

	// skip any file names that do not match the regex
	const WCHAR* sFileName = tObjectEntry.Name.c_str();
	if (wcsrchr(sFileName, '\\') != nullptr) sFileName = wcsrchr(sFileName, '\\') + 1;
	if (!std::regex_match(sFileName, tRegexLink)) return;

	// initialize com for this thread
	InitThreadCom();

	// fetch file attribute data
	WIN32_FILE_ATTRIBUTE_DATA tData = {};
	if (tObjectEntry.ObjectType == SE_FILE_OBJECT &&
		GetFileAttributesExW(tObjectEntry.Name.c_str(), GetFileExInfoStandard, &tData) == 0)
	{
		InputOutput::AddError(L"Unable to read file attributes.");
	}

	// get common file attributes
	const std::wstring sSize = FileSizeToString(tObjectEntry.FileSize);
	const std::wstring sAttributes = FileAttributesToString(tObjectEntry.Attributes);
	const std::wstring sModifiedTime = FileTimeToString(tObjectEntry.ModifiedTime);
	const std::wstring sCreationTime = FileTimeToString(tObjectEntry.CreationTime);

	// create shortcut interfaces
	CComPtr<IShellLinkW> oLink = nullptr;
	CComPtr<IPersistFile> oFile = nullptr;
	if (CoCreateInstance(__uuidof(ShellLink), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&oLink)) != S_OK ||
		oLink->QueryInterface(IID_PPV_ARGS(&oFile)) != S_OK)
	{
		wprintf(L"ERROR: Could not initialize ShellLink COM instance.\n");
		return;
	}

	// load in the shortcut and turn off link tracking
	CComPtr<IShellLinkDataList> oDataList = nullptr;
	DWORD iFlags = 0;
	if (FAILED(oFile->Load(tObjectEntry.Name.c_str(), STGM_READ)) || 
		FAILED(oLink->QueryInterface(IID_PPV_ARGS(&oDataList))) ||
		FAILED(oDataList->GetFlags(&iFlags)) ||
		FAILED(oDataList->SetFlags(iFlags | 
			SLDF_DISABLE_KNOWNFOLDER_RELATIVE_TRACKING |
			SLDF_DISABLE_LINK_PATH_TRACKING |
			SLDF_FORCE_NO_LINKINFO |
			SLDF_FORCE_NO_LINKTRACK |
			SLDF_NO_KF_ALIAS)))
	{
		wprintf(L"ERROR: Could not read ShellLink COM instance.\n");
		return;
	}

	// reload the shortcut to activate the link tracking change
	constexpr LARGE_INTEGER tSeekLocation = { { 0 , 0 } };
	CComPtr<IStream> oUpdatedLinkStream = nullptr;
	CComPtr<IPersistStream> oUpdatedLinkPersistStream = nullptr;
	if (FAILED(CreateStreamOnHGlobal(nullptr, TRUE, &oUpdatedLinkStream)) ||
		FAILED(oLink->QueryInterface(IID_PPV_ARGS(&oUpdatedLinkPersistStream))) ||
		FAILED(oUpdatedLinkPersistStream->Save(oUpdatedLinkStream, true)) ||
		FAILED(oUpdatedLinkStream->Seek(tSeekLocation, 0, nullptr)) ||
		FAILED(oUpdatedLinkPersistStream->Load(oUpdatedLinkStream)))
	{
		wprintf(L"ERROR: Could not reload ShellLink COM instance.\n");
		return;
	}

	// get link data
	std::wstring sTargetPath = L"<ERROR READING>";
	std::wstring sWorkingDirectory = L"<ERROR READING>";
	WCHAR sTargetPathRaw[MAX_PATH];
	WCHAR sWorkingDirRaw[MAX_PATH];
	if (SUCCEEDED(oLink->GetPath(sTargetPathRaw, MAX_PATH, nullptr, SLGP_RAWPATH))) sTargetPath = sTargetPathRaw;
	if (SUCCEEDED(oLink->GetWorkingDirectory(sWorkingDirRaw, MAX_PATH))) sWorkingDirectory = sWorkingDirRaw;

	// check if the target path matches out regex filter 
	if (std::regex_match(sTargetPath, tRegexTarget))
	{
		// write output to file
		std::wstring sToWrite = std::wstring(L"") + Q(tObjectEntry.Name) + L"," +
			Q(sCreationTime) + L"," + Q(sModifiedTime) + L"," + Q(sSize) + L"," +
			Q(sAttributes) + L"," + Q(sTargetPath) + L"," + Q(sWorkingDirectory) + L"\r\n";
		if (WriteToFile(sToWrite, hReportFile) == 0)
		{
			InputOutput::AddError(L"Unable to write security information to report file.");
		}
	}
}