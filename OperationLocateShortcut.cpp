#include "OperationLocateShortcut.h"
#include "InputOutput.h"
#include "Helpers.h"

#include <atlbase.h>
#include <ShlObj.h>

ClassFactory<OperationLocateShortcut> OperationLocateShortcut::RegisteredFactory(GetCommand());

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
		Print(L"ERROR: Could not create file '{}' specified for parameter '{}'.", sReportFile.at(0), GetCommand());
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
			Print(L"ERROR: Could not write out file type marker '{}'.", GetCommand());
			std::exit(-1);
		}

		// write out the header
		if (WriteToFile(OutToCsv(L"Path", L"Creation Time", L"Modified Time",
			L"Size", L"Attributes", L"Target Path", L"Working Directory"), hReportFile) == 0)
		{
			Print(L"ERROR: Could not write header to report file for parameter '{}'.", GetCommand());
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
		Print(L"ERROR: Invalid regular expression '{}' specified for parameter '{}'.", sMatchAndArgs.at(0), GetCommand());
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
		Print(L"ERROR: Could not initialize ShellLink COM instance.");
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
		Print(L"ERROR: Could not read ShellLink COM instance.");
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
		Print(L"ERROR: Could not reload ShellLink COM instance.");
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
		if (WriteToFile(OutToCsv(tObjectEntry.Name, sCreationTime, sModifiedTime,
			sSize, sAttributes, sTargetPath, sWorkingDirectory), hReportFile) == 0)
		{
			InputOutput::AddError(L"Unable to write security information to report file.");
		}
	}
}