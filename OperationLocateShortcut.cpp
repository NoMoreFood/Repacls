#include "OperationLocateShortcut.h"
#include "InputOutput.h"
#include "Functions.h"

#pragma comment(lib, "shlwapi.lib") 

#include <shlobj.h> 
#include <shlwapi.h> 

ClassFactory<OperationLocateShortcut> OperationLocateShortcut::RegisteredFactory(GetCommand());

#define Q(x) L"\"" + (x) + L"\""

OperationLocateShortcut::OperationLocateShortcut(std::queue<std::wstring> & oArgList, std::wstring sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sReportFile = ProcessAndCheckArgs(1, oArgList, L"\\0");
	std::vector<std::wstring> sMatchAndArgs = ProcessAndCheckArgs(1, oArgList, L"\\0");

	// fetch params
	HANDLE hFile = CreateFile(sReportFile.at(0).c_str(), GENERIC_WRITE,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	// see if names could be resolved
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// complain
		wprintf(L"ERROR: Could not create file '%s' specified for parameter '%s'.\n", sReportFile.at(0).c_str(), GetCommand().c_str());
		exit(-1);
	}

	// register the file handle
	hReportFile = RegisterFileHandle(hFile, GetCommand());

	// if this is the first handle using this file, write out a header
	if (hFile == hReportFile)
	{
		// write out the file type marker
		const BYTE hHeader[] = { 0xEF,0xBB,0xBF };
		DWORD iBytes = 0;
		if (WriteFile(hFile, &hHeader, _countof(hHeader), &iBytes, nullptr) == 0)
		{
			wprintf(L"ERROR: Could not write out file type marker '%s'.\n", GetCommand().c_str());
			exit(-1);
		}

		// write out the header
		std::wstring sToWrite = std::wstring(L"") + Q(L"Path") + L"," + Q(L"Creation Time") + L"," +
			Q(L"Modified Time") + L"," + Q(L"Size") + L"," + Q(L"Attributes") + L"," + 
			Q(L"Target Path") + L"," + Q(L"Working Directory") + L"\r\n";
		if (WriteToFile(sToWrite, hReportFile) == 0)
		{
			wprintf(L"ERROR: Could not write header to report file for parameter '%s'.\n", GetCommand().c_str());
			exit(-1);
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
	catch (const std::regex_error &)
	{
		wprintf(L"ERROR: Invalid regular expression '%s' specified for parameter '%s'.\n", sMatchAndArgs[0].c_str(), GetCommand().c_str());
		exit(-1);
	}
}

void OperationLocateShortcut::ProcessObjectAction(ObjectEntry & tObjectEntry)
{
	// skip any file names that do not match the regex
	const WCHAR * sFileName = tObjectEntry.Name.c_str();
	if (wcsrchr(sFileName, '\\') != nullptr) sFileName = wcsrchr(sFileName, '\\') + 1;
	if (!std::regex_match(sFileName, tRegexLink)) return;

	// initialize com for this thread
	__declspec(thread) static bool bComInitialized = false;
	if (!bComInitialized)
	{
		bComInitialized = true;
		const HRESULT hComInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
		if (hComInit != S_OK && hComInit != S_FALSE)
		{
			wprintf(L"ERROR: Could not initialize COM.\n");
			exit(-1);
		}
	}

	// fetch file attribute data
	WIN32_FILE_ATTRIBUTE_DATA tData;
	if (GetFileAttributesExW(tObjectEntry.Name.c_str(), GetFileExInfoStandard, &tData) == 0)
	{
		InputOutput::AddError(L"ERROR: Unable to read file attributes.");
	}

	// convert the file size to a string
	WCHAR sSize[32] = { 0 };
	ULARGE_INTEGER iFileSize;
	iFileSize.LowPart = tData.nFileSizeLow;
	iFileSize.HighPart = tData.nFileSizeHigh;
	setlocale(LC_NUMERIC, "");
	wsprintf(sSize, L"%I64u", iFileSize.QuadPart);

	// decode attributes
	std::wstring sAttributes = L"";
	if (tData.dwFileAttributes & FILE_ATTRIBUTE_READONLY) sAttributes += L"R";
	if (tData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) sAttributes += L"H";
	if (tData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) sAttributes += L"S";
	if (tData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) sAttributes += L"D";
	if (tData.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) sAttributes += L"A";
	if (tData.dwFileAttributes & FILE_ATTRIBUTE_TEMPORARY) sAttributes += L"T";
	if (tData.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED) sAttributes += L"C";
	if (tData.dwFileAttributes & FILE_ATTRIBUTE_OFFLINE) sAttributes += L"O";
	if (tData.dwFileAttributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) sAttributes += L"N";
	if (tData.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED) sAttributes += L"E";

	// create shortcut interfaces
	IShellLinkW * oLink = nullptr;
	IPersistFile * oFile = nullptr;
	if (CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (VOID **)&oLink) != S_OK ||
		oLink->QueryInterface(IID_IPersistFile, (VOID **)&oFile) != S_OK)
	{
		wprintf(L"ERROR: Could not initialize ShellLink COM instance.\n");
		return;
	}

	// load in the shortcut
	std::wstring sTargetPath = L"<ERROR READING>";
	std::wstring sWorkingDirectory = L"<ERROR READING>";
	if (oFile->Load(tObjectEntry.Name.c_str(), STGM_READ) == S_OK)
	{
		WCHAR sTargetPathRaw[MAX_PATH];
		WCHAR sWorkingDirRaw[MAX_PATH];
		if (oLink->GetPath(sTargetPathRaw, MAX_PATH, nullptr, SLGP_RAWPATH) == S_OK) sTargetPath = sTargetPathRaw;
		if (oLink->GetWorkingDirectory(sWorkingDirRaw, MAX_PATH) == S_OK) sWorkingDirectory = sWorkingDirRaw;
	}

	// check if the target path matches out regex filter 
	if (std::regex_match(sTargetPath, tRegexTarget))
	{
		// write output to file
		std::wstring sToWrite = std::wstring(L"") + Q(tObjectEntry.Name) + L"," +
			Q(FileTimeToString(&tData.ftCreationTime)) + L"," + Q(FileTimeToString(&tData.ftLastWriteTime)) +
			L"," + Q(sSize) + L"," + Q(sAttributes) + L"," + Q(sTargetPath) + L"," + Q(sWorkingDirectory) + L"\r\n";
		if (WriteToFile(sToWrite, hReportFile) == 0)
		{
			InputOutput::AddError(L"ERROR: Unable to write security information to report file.");
		}
	}

	// cleanup
	oLink->Release();
	oFile->Release();
}