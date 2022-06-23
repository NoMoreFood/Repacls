#include "OperationLocateHash.h"
#include "InputOutput.h"
#include "Helpers.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

#include <bcrypt.h>
#include <sal.h>

ClassFactory<OperationLocateHash> OperationLocateHash::RegisteredFactory(GetCommand());

#define Q(x) L"\"" + (x) + L"\""

OperationLocateHash::OperationLocateHash(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	std::vector<std::wstring> sReportFile = ProcessAndCheckArgs(1, oArgList, L"\\0");
	std::vector<std::wstring> sMatchAndArgs = ProcessAndCheckArgs(2, oArgList);

	// fetch params
	HANDLE hFile = CreateFile(sReportFile.at(0).c_str(), GENERIC_WRITE,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

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
		const BYTE hHeader[] = { 0xEF,0xBB,0xBF };
		DWORD iBytes = 0;
		if (WriteFile(hFile, &hHeader, _countof(hHeader), &iBytes, nullptr) == 0)
		{
			wprintf(L"ERROR: Could not write out file type marker '%s'.\n", GetCommand().c_str());
			std::exit(-1);
		}

		// write out the header
		std::wstring sToWrite = std::wstring(L"") + Q(L"Path") + L"," + Q(L"Creation Time") + L"," +
			Q(L"Modified Time") + L"," + Q(L"Size") + L"," + Q(L"Attributes") + L"," + 
			Q(L"Hash") + L"\r\n";
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
		tRegex = std::wregex(sMatchAndArgs.at(0), std::wregex::icase | std::wregex::optimize);
	}
	catch (const std::regex_error &)
	{
		wprintf(L"ERROR: Invalid regular expression '%s' specified for parameter '%s'.\n", sMatchAndArgs.at(0).c_str(), GetCommand().c_str());
		std::exit(-1);
	}

	// determine hash to match
	aHashToMatch = new BYTE[HASH_IN_BYTES];
	DWORD iBytesRead = HASH_IN_BYTES;
	if (CryptStringToBinary(sMatchAndArgs.at(1).c_str(), (DWORD) sMatchAndArgs.at(1).size(),
		CRYPT_STRING_HEX_ANY, aHashToMatch, &iBytesRead, NULL, NULL) == FALSE || iBytesRead != HASH_IN_BYTES)
	{
		wprintf(L"ERROR: Invalid hash '%s' specified for parameter '%s'.\n", sMatchAndArgs.at(1).c_str(), GetCommand().c_str());
		std::exit(-1);
	}

	// record specific size if specified
	if (sMatchAndArgs.size() > 2)
	{
		iSizeToMatch = _wtoll(sMatchAndArgs.at(2).c_str());
	}
}

void OperationLocateHash::ProcessObjectAction(ObjectEntry & tObjectEntry)
{
	// skip directories
	if (IsDirectory(tObjectEntry.Attributes)) return;

	// skip any files that do not match the size (if specified)
	if (iSizeToMatch != -1 && tObjectEntry.FileSize.QuadPart != iSizeToMatch) return;

	// skip any file names that do not match the regex
	const WCHAR* sFileName = tObjectEntry.Name.c_str();
	if (wcsrchr(sFileName, '\\') != nullptr) sFileName = wcsrchr(sFileName, '\\') + 1;
	if (!std::regex_match(sFileName, tRegex)) return;

	// initialize hash for this thread
	static constexpr size_t iFileBuffer = 2 * 1024 * 1024;
	thread_local static BCRYPT_HASH_HANDLE HashHandle = NULL;
	thread_local static PBYTE Hash = nullptr;
	thread_local static PBYTE FileBuffer = nullptr; 
	thread_local static DWORD HashLength = 0;
	if (Hash == nullptr)
	{
		BCRYPT_ALG_HANDLE AlgHandle = NULL;
		DWORD ResultLength = 0;
		if (BCryptOpenAlgorithmProvider(&AlgHandle, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_HASH_REUSABLE_FLAG) != 0 ||
			BCryptGetProperty(AlgHandle, BCRYPT_HASH_LENGTH, (PBYTE) &HashLength, sizeof(HashLength), &ResultLength, 0) != 0 ||
			BCryptCreateHash(AlgHandle, &HashHandle, NULL, 0, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG) != 0 ||
			(Hash = (PBYTE) malloc(HashLength)) == NULL ||
			(FileBuffer = (PBYTE) malloc(iFileBuffer)) == NULL)
		{
			wprintf(L"ERROR: Could not setup hashing environment.\n");
			std::exit(-1);
		}
	}

	HANDLE hFile = CreateFile(tObjectEntry.Name.c_str(), GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		InputOutput::AddError(L"Unable to open file for reading.");
		return;
	}

	DWORD iReadResult = 0;
	DWORD iHashResult = 0;
	DWORD iReadBytes = 0;
	while ((iReadResult = ReadFile(hFile, FileBuffer, iFileBuffer, &iReadBytes, NULL)) != 0 && iReadBytes > 0)
	{
		iHashResult = BCryptHashData(HashHandle, FileBuffer, iReadBytes, 0);
		if (iHashResult != 0) break;
	}

	// done reading data
	CloseHandle(hFile);
	
	// complete hash data
	if (BCryptFinishHash(HashHandle, Hash, HashLength, 0) != 0)
	{
		InputOutput::AddError(L"Could not finalize file data for hashing.");
		std::exit(-1);
	}

	// file read failed
	if (iHashResult != 0 || iReadResult == 0)
	{
		InputOutput::AddError(L"Could not hash/read file data.");
		return;
	}

	// skip if a hash was specified and there is no match
	if (aHashToMatch != nullptr && memcmp(aHashToMatch, Hash, HASH_IN_BYTES) != 0)
	{
		return;
	}

	// convert to base64
	WCHAR sHash[HASH_IN_HEXCHARS + 1] = L"";
	DWORD iHashStringLength = HASH_IN_HEXCHARS + 1;
	CryptBinaryToStringW(Hash, HashLength, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, 
		sHash, &iHashStringLength);

	// get common file attributes
	const std::wstring sSize = FileSizeToString(tObjectEntry.FileSize);
	const std::wstring sAttributes = FileAttributesToString(tObjectEntry.Attributes);
	const std::wstring sModifiedTime = FileTimeToString(tObjectEntry.ModifiedTime);
	const std::wstring sCreationTime = FileTimeToString(tObjectEntry.CreationTime);

	// write output to file
	std::wstring sToWrite = std::wstring(L"") + Q(tObjectEntry.Name) + L"," +
		Q(sCreationTime) + L"," + Q(sModifiedTime) + L"," + 
		Q(sSize) + L"," + Q(sAttributes) + L"," + Q(sHash) + L"," + L"\r\n";
	if (WriteToFile(sToWrite, hReportFile) == 0)
	{
		InputOutput::AddError(L"Unable to write information to report file.");
	}
}