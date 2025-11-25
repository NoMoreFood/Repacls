#include "OperationLocateHash.h"
#include "InputOutput.h"
#include "Helpers.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

#include <sal.h>

ClassFactory<OperationLocateHash> OperationLocateHash::RegisteredFactory(GetCommand());

#define Q(x) L"\"" + (x) + L"\""

OperationLocateHash::OperationLocateHash(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// exit if there are not enough arguments to parse
	const std::vector<std::wstring> sReportFile = ProcessAndCheckArgs(1, oArgList, L"\\0");
	const std::vector<std::wstring> sMatchAndArgs = ProcessAndCheckArgs(2, oArgList);

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
		const std::wstring sToWrite = std::wstring(L"") + Q(L"Path") + L"," + Q(L"Creation Time") + L"," +
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

	// determine hash algorithm based on hash string length
	const size_t iHashStringLength = sMatchAndArgs.at(1).size();
	const std::map<size_t, LPCWSTR> hashAlgorithms = {
		{ 32, BCRYPT_MD5_ALGORITHM },
		{ 40, BCRYPT_SHA1_ALGORITHM },
		{ 64, BCRYPT_SHA256_ALGORITHM },
		{ 96, BCRYPT_SHA384_ALGORITHM },
		{ 128, BCRYPT_SHA512_ALGORITHM }
	};
	const auto hashAlg = hashAlgorithms.find(iHashStringLength);
	if (hashAlg == hashAlgorithms.end())
	{
		wprintf(L"ERROR: Invalid hash '%s' specified for parameter '%s'.\n", sMatchAndArgs.at(1).c_str(), GetCommand().c_str());
		std::exit(-1);
	}

	// initialize hashing environment
	DWORD ResultLength = 0;
	if (BCryptOpenAlgorithmProvider(&hAlgHandle, hashAlg->second, nullptr, BCRYPT_HASH_REUSABLE_FLAG) != 0 ||
		BCryptGetProperty(hAlgHandle, BCRYPT_HASH_LENGTH, (PBYTE)&iHashLength, sizeof(DWORD), &ResultLength, 0) != 0 ||
		BCryptCreateHash(hAlgHandle, &hHashHandle, nullptr, 0, nullptr, 0, BCRYPT_HASH_REUSABLE_FLAG) != 0)
	{
		wprintf(L"ERROR: Could not setup hashing environment.\n");
		std::exit(-1);
	}

	// determine hash to match
	aHashToMatch.resize(iHashLength);
	DWORD iBytesRead = iHashLength;
	if (CryptStringToBinary(sMatchAndArgs.at(1).c_str(), (DWORD) sMatchAndArgs.at(1).size(),
		CRYPT_STRING_HEX_ANY, aHashToMatch.data(), &iBytesRead, nullptr, nullptr) == FALSE || iBytesRead != (DWORD)iHashLength)
	{
		wprintf(L"ERROR: Invalid hash '%s' specified for parameter '%s'.\n", sMatchAndArgs.at(1).c_str(), GetCommand().c_str());
		std::exit(-1);
	}

	// record specific size if specified
	if (sMatchAndArgs.size() > 2)
	{
		iSizeToMatch = _wtoll(sMatchAndArgs.at(2).c_str());
	}

	aHash.resize(iHashLength);
	aFileBuffer.resize(2ull * 1024ull * 1024ull);
}

OperationLocateHash::~OperationLocateHash()
{
	if (hHashHandle != nullptr)
	{
		BCryptDestroyHash(hHashHandle);
	}
	if (hAlgHandle != nullptr)
	{
		BCryptCloseAlgorithmProvider(hAlgHandle, 0);
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

	HANDLE hFile = CreateFile(tObjectEntry.Name.c_str(), GENERIC_READ, FILE_SHARE_READ,
	           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		InputOutput::AddError(L"Unable to open file for reading.");
		return;
	}

	DWORD iReadResult = 0;
	DWORD iHashResult = 0;
	DWORD iReadBytes = 0;
	while ((iReadResult = ReadFile(hFile, aFileBuffer.data(), (DWORD)aFileBuffer.size(), &iReadBytes, nullptr)) != 0 && iReadBytes > 0)
	{
		iHashResult = BCryptHashData(hHashHandle, aFileBuffer.data(), iReadBytes, 0);
		if (iHashResult != 0) break;
	}

	// done reading data
	CloseHandle(hFile);
	
	// complete hash data
	if (BCryptFinishHash(hHashHandle, aHash.data(), iHashLength, 0) != 0)
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
	if (!aHashToMatch.empty() && memcmp(aHashToMatch.data(), aHash.data(), iHashLength) != 0)
	{
		return;
	}

	// convert to hex string
	DWORD iHashStringLength = iHashLength * 2 + 1;
	std::vector<WCHAR> sHash(iHashStringLength);
	CryptBinaryToStringW(aHash.data(), iHashLength, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, 
		sHash.data(), &iHashStringLength);

	// get common file attributes
	const std::wstring sSize = FileSizeToString(tObjectEntry.FileSize);
	const std::wstring sAttributes = FileAttributesToString(tObjectEntry.Attributes);
	const std::wstring sModifiedTime = FileTimeToString(tObjectEntry.ModifiedTime);
	const std::wstring sCreationTime = FileTimeToString(tObjectEntry.CreationTime);

	// write output to file
	const std::wstring sToWrite = std::wstring(L"") + Q(tObjectEntry.Name) + L"," +
		Q(sCreationTime) + L"," + Q(sModifiedTime) + L"," + 
		Q(sSize) + L"," + Q(sAttributes) + L"," + Q(sHash.data()) + L"," + L"\r\n";
	if (WriteToFile(sToWrite, hReportFile) == 0)
	{
		InputOutput::AddError(L"Unable to write information to report file.");
	}
}