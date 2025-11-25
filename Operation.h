#pragma once

// mute compatibility concerns
#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS

#include <Windows.h>
#include <AccCtrl.h>
#include <AclAPI.h>
#include <string>
#include <vector>
#include <queue>
#include <algorithm>
#include <cwchar>
#include <map>

typedef struct ObjectEntry
{
	std::wstring Name;
	SE_OBJECT_TYPE ObjectType;
	DWORD Attributes;
	FILETIME ModifiedTime;
	FILETIME CreationTime;
	LARGE_INTEGER FileSize;
	unsigned int Depth;

	std::wstring NameExtended;
	HANDLE hObject;
}
ObjectEntry;

// generic header for allow, deny, and audit object aces
using ACE_ACCESS_HEADER = struct {
	BYTE AceType;
	BYTE AceFlags;
	WORD AceSize;
	ACCESS_MASK Mask;
} ;
using PACE_ACCESS_HEADER = ACE_ACCESS_HEADER*;;

// macros to iterate through access control entries
#define FirstAce(Acl) reinterpret_cast<PACE_ACCESS_HEADER>(((PUCHAR)(Acl) + sizeof(ACL)))
#define NextAce(Ace) reinterpret_cast<PACE_ACCESS_HEADER>((PUCHAR)(Ace) + ((PACE_ACCESS_HEADER)(Ace))->AceSize)

// define our own version of sid length since its faster
constexpr DWORD SidGetLength(PSID x) { return sizeof(SID) + (((SID*)(x))->SubAuthorityCount - 1) * sizeof(((SID*)(x))->SubAuthority); };
constexpr bool SidMatch(PSID x, PSID y) { return __builtin_memcmp(x, y, min(SidGetLength(x), SidGetLength(y))) == 0; };
constexpr bool SidNotMatch(PSID x, PSID y) { return !SidMatch(x, y); };

// macros for checking file attributes
constexpr bool CheckBitSet(DWORD x, DWORD y) { return (((x) & (y)) != 0); }
constexpr bool IsDirectory(DWORD x) { return CheckBitSet(x, FILE_ATTRIBUTE_DIRECTORY); };
constexpr bool IsHiddenSystem(DWORD x) { return CheckBitSet(x, FILE_ATTRIBUTE_HIDDEN) && CheckBitSet(x, FILE_ATTRIBUTE_SYSTEM); };
constexpr bool IsReparsePoint(DWORD x) { return CheckBitSet(x, FILE_ATTRIBUTE_REPARSE_POINT); };

// a few simple defines for convenience
constexpr bool IsInherited(PACE_ACCESS_HEADER x) { return CheckBitSet((x)->AceFlags, INHERITED_ACE); };
constexpr bool HasContainerInherit(PACE_ACCESS_HEADER x) { return CheckBitSet((x)->AceFlags, CONTAINER_INHERIT_ACE); };
constexpr bool HasObjectInherit(PACE_ACCESS_HEADER x) { return CheckBitSet((x)->AceFlags, OBJECT_INHERIT_ACE); };
constexpr bool HasInheritOnly(PACE_ACCESS_HEADER x) { return CheckBitSet((x)->AceFlags, INHERIT_ONLY_ACE); };
constexpr bool HasNoPropogate(PACE_ACCESS_HEADER x) { return CheckBitSet((x)->AceFlags, NO_PROPAGATE_INHERIT_ACE); };
constexpr DWORD GetNonOiCiIoBits(PACE_ACCESS_HEADER x) { return ((~(CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE)) & (x)->AceFlags); };

// string helper operations
constexpr void ConvertToUpper(std::wstring & str)
{
	std::ranges::transform(str, str.begin(), ::towupper);
}

typedef enum SidActionResult : char
{
	Nothing = 0,
	Replace = 1 << 0,
	Remove = 1 << 1
}
SidActionResult;

class Operation
{
protected:

	static std::vector<std::wstring> SplitArgs(std::wstring sInput, const std::wstring & sDelimiter);
	static std::vector<std::wstring> ProcessAndCheckArgs(int iArgsRequired, std::queue<std::wstring> & oArgList, const std::wstring & sDelimiter = L":");
	void ProcessGranularTargetting(std::wstring sScope);

public:

	bool AppliesToDacl = false;
	bool AppliesToSacl = false;
	bool AppliesToOwner = false;
	bool AppliesToGroup = false;
	bool AppliesToSd = false;
	bool AppliesToObject = false;

	bool AppliesToRootOnly = false;
	bool AppliesToChildrenOnly = false;
	bool ExclusiveOperation = false;

	DWORD SpecialCommitFlags = false;
	PSID DefaultSidWhenEmpty = nullptr;

	virtual bool ProcessSdAction(std::wstring & sFileName, ObjectEntry & tObjectEntry, PSECURITY_DESCRIPTOR & tDescriptor, bool & bDescReplacement) { return false; }
	virtual bool ProcessAclAction(const WCHAR * sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement);
	virtual bool ProcessSidAction(const WCHAR * sSdPart, ObjectEntry & tObjectEntry, PSID & tCurrentSid, bool & bSidReplacement);
	virtual SidActionResult DetermineSid(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid) { return SidActionResult::Nothing; }
	virtual void ProcessObjectAction(ObjectEntry & tObjectEntry) { return; }
	static PSID GetSidFromAce(PACE_ACCESS_HEADER tAce) noexcept;

	Operation(std::queue<std::wstring> & oArgList);
	virtual ~Operation() = default;
};

#include "OperationFactory.h"