#pragma once

#include <windows.h>
#include <accctrl.h>
#include <aclapi.h>
#include <string>
#include <vector>
#include <queue>
#include <map>

#include "Functions.h"

// generic header for allow, deny, and audit aces
typedef struct _ACCESS_ACE {
	ACE_HEADER Header;
	ACCESS_MASK Mask;
	SID Sid;
} ACCESS_ACE;
typedef ACCESS_ACE *PACCESS_ACE;

// macros to iterate through access control entries
#define FirstAce(Acl) ((ACCESS_ACE *)((PUCHAR)(Acl) + sizeof(ACL)))
#define NextAce(Ace) ((ACCESS_ACE *)((PUCHAR)(Ace) + ((PACE_HEADER)(Ace))->AceSize))

// define our own version of sid length since its faster
#define GetLengthSid(x) (sizeof(SID) + (((SID *) (x))->SubAuthorityCount - 1) * sizeof(((SID *) (x))->SubAuthority))
#define SidMatch(x,y) (memcmp(x,y,min(GetLengthSid(x),GetLengthSid(y))) == 0)
#define SidNotMatch(x,y) (!SidMatch(x,y))

// macros for checking file attributes
#define CheckBitSet(x,y) (((x) & (y)) != 0)
#define IsDirectory(x) CheckBitSet(x,FILE_ATTRIBUTE_DIRECTORY)
#define IsHiddenSystem(x) (CheckBitSet(x,FILE_ATTRIBUTE_HIDDEN) && CheckBitSet(x,FILE_ATTRIBUTE_SYSTEM))
#define IsReparsePoint(x) (CheckBitSet(x,FILE_ATTRIBUTE_REPARSE_POINT))

// a few simple defines for convenience
#define IsInherited(x) CheckBitSet((x)->Header.AceFlags,INHERITED_ACE)
#define HasContainerInherit(x) CheckBitSet((x)->Header.AceFlags,CONTAINER_INHERIT_ACE)
#define HasObjectInherit(x) CheckBitSet((x)->Header.AceFlags,OBJECT_INHERIT_ACE)
#define HasInheritOnly(x) CheckBitSet((x)->Header.AceFlags,INHERIT_ONLY_ACE)
#define HasNoPropogate(x) CheckBitSet((x)->Header.AceFlags,NO_PROPAGATE_INHERIT_ACE)
#define GetNonOiCiIoBits(x) ((~(CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE)) & (x)->Header.AceFlags)

// string helper operations
#define ConvertToUpper(_x) std::transform(_x.begin(), _x.end(), _x.begin(),	\
	[](const WCHAR c) noexcept { return static_cast<WCHAR>(::toupper(c)); });

typedef struct ObjectEntry
{
	std::wstring Name;
	DWORD Attributes;
	FILETIME CreationTime;
	FILETIME ModifiedTime;
	LARGE_INTEGER FileSize;
	bool IsRoot;
}
ObjectEntry;

typedef enum SidActionResult : char
{
	Nothing = 0,
	Replace = 1 << 0,
	Remove = 1 << 1,
	Add = 1 << 2
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
	virtual bool ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement);
	virtual bool ProcessSidAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID & tCurrentSid, bool & bSidReplacement);
	virtual SidActionResult DetermineSid(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PSID const tCurrentSid, PSID & tResultantSid) { return SidActionResult::Nothing; }
	virtual void ProcessObjectAction(ObjectEntry & tObjectEntry) { return; }

	Operation(std::queue<std::wstring> & oArgList);
	virtual ~Operation() = default;
};

#include "OperationFactory.h"