#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#include "Operation.h"
#include "Helpers.h"
#include "Processor.h"
#include "InputOutput.h"
#include "OperationCheckCanonical.h"

#include <LM.h>
#include <codecvt>
#include <fstream>
#include <memory>
#include <stdexcept>

std::wstring InitialDescriptor;
DWORD CommittedInformation = 0;
std::wstring CommittedDacl;
std::vector<std::pair<std::wstring, std::wstring>> TestShares;

void Require(bool condition, const char* message)
{
	if (!condition) throw std::runtime_error(message);
}

std::unique_ptr<Operation> MakeOperation(std::initializer_list<std::wstring> arguments)
{
	std::queue<std::wstring> queue;
	for (const auto& argument : arguments) queue.push(argument);
	return std::unique_ptr<Operation>(FactoryPlant::CreateInstance(queue));
}

std::wstring Describe(PSECURITY_DESCRIPTOR descriptor, SECURITY_INFORMATION information)
{
	SmartPointer<WCHAR*> text(LocalFree);
	Require(ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1,
		information, &text, nullptr) != 0, "Convert descriptor to SDDL");
	return std::wstring(text);
}

std::wstring DescribeAcl(PACL acl, bool audit = false)
{
	SECURITY_DESCRIPTOR descriptor{};
	InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);
	if (audit) SetSecurityDescriptorSacl(&descriptor, TRUE, acl, FALSE);
	else SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE);
	return Describe(&descriptor, audit ? SACL_SECURITY_INFORMATION : DACL_SECURITY_INFORMATION);
}

bool CanRead(PACL acl)
{
	// evaluate actual Windows access checks for overlapping token groups
	SECURITY_DESCRIPTOR descriptor{};
	InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE);
	SetSecurityDescriptorOwner(&descriptor, GetSidFromName(L"S-1-5-18"), FALSE);
	SetSecurityDescriptorGroup(&descriptor, GetSidFromName(L"S-1-5-18"), FALSE);
	SmartPointer<HANDLE> token(CloseHandle), impersonation(CloseHandle);
	Require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token) != 0 &&
		DuplicateToken(token, SecurityImpersonation, &impersonation) != 0, "Create access-check token");
	GENERIC_MAPPING mapping{ FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS };
	BYTE privileges[2048]{};
	DWORD size = sizeof(privileges), granted = 0;
	BOOL allowed = FALSE;
	Require(AccessCheck(&descriptor, impersonation, FILE_READ_DATA, &mapping,
		reinterpret_cast<PPRIVILEGE_SET>(privileges), &size, &granted, &allowed) != 0, "Run access check");
	return allowed != FALSE;
}

DWORD ReadTestSecurity(LPCWSTR name, SE_OBJECT_TYPE type, SECURITY_INFORMATION information,
	PSID* owner, PSID* group, PACL* dacl, PACL* sacl, PSECURITY_DESCRIPTOR* descriptor)
{
	// provide real Windows descriptors without requiring access to privileged object storage
	if (InitialDescriptor.empty())
		return GetNamedSecurityInfoW(name, type, information, owner, group, dacl, sacl, descriptor);
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(InitialDescriptor.c_str(),
		SDDL_REVISION_1, descriptor, nullptr)) return GetLastError();
	BOOL present = FALSE, defaulted = FALSE;
	if (owner) GetSecurityDescriptorOwner(*descriptor, owner, &defaulted);
	if (group) GetSecurityDescriptorGroup(*descriptor, group, &defaulted);
	if (dacl) GetSecurityDescriptorDacl(*descriptor, &present, dacl, &defaulted);
	if (sacl) GetSecurityDescriptorSacl(*descriptor, &present, sacl, &defaulted);
	return ERROR_SUCCESS;
}

DWORD WriteTestSecurity(LPWSTR name, SE_OBJECT_TYPE type, SECURITY_INFORMATION information,
	PSID owner, PSID group, PACL dacl, PACL sacl)
{
	// capture the exact descriptor parts and protection flags submitted to Windows
	if (InitialDescriptor.empty())
		return SetNamedSecurityInfoW(name, type, information, owner, group, dacl, sacl);
	CommittedInformation = information;
	CommittedDacl = DescribeAcl(dacl);
	return ERROR_SUCCESS;
}

#undef GetNamedSecurityInfo
#undef SetNamedSecurityInfo
#define GetNamedSecurityInfo ReadTestSecurity
#define SetNamedSecurityInfo WriteTestSecurity
#include "Processor.cpp"
#undef GetNamedSecurityInfo
#undef SetNamedSecurityInfo
#define GetNamedSecurityInfo GetNamedSecurityInfoW
#define SetNamedSecurityInfo SetNamedSecurityInfoW

NET_API_STATUS EnumerateTestShares(LPWSTR, DWORD, LPBYTE* buffer, DWORD,
	LPDWORD read, LPDWORD total, LPDWORD resume)
{
	// exercise discovery with duplicate aliases, descendants, and unrelated paths
	const DWORD count = static_cast<DWORD>(TestShares.size());
	const auto status = NetApiBufferAllocate(count * sizeof(SHARE_INFO_2), reinterpret_cast<LPVOID*>(buffer));
	if (status != NERR_Success) return status;
	auto entries = reinterpret_cast<SHARE_INFO_2*>(*buffer);
	ZeroMemory(entries, count * sizeof(SHARE_INFO_2));
	for (DWORD index = 0; index < count; ++index)
	{
		entries[index].shi2_netname = TestShares[index].first.data();
		entries[index].shi2_path = TestShares[index].second.data();
		entries[index].shi2_type = STYPE_DISKTREE;
	}
	*read = *total = count;
	*resume = 0;
	return NERR_Success;
}

#define NetShareEnum EnumerateTestShares
#include "OperationSharePaths.cpp"
#undef NetShareEnum

class CaptureDescriptor final : public Operation
{
public:
	std::vector<std::wstring> Snapshots;

	CaptureDescriptor(std::queue<std::wstring>& arguments, bool checkAbsentAcls = false) : Operation(arguments)
	{
		AppliesToSd = true;
		AppliesToDacl = AppliesToSacl = checkAbsentAcls;
	}

	bool ProcessAclAction(const WCHAR*, ObjectEntry&, PACL& acl, bool&) override
	{
		Require(acl == nullptr, "Clear stale component pointers when restoring absent ACLs");
		return false;
	}

	bool ProcessSdAction(std::wstring&, ObjectEntry&, PSECURITY_DESCRIPTOR& descriptor, bool&) override
	{
		Snapshots.push_back(Describe(descriptor, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
			DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION));
		return false;
	}
};

void CheckCanonicalization()
{
	// retain inherited allow/deny order even when explicit entries need sorting
	auto operation = MakeOperation({ L"/CanonicalizeAcls" });
	for (const auto* sddl : { L"D:(A;ID;0x1;;;WD)(D;ID;0x1;;;WD)",
		L"D:(A;;0x2;;;WD)(D;;0x2;;;WD)(A;ID;0x1;;;WD)(D;ID;0x1;;;WD)" })
	{
		SmartPointer<PSECURITY_DESCRIPTOR> descriptor(LocalFree);
		Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1,
			&descriptor, nullptr) != 0, "Parse canonicalization fixture");
		PACL acl = nullptr;
		BOOL present, defaulted;
		GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted);
		Require(CanRead(acl), "Inherited fixture initially allows read");
		bool cleanup = false;
		ObjectEntry entry{};
		const bool explicitEntries = acl->AceCount == 4;
		Require(operation->ProcessAclAction(L"DACL", entry, acl, cleanup) == explicitEntries,
			"Canonicalization only reorders explicit entries");
		Require(CanRead(acl) && OperationCheckCanonical::IsAclCanonical(acl), "Preserve inherited effective access");
		Require(DescribeAcl(acl).ends_with(L"(A;ID;CC;;;WD)(D;ID;CC;;;WD)"), "Preserve inherited ACE sequence");
		Require(!operation->ProcessAclAction(L"DACL", entry, acl, cleanup), "Canonicalization is idempotent");
		if (cleanup) LocalFree(acl);
	}
}

void CheckAuditRedundancy()
{
	// check both missing audit outcomes and genuine inherited coverage
	auto operation = MakeOperation({ L"/RemoveRedundant" });
	for (const auto& [sddl, removable] : std::vector<std::pair<std::wstring, bool>>{
		{ L"S:(AU;SA;0x1;;;WD)(AU;FAID;0x1;;;WD)", false },
		{ L"S:(AU;FA;0x1;;;WD)(AU;SAID;0x1;;;WD)", false },
		{ L"S:(AU;SAFA;0x1;;;WD)(AU;SAID;0x1;;;WD)", false },
		{ L"S:(AU;SA;0x1;;;WD)(AU;SAFAID;0x1;;;WD)", true },
		{ L"S:(AU;SAFA;0x1;;;WD)(AU;SAFAID;0x1;;;WD)", true } })
	{
		SmartPointer<PSECURITY_DESCRIPTOR> descriptor(LocalFree);
		Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
			&descriptor, nullptr) != 0, "Parse audit fixture");
		PACL acl = nullptr;
		BOOL present, defaulted;
		GetSecurityDescriptorSacl(descriptor, &present, &acl, &defaulted);
		const auto before = DescribeAcl(acl, true);
		bool cleanup = false;
		ObjectEntry entry{};
		Require(operation->ProcessAclAction(L"SACL", entry, acl, cleanup) == removable, "Respect audit outcome coverage");
		Require(acl->AceCount == (removable ? 1 : 2), "Retain uncovered audit entries");
		if (!removable) Require(DescribeAcl(acl, true) == before, "Leave necessary auditing unchanged");
		if (cleanup) LocalFree(acl);
	}
}

void CheckIdentityMappings(const std::wstring& directory)
{
	// identity mappings must not suppress changes before or after them
	const auto path = directory + L"\\identity.map";
	std::ofstream map(path);
	map << "S-1-1-0:S-1-1-0\nS-1-5-11:S-1-5-32-545\n";
	map.close();
	auto operation = MakeOperation({ L"/ReplaceMap", path + L"|DACL" });
	for (const auto* sddl : { L"D:(A;;0x1;;;WD)(A;;0x2;;;AU)", L"D:(A;;0x2;;;AU)(A;;0x1;;;WD)" })
	{
		SmartPointer<PSECURITY_DESCRIPTOR> descriptor(LocalFree);
		Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1,
			&descriptor, nullptr) != 0, "Parse identity-map fixture");
		PACL acl = nullptr;
		BOOL present, defaulted;
		GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted);
		bool cleanup = false;
		ObjectEntry entry{};
		Require(operation->ProcessAclAction(L"DACL", entry, acl, cleanup), "Keep mapping change status");
		const auto result = DescribeAcl(acl);
		Require(result.find(L";;;BU)") != std::wstring::npos && result.find(L";;;AU)") == std::wstring::npos,
			"Apply mappings on either side of an identity mapping");
		Require(!operation->ProcessAclAction(L"DACL", entry, acl, cleanup), "Completed mapping is idempotent");
		if (cleanup) LocalFree(acl);
	}
}

void CheckCallbackObjectAces()
{
	// replace differently sized SIDs while retaining optional GUIDs and callback data
	GUID objectType{ 0x12345678, 0x1234, 0x1234, { 1, 2, 3, 4, 5, 6, 7, 8 } };
	GUID inheritedType{ 0x87654321, 0x4321, 0x4321, { 8, 7, 6, 5, 4, 3, 2, 1 } };
	auto grow = MakeOperation({ L"/ReplaceAccount", L"S-1-1-0:S-1-5-32-545:DACL" });
	auto shrink = MakeOperation({ L"/ReplaceAccount", L"S-1-5-32-545:S-1-1-0:DACL" });
	const BYTE types[] = { ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
		SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE };
	for (BYTE type : types)
	{
		for (DWORD flags = 0; flags < 4; ++flags)
		{
			std::vector<BYTE> storage(256);
			PACL acl = reinterpret_cast<PACL>(storage.data());
			InitializeAcl(acl, static_cast<DWORD>(storage.size()), ACL_REVISION_DS);

			// callback object entries retain their flags field even when neither GUID is present
			std::vector<BYTE> entryBytes(128);
			auto objectAce = reinterpret_cast<ACCESS_ALLOWED_CALLBACK_OBJECT_ACE*>(entryBytes.data());
			objectAce->Header.AceType = type;
			objectAce->Header.AceFlags = OBJECT_INHERIT_ACE;
			objectAce->Mask = FILE_READ_DATA;
			objectAce->Flags = flags;
			auto cursor = reinterpret_cast<BYTE*>(&objectAce->ObjectType);
			if (flags & ACE_OBJECT_TYPE_PRESENT) { memcpy(cursor, &objectType, sizeof(GUID)); cursor += sizeof(GUID); }
			if (flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
			{
				memcpy(cursor, &inheritedType, sizeof(GUID));
				cursor += sizeof(GUID);
			}
			const auto sidOffset = cursor - entryBytes.data();
			const auto sidLength = GetLengthSid(GetSidFromName(L"S-1-1-0"));
			Require(CopySid(sidLength, cursor, GetSidFromName(L"S-1-1-0")) != 0, "Build callback object SID");
			cursor += sidLength;
			constexpr DWORD payload = 0x1234abcd;
			memcpy(cursor, &payload, sizeof(payload));
			objectAce->Header.AceSize = static_cast<WORD>(cursor + sizeof(payload) - entryBytes.data());
			Require(AddAce(acl, ACL_REVISION_DS, MAXDWORD, objectAce, objectAce->Header.AceSize) != 0,
				"Build callback object ACE");
			auto ace = FirstAce(acl);
			std::vector<BYTE> prefix(reinterpret_cast<BYTE*>(ace), reinterpret_cast<BYTE*>(ace) + sidOffset);
			bool cleanup = false;
			ObjectEntry entry{};
			for (Operation* operation : { grow.get(), shrink.get() })
			{
				Require(operation->ProcessAclAction(L"DACL", entry, acl, cleanup), "Replace callback object SID");
				ace = FirstAce(acl);
				auto sid = Operation::GetSidFromAce(ace);
				Require(IsValidAcl(acl) && EqualSid(sid,
					GetSidFromName(operation == grow.get() ? L"S-1-5-32-545" : L"S-1-1-0")), "Find replaced callback SID");
				Require(ace->AceType == type && ace->AceFlags == OBJECT_INHERIT_ACE && ace->Mask == FILE_READ_DATA,
					"Preserve callback ACE permissions");
				Require(memcmp(reinterpret_cast<BYTE*>(ace) + sizeof(ACE_ACCESS_HEADER),
					prefix.data() + sizeof(ACE_ACCESS_HEADER), sidOffset - sizeof(ACE_ACCESS_HEADER)) == 0,
					"Preserve callback object GUIDs");
				Require(memcmp(static_cast<BYTE*>(sid) + GetLengthSid(sid), &payload, sizeof(payload)) == 0,
					"Preserve callback payload");
			}
			if (cleanup) LocalFree(acl);
		}
	}
}

std::wstring ReadBackup(const std::wstring& path)
{
	std::wifstream file(path);
	file.imbue(std::locale(file.getloc(), new std::codecvt_utf8<wchar_t, 0x10ffff, std::consume_header>));
	std::wstring line;
	std::getline(file, line);
	const auto separator = line.find(L'|');
	Require(separator != std::wstring::npos, "Read saved descriptor");
	if (line.ends_with(L'\r')) line.pop_back();
	return line.substr(separator + 1);
}

void CheckDescriptorPipeline(const std::wstring& directory)
{
	// backup readers must observe every preceding component update
	InitialDescriptor = L"O:SYG:SYD:PAI(A;;FA;;;SY)S:PAI(AU;SA;0x1;;;WD)";
	InputOutput::HadErrors() = false;
	const auto beforePath = directory + L"\\before.backup";
	const auto afterPath = directory + L"\\after.backup";
	auto before = MakeOperation({ L"/BackupSecurity", beforePath });
	auto grant = MakeOperation({ L"/GrantPerms", L"S-1-1-0:(R)" });
	auto owner = MakeOperation({ L"/SetOwner", L"S-1-5-32-544" });
	auto group = MakeOperation({ L"/SetOwner", L"S-1-5-32-545:GROUP" });
	auto audit = MakeOperation({ L"/ReplaceAccount", L"S-1-1-0:S-1-5-11:SACL" });
	auto after = MakeOperation({ L"/BackupSecurity", afterPath });
	auto extraGrant = MakeOperation({ L"/GrantPerms", L"S-1-5-32-545:(W)" });
	std::queue<std::wstring> arguments;
	CaptureDescriptor capture(arguments);
	ObjectEntry entry{};
	entry.Name = L"regression";
	entry.ObjectType = SE_FILE_OBJECT;
	Processor processor({ before.get(), grant.get(), owner.get(), group.get(), audit.get(), after.get(),
		extraGrant.get(), &capture }, true, true, true, true);
	processor.AnalyzeSecurity(entry);
	const auto original = ReadBackup(beforePath);
	const auto updated = ReadBackup(afterPath);
	Require(original.find(L";;;WD)") != std::wstring::npos && original.find(L"(A;;FR;;;WD)") == std::wstring::npos,
		"First backup retains the original DACL");
	Require(updated.find(L"O:BAG:BU") == 0 && updated.find(L"(A;;FR;;;WD)") != std::wstring::npos &&
		updated.find(L"(AU;SA;CC;;;AU)") != std::wstring::npos, "Later backup includes owner, group, DACL, and SACL edits");
	Require(updated.find(L"D:PAI") != std::wstring::npos && updated.find(L"S:PAI") != std::wstring::npos,
		"Synchronization retains descriptor control flags");
	Require(capture.Snapshots.size() == 1 && capture.Snapshots[0].find(L"(A;;FW;;;BU)") != std::wstring::npos,
		"A later edit remains valid after descriptor synchronization");
	Require(CommittedDacl.find(L"(A;;FW;;;BU)") != std::wstring::npos && processor.ItemsUpdatedSuccess == 1ull &&
		!InputOutput::HadErrors(), "Commit the final working ACL");

	// granting access to a null DACL must publish the newly present ACL
	InitialDescriptor = L"O:SYG:SYD:NO_ACCESS_CONTROL";
	CaptureDescriptor nullCapture(arguments);
	Processor nullProcessor({ grant.get(), &nullCapture }, true, true, true, true);
	nullProcessor.AnalyzeSecurity(entry);
	Require(nullCapture.Snapshots[0].find(L"(A;;FR;;;WD)") != std::wstring::npos &&
		nullCapture.Snapshots[0].find(L"NO_ACCESS_CONTROL") == std::wstring::npos, "Publish replacement of a null DACL");
	InitialDescriptor.clear();
}

void CheckRestoreProtection(const std::wstring& directory)
{
	// restore both protection states independently, including subsequent inheritance operations
	for (bool daclProtected : { false, true })
	{
		for (bool saclProtected : { false, true })
		{
			InputOutput::HadErrors() = false;
			InitialDescriptor = L"O:SYG:SYD:(A;;FA;;;SY)S:(AU;SA;0x1;;;WD)";
			const auto path = directory + L"\\protection.backup";
			std::ofstream file(path);
			file << "regression|O:SYG:SYD:" << (daclProtected ? "P" : "") << "(A;;FR;;;WD)S:"
				<< (saclProtected ? "P" : "") << "(AU;FA;0x1;;;WD)\n";
			file.close();
			auto restore = MakeOperation({ L"/RestoreSecurity", path });
			auto grant = MakeOperation({ L"/GrantPerms", L"S-1-5-32-545:(W)" });
			auto inherit = MakeOperation({ L"/InheritChildren" });
			std::queue<std::wstring> arguments;
			CaptureDescriptor capture(arguments);
			ObjectEntry entry{};
			entry.Name = L"regression";
			entry.ObjectType = SE_FILE_OBJECT;
			entry.Depth = 1;
			Processor processor({ grant.get(), restore.get(), &capture }, true, true, true, true);
			processor.AnalyzeSecurity(entry);
			const DWORD daclFlags = PROTECTED_DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION;
			const DWORD saclFlags = PROTECTED_SACL_SECURITY_INFORMATION | UNPROTECTED_SACL_SECURITY_INFORMATION;
			Require((CommittedInformation & daclFlags) == (daclProtected ?
				PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION), "Restore DACL protection");
			const DWORD expectedSaclFlag = saclProtected ?
				PROTECTED_SACL_SECURITY_INFORMATION : UNPROTECTED_SACL_SECURITY_INFORMATION;
			Require((CommittedInformation & saclFlags) == expectedSaclFlag, "Restore SACL protection");
			Require(CommittedDacl.find(L";;;BU)") == std::wstring::npos, "Restore replaces earlier ACL allocations");
			Require((capture.Snapshots[0].find(L"S:P") != std::wstring::npos) == saclProtected,
				"Descriptor readers see restored SACL protection");

			// the last inheritance operation governs both commit flags and descriptor readers
			CaptureDescriptor inheritedCapture(arguments);
			Processor inheritedProcessor({ restore.get(), inherit.get(), &inheritedCapture }, true, true, true, true);
			inheritedProcessor.AnalyzeSecurity(entry);
			Require((CommittedInformation & daclFlags) == UNPROTECTED_DACL_SECURITY_INFORMATION &&
				(CommittedInformation & saclFlags) == UNPROTECTED_SACL_SECURITY_INFORMATION, "Later inheritance wins");
			Require(inheritedCapture.Snapshots[0].find(L"D:P") == std::wstring::npos &&
				inheritedCapture.Snapshots[0].find(L"S:P") == std::wstring::npos, "Publish pending inheritance changes");
			Require(!InputOutput::HadErrors(), "Restore pipeline completes without errors");
		}
	}

	// restoring absent ACLs must not retain pointers into the freed descriptor
	InitialDescriptor = L"O:SYG:SYD:(A;;FA;;;SY)S:(AU;SA;0x1;;;WD)";
	const auto absentPath = directory + L"\\absent-acls.backup";
	std::ofstream absentFile(absentPath);
	absentFile << "regression|O:SYG:SY\n";
	absentFile.close();
	auto restoreAbsent = MakeOperation({ L"/RestoreSecurity", absentPath });
	std::queue<std::wstring> arguments;
	CaptureDescriptor absentCapture(arguments, true);
	ObjectEntry entry{};
	entry.Name = L"regression";
	entry.ObjectType = SE_FILE_OBJECT;
	Processor absentProcessor({ restoreAbsent.get(), &absentCapture }, true, true, true, true);
	absentProcessor.AnalyzeSecurity(entry);
	Require(absentProcessor.ItemsUpdatedSuccess == 1ull && !InputOutput::HadErrors(), "Restore absent ACLs safely");
	InitialDescriptor.clear();
}

void CheckShareDiscovery()
{
	TestShares = { { L"Legacy", L"C:\\Data" }, { L"Current", L"C:\\Data" },
		{ L"Child", L"C:\\Data\\Child" }, { L"Unrelated", L"C:\\Database" } };
	InputOutput::ScanPaths().clear();
	auto deduplicated = MakeOperation({ L"/SharePaths", L"regression-server" });
	const auto& paths = InputOutput::ScanPaths();
	Require(paths.size() == 2 && std::ranges::find(paths, L"\\\\regression-server\\Current") != paths.end() &&
		std::ranges::find(paths, L"\\\\regression-server\\Unrelated") != paths.end(), "Keep one alias and unrelated paths");
	InputOutput::ScanPaths().clear();
	auto allShares = MakeOperation({ L"/SharePaths", L"regression-server:NoDeDupe" });
	Require(InputOutput::ScanPaths().size() == TestShares.size(), "NoDeDupe retains every share");
	InputOutput::ScanPaths().clear();
}

void CheckSecurityReadFailure(const std::wstring& directory)
{
	// a real Windows lookup failure must set the process-wide error state
	InputOutput::HadErrors() = false;
	auto find = MakeOperation({ L"/FindAccount", L"S-1-1-0:DACL" });
	ObjectEntry entry{};
	entry.Name = directory + L"\\missing-security-target";
	entry.ObjectType = SE_FILE_OBJECT;
	Processor processor({ find.get() }, true, false, false, false);
	processor.AnalyzeSecurity(entry);
	Require(processor.ItemsReadFailures == 1ull && InputOutput::HadErrors(), "Record security read failures");
}

int wmain(int argc, WCHAR* argv[])
{
	try
	{
		Require(argc == 2, "Supply a temporary output directory");
		InputOutput::InQuietMode() = true;
		CheckCanonicalization();
		CheckAuditRedundancy();
		CheckIdentityMappings(argv[1]);
		CheckCallbackObjectAces();
		CheckDescriptorPipeline(argv[1]);
		CheckRestoreProtection(argv[1]);
		CheckShareDiscovery();
		CheckSecurityReadFailure(argv[1]);
		std::wcout << L"PASS: native ACL, descriptor pipeline, and share discovery regressions\n";
		return 0;
	}
	catch (const std::exception& error)
	{
		std::cerr << "FAIL: " << error.what() << '\n';
		return 1;
	}
}
