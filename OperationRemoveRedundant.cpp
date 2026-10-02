#include "OperationRemoveRedundant.h"
#include "DriverKitPartial.h"
#include "InputOutput.h"
#include "Helpers.h"

ClassFactory<OperationRemoveRedundant> OperationRemoveRedundant::RegisteredFactory(GetCommand());

OperationRemoveRedundant::OperationRemoveRedundant(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
}

bool OperationRemoveRedundant::ProcessAclAction(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	// sanity check
	if (tCurrentAcl == nullptr) return false;

	// track whether the acl was actually change so the caller may decide
	// that the change needs to be persisted
	bool bMadeChange = false;
	bool bSkipIncrement = false;

	PACE_ACCESS_HEADER tAceExplicit = FirstAce(tCurrentAcl);
	for (ULONG iEntryExplicit = 0; iEntryExplicit < tCurrentAcl->AceCount;
		tAceExplicit = (bSkipIncrement) ? tAceExplicit : NextAce(tAceExplicit), iEntryExplicit += (bSkipIncrement) ? 0 : 1)
	{
		// reset skip increment variable
		bSkipIncrement = false;

		// only process explicit items in the outer loop
		if (IsInherited(tAceExplicit)) continue;

		// only process standard ace types
		if (tAceExplicit->AceType != ACCESS_ALLOWED_ACE_TYPE &&
			tAceExplicit->AceType != ACCESS_DENIED_ACE_TYPE &&
			tAceExplicit->AceType != SYSTEM_AUDIT_ACE_TYPE) continue;

		// find a covering inherited entry without changing access-check precedence
		PACE_ACCESS_HEADER tAceInherited = NextAce(tAceExplicit);
		for (ULONG iEntryInherited = iEntryExplicit + 1; iEntryInherited < tCurrentAcl->AceCount;
			tAceInherited = NextAce(tAceInherited), iEntryInherited++)
		{
			// a different access type can change the result for overlapping group memberships
			if (tAceExplicit->AceType != SYSTEM_AUDIT_ACE_TYPE &&
				tAceInherited->AceType != tAceExplicit->AceType) break;

			// only process inherited items in the inner loop
			if (!IsInherited(tAceInherited)) continue;

			// stop processing if we have a mismatching type
			if (tAceInherited->AceType != tAceExplicit->AceType) continue;

			// stop processing if the explicit mask is not a subset of the inherited mask
			if ((tAceExplicit->Mask | tAceInherited->Mask) != tAceInherited->Mask) continue;

			// an inherited audit entry must cover every explicit audit outcome
			constexpr BYTE iAuditFlags = SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG;
			if ((tAceExplicit->AceFlags & iAuditFlags & ~tAceInherited->AceFlags) != 0) continue;

			// stop processing if the explicit mask has container or object inherit
			// but the inherited entry does not
			if (HasContainerInherit(tAceExplicit) && !HasContainerInherit(tAceInherited)) continue;
			if (HasObjectInherit(tAceExplicit) && !HasObjectInherit(tAceInherited)) continue;

			// stop processing if the inherited ace has an inherit only limitation but
			// the explicit entry does not
			if (HasInheritOnly(tAceInherited) && !HasInheritOnly(tAceExplicit)) continue;
			if (HasNoPropogate(tAceInherited) && !HasNoPropogate(tAceExplicit)) continue;

			// if sids are equal then delete this ace since it is redundant
			if (SidMatch(GetSidFromAce(tAceInherited), GetSidFromAce(tAceExplicit)))
			{
				InputOutput::AddInfo(L"Removed redundant explicit entry for '" +
					GetNameFromSidEx(GetSidFromAce(tAceExplicit)) + L"'", sSdPart);
				DeleteAce(tCurrentAcl, iEntryExplicit);
				bMadeChange = true;
				bSkipIncrement = true;
				break;
			}
		}
	}

	return bMadeChange;
}
