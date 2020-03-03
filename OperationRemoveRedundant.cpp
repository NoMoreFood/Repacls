#include "OperationRemoveRedundant.h"
#include "DriverKitPartial.h"
#include "InputOutput.h"
#include "Functions.h"

ClassFactory<OperationRemoveRedundant> OperationRemoveRedundant::RegisteredFactory(GetCommand());

OperationRemoveRedundant::OperationRemoveRedundant(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
}

bool OperationRemoveRedundant::ProcessAclAction(WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	// sanity check
	if (tCurrentAcl == nullptr) return false;

	// track whether the acl was actually change so the caller may decide
	// that the change needs to be persisted
	bool bMadeChange = false;
	bool bSkipIncrement = false;

	ACCESS_ACE * tAceExplicit = FirstAce(tCurrentAcl);
	for (ULONG iEntryExplicit = 0; iEntryExplicit < tCurrentAcl->AceCount;
		tAceExplicit = (bSkipIncrement) ? tAceExplicit : NextAce(tAceExplicit), iEntryExplicit += (bSkipIncrement) ? 0 : 1)
	{
		// reset skip increment variable
		bSkipIncrement = false;

		// only process explicit items in the outer loop
		if (IsInherited(tAceExplicit)) continue;

		// only process standard ace types
		if (tAceExplicit->Header.AceType != ACCESS_ALLOWED_ACE_TYPE &&
			tAceExplicit->Header.AceType != ACCESS_DENIED_ACE_TYPE &&
			tAceExplicit->Header.AceType != SYSTEM_AUDIT_ACE_TYPE) continue;

		// assume we are increments on the next round
		ACCESS_ACE * tAceInherited = FirstAce(tCurrentAcl);
		for (ULONG iEntryInherited = 0; iEntryInherited < tCurrentAcl->AceCount; tAceInherited = NextAce(tAceInherited), iEntryInherited++)
		{
			// only process inherited items in the inner loop
			if (!IsInherited(tAceInherited)) continue;

			// stop processing if we have a mismatching type
			if (tAceInherited->Header.AceType != tAceExplicit->Header.AceType) continue;

			// stop processing if the explit mask is not a subset of the inherited mask
			if ((tAceExplicit->Mask | tAceInherited->Mask) != tAceInherited->Mask) continue;

			// stop processing if the explcit mask has container or object inherit
			// but the inherited entry does not
			if (HasContainerInherit(tAceExplicit) && !HasContainerInherit(tAceInherited)) continue;
			if (HasObjectInherit(tAceExplicit) && !HasObjectInherit(tAceInherited)) continue;

			// stop processing if the inherited ace has a inherit only limitation but
			// the explcit entry does not
			if (HasInheritOnly(tAceInherited) && !HasInheritOnly(tAceExplicit)) continue;
			if (HasNoPropogate(tAceInherited) && !HasNoPropogate(tAceExplicit)) continue;

			// if sids are equal then delete this ace since it is redundant
			if (SidMatch(&tAceInherited->Sid, &tAceExplicit->Sid))
			{
				InputOutput::AddInfo(L"Removed redundant explicit entry for '" +
					GetNameFromSidEx(&tAceExplicit->Sid) + L"'", sSdPart);
				DeleteAce(tCurrentAcl, iEntryExplicit);
				bMadeChange = true;
				bSkipIncrement = true;
				break;
			}
		}
	}

	return bMadeChange;
}
