#include "OperationCompact.h"
#include "DriverKitPartial.h"
#include "InputOutput.h"
#include "Helpers.h"

ClassFactory<OperationCompact> OperationCompact::RegisteredFactory(GetCommand());

OperationCompact::OperationCompact(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	// flag this as being an ace-level action
	AppliesToDacl = true;
	AppliesToSacl = true;
}

bool OperationCompact::ProcessAclAction(const WCHAR * const sSdPart, ObjectEntry & tObjectEntry, PACL & tCurrentAcl, bool & bAclReplacement)
{
	// sanity check
	if (tCurrentAcl == nullptr) return false;

	// track whether the acl was actually change so the caller may decide
	// that the change needs to be persisted
	bool bMadeChange = false;

	PACE_ACCESS_HEADER tAceOuter = FirstAce(tCurrentAcl);
	for (ULONG iEntryOuter = 0; iEntryOuter < tCurrentAcl->AceCount; tAceOuter = NextAce(tAceOuter), iEntryOuter++)
	{
		// only process standard ace types
		if (tAceOuter->AceType != ACCESS_ALLOWED_ACE_TYPE &&
			tAceOuter->AceType != ACCESS_DENIED_ACE_TYPE &&
			tAceOuter->AceType != SYSTEM_AUDIT_ACE_TYPE) continue;

		// only process explicit entires
		if (IsInherited(tAceOuter)) continue;

		bool bSkipIncrement = false;
		PACE_ACCESS_HEADER tAceInner = NextAce(tAceOuter);
		for (ULONG iEntryInner = iEntryOuter + 1; iEntryInner < tCurrentAcl->AceCount;
			tAceInner = (bSkipIncrement) ? tAceInner : NextAce(tAceInner), iEntryInner += (bSkipIncrement) ? 0 : 1)
		{
			// reset skip increment variable
			bSkipIncrement = false;

			// stop processing completely if the flags are not identical or
			// the flags aren't mergeable with identical masks
			if (!(tAceInner->AceFlags == tAceOuter->AceFlags) &&
				!((tAceInner->Mask == tAceOuter->Mask) &&
				(GetNonOiCiIoBits(tAceInner) == GetNonOiCiIoBits(tAceOuter)))) continue;

			// stop processing completely if we have a mismatching type
			if (tAceInner->AceType != tAceOuter->AceType) continue;

			// if sids are equal then delete this ace
			if (SidMatch(GetSidFromAce(tAceInner), GetSidFromAce(tAceOuter)))
			{
				// the CI and OI flags of entries are mergable since they both add additional
				// permissions.  however, the IO flags effectively blocks access to the parent
				// container so this is merged by setting the bit to zero if either one of the two
				// entries has it unset.
				tAceOuter->AceFlags |= (tAceInner->AceFlags & CONTAINER_INHERIT_ACE);
				tAceOuter->AceFlags |= (tAceInner->AceFlags & OBJECT_INHERIT_ACE);
				tAceOuter->AceFlags &= (!HasInheritOnly(tAceInner) || !HasInheritOnly(tAceOuter)) ? ~INHERIT_ONLY_ACE : ~0;

				// per previous checks, the masks are either identical or mergable so we can
				// unconditionally or them together
				tAceOuter->Mask |= tAceInner->Mask;

				// cleanup the old entry and setup the next interaction to reach the
				// check on the current index
				InputOutput::AddInfo(L"Compacted entries for '" +
					GetNameFromSidEx(GetSidFromAce(tAceInner)) + L"'", sSdPart);
				DeleteAce(tCurrentAcl, iEntryInner);
				iEntryInner = iEntryOuter;
				tAceInner = tAceOuter;
				bMadeChange = true;
			}
		}
	}

	return bMadeChange;
}
