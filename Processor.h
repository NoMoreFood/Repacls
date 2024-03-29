#pragma once

#include <atomic>

#include "ConcurrentQueue.h"
#include "Operation.h"

class Processor final
{
protected:

	bool bFetchDacl = false;
	bool bFetchSacl = false;
	bool bFetchOwner = false;
	bool bFetchGroup = false;

	SECURITY_INFORMATION iInformationToLookup;
	std::vector<Operation*> oOperationList;

	ConcurrentQueue<ObjectEntry> oQueue;
	std::atomic<ULONGLONG> iFilesToProcess;

public:

	std::atomic<ULONGLONG> ItemsScanned = 0;
	std::atomic<ULONGLONG> ItemsUpdatedSuccess = 0;
	std::atomic<ULONGLONG> ItemsUpdatedFailure = 0;
	std::atomic<ULONGLONG> ItemsEnumerationFailures = 0;
	std::atomic<ULONGLONG> ItemsReadFailures = 0;

	ConcurrentQueue<ObjectEntry>& GetQueue() noexcept { return oQueue; }

	void AnalyzeSecurity(ObjectEntry& oEntry);

	static void CompleteEntry(ObjectEntry& oEntry);

	Processor(std::vector<Operation*> poOperationList, bool pbFetchDacl, bool pbFetchSacl, bool pbFetchOwner, bool pbFetchGroup);
	virtual ~Processor() = default;
};
