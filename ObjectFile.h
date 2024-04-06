#pragma once

#include "Object.h"

class ObjectFile : public Object
{
	static constexpr ULONG MAX_DIRECTORY_BUFFER = 65536;

public:

	// overrides
	void GetBaseObject(std::wstring sPath) override;
	void GetChildObjects(ObjectEntry& oEntry) override;

	// constructors
	ObjectFile(Processor& poProcessor) : Object(poProcessor) {}
};

