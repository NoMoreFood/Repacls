#pragma once

#include "Object.h"

class ObjectAds : public Object
{
public:

	// overrides
	void GetBaseObject(std::wstring_view sPath) override;
	void GetChildObjects(ObjectEntry& oEntry) override;

	// constructors
	ObjectAds(Processor& poProcessor) : Object(poProcessor) {}
};

