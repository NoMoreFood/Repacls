#pragma once

#include "Object.h"

class ObjectRegistry : public Object
{
public:

	// overrides
	void GetBaseObject(std::wstring sPath) override;
	void GetChildObjects(ObjectEntry& oEntry) override;

	// constructors
	ObjectRegistry(Processor& poProcessor) : Object(poProcessor) {}
};

