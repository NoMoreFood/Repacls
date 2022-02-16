#pragma once

#include "Object.h"

class ObjectRegistry : public Object
{
public:

	// overrides
	void GetBaseObject(std::wstring_view sPath) override;
	void GetChildObjects(ObjectEntry& oObject) override;

	// constructors
	ObjectRegistry(Processor& poProcessor) : Object(poProcessor) {};
};

