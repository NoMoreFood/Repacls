#pragma once

#include <string>

#include "Operation.h"
#include "Processor.h"

class Object
{
protected:

	Processor& oProcessor;
	Object() = default;

public:

	virtual void GetBaseObject(std::wstring sPath) = 0;
	virtual void GetChildObjects(ObjectEntry& oObject) = 0;

	Object(Processor& poProcessor) : oProcessor(poProcessor) {}
	virtual ~Object() = default;
};
