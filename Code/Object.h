#pragma once

#include <string>

#include "Operation.h"
#include "Processor.h"

class Object
{
protected:

	Processor& oProcessor;

public:

	virtual void GetBaseObject(std::wstring sPath) = 0;
	virtual void GetChildObjects(ObjectEntry& oObject) = 0;

	explicit Object(Processor& poProcessor) noexcept : oProcessor(poProcessor) {}
	virtual ~Object() = default;
};
