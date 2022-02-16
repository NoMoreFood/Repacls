#pragma once

// mute compatibility concerns
#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS

#include <windows.h>
#include <accctrl.h>
#include <string>
#include <vector>
#include <queue>
#include <map>

#include "Operation.h"
#include "Processor.h"
#include "ConcurrentQueue.h"

class Object
{
protected:

	Processor& oProcessor;
	Object() = default;

public:

	virtual void GetBaseObject(std::wstring_view sPath) = 0;
	virtual void GetChildObjects(ObjectEntry& oObject) = 0;

	Object(Processor& poProcessor) : oProcessor(poProcessor) {};
	virtual ~Object() = default;
};
