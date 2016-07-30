#pragma once

#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>

template <typename T>
class ConcurrentQueue
{
public:

	ConcurrentQueue() = default;

	T pop()
	{
		std::unique_lock<std::mutex> oMutexLock(oMutex);
		while (oQueue.empty())
		{
			oCondition.wait(oMutexLock);
		}
		auto oVar = oQueue.front();
		oQueue.pop();
		return oVar;
	}

	void push(const T& oItem)
	{
		std::unique_lock<std::mutex> oMutuxLock(oMutex);
		oQueue.push(oItem);
		oMutuxLock.unlock();
		oCondition.notify_one();
	}

	void pop(T& oItem)
	{
		std::unique_lock<std::mutex> mlock(oMutex);
		while (oQueue.empty())
		{
			oCondition.wait(mlock);
		}
		oItem = oQueue.front();
		oQueue.pop();
	}

private:
	std::condition_variable oCondition;
	std::queue<T> oQueue;
	std::mutex oMutex;
};