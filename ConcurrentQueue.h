#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>

template <typename T>
class ConcurrentQueue final
{
private:
	std::condition_variable oItemAvailableCondition;
	std::condition_variable oIsEmptyCondition;
	std::queue<T> oQueue;
	std::mutex oQueueMutex;
	short iWaiters;

public:
	ConcurrentQueue() = default;

	T Pop()
	{
		std::unique_lock<std::mutex> mlock(oQueueMutex);
		if (--iWaiters == 0 && oQueue.empty()) oIsEmptyCondition.notify_one();
		oItemAvailableCondition.wait(mlock, [&]() noexcept { return !oQueue.empty(); });
		auto oQueueItem = oQueue.front();
		oQueue.pop();
		iWaiters++;
		return oQueueItem;
	}

	void Push(const T& oQueueItem)
	{
		{
			std::lock_guard<std::mutex> mlock(oQueueMutex);
			oQueue.push(oQueueItem);
		}
		oItemAvailableCondition.notify_one();
	}

	void WaitForEmptyQueues() 
	{
		std::unique_lock<std::mutex> mlock(oQueueMutex);
		oIsEmptyCondition.wait(mlock, [&]() noexcept { return iWaiters == 0; });
	}

	void SetWaiterCounter(short iWaitCounters)
	{
		iWaiters = iWaitCounters;
	}
};