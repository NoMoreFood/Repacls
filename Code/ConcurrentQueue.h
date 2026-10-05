#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>
#include <utility>

template <typename T>
class ConcurrentQueue final
{
	std::condition_variable oItemAvailableCondition;
	std::condition_variable oIsEmptyCondition;
	std::queue<T> oQueue;
	std::mutex oQueueMutex;
	int iActiveWorkers = 0;

public:
	ConcurrentQueue() = default;
	ConcurrentQueue(const ConcurrentQueue&) = delete;
	ConcurrentQueue& operator=(const ConcurrentQueue&) = delete;
	ConcurrentQueue(ConcurrentQueue&&) = delete;
	ConcurrentQueue& operator=(ConcurrentQueue&&) = delete;

	T Pop()
	{
		std::unique_lock<std::mutex> mlock(oQueueMutex);
		if (--iActiveWorkers == 0 && oQueue.empty()) oIsEmptyCondition.notify_all();
		oItemAvailableCondition.wait(mlock, [this]() noexcept { return !oQueue.empty(); });
		T oQueueItem = std::move(oQueue.front());
		oQueue.pop();
		++iActiveWorkers;
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

	void Push(T&& oQueueItem)
	{
		{
			std::lock_guard<std::mutex> mlock(oQueueMutex);
			oQueue.push(std::move(oQueueItem));
		}
		oItemAvailableCondition.notify_one();
	}

	void WaitForEmptyQueues()
	{
		std::unique_lock<std::mutex> mlock(oQueueMutex);
		oIsEmptyCondition.wait(mlock, [this]() noexcept { return iActiveWorkers == 0 && oQueue.empty(); });
	}

	void SetWaiterCounter(short iWaitCounters) noexcept
	{
		std::lock_guard<std::mutex> mlock(oQueueMutex);
		iActiveWorkers = iWaitCounters;
	}
};
