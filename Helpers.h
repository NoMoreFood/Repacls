#pragma once

#include <Windows.h>
#include <sddl.h>
#include <string>
#include <functional>

#include "Operation.h"

// helper functions
VOID EnablePrivs() noexcept;
PSID GetSidFromName(const std::wstring & sAccountName);
std::wstring GetNameFromSid(PSID tSid, bool * bMarkAsOrphan = nullptr);
std::wstring GetNameFromSidEx(PSID tSid, bool * bMarkAsOrphan = nullptr);
std::wstring GetDomainNameFromSid(PSID tSid);
std::wstring GenerateAccessMask(DWORD iCurrentMask);
std::wstring GenerateInheritanceFlags(DWORD iCurrentFlags);
HANDLE RegisterFileHandle(HANDLE hFile, const std::wstring & sOperation);
std::wstring GetAntivirusStateDescription();
std::wstring FileTimeToString(FILETIME tFileTime);
std::wstring FileSizeToString(LARGE_INTEGER iFileSize);
std::wstring FileAttributesToString(DWORD iAttributes);
BOOL WriteToFile(const std::wstring & sStringToWrite, HANDLE hFile) noexcept;
VOID InitThreadCom() noexcept;
BOOL IsSidInDomain(PSID pSid, PSID pDomainSid) noexcept;

// helper typedefs
typedef struct SidCompare
{
	bool operator()(PSID p1, PSID p2) const
	{
		const DWORD iLength1 = SidLength(p1);
		const DWORD iLength2 = SidLength(p2);
		if (iLength1 != iLength2) return iLength1 < iLength2;
		return memcmp(p1, p2, iLength1) > 0;
	}
}
SidCompare;

//
// SmartPointer<>. Custom template for WinAPI resource cleanup.
// Automatically invokes the provided cleanup callable in its destructor.
//
template <typename T>
class SmartPointer final
{
public:

    SmartPointer(const SmartPointer&) = delete; // non-copyable
    T operator=(const SmartPointer& lp) = delete; // copy assignment forbidden

    SmartPointer(std::function<void(T)> cleanup) noexcept : m_cleanup(std::move(cleanup)), m_data(nullptr) {}
    SmartPointer(std::function<void(T)> cleanup, T data) noexcept : m_cleanup(std::move(cleanup)), m_data(data) {}

    ~SmartPointer()
    {
        Release();
    }

    SmartPointer(SmartPointer&& src) noexcept
    {
        m_cleanup = src.m_cleanup;
        m_data = src.m_data;
        src.m_data = nullptr;
    }

    SmartPointer& operator=(SmartPointer&& src) noexcept
    {
        if (std::addressof(*this) != std::addressof(src))
        {
            Release();
            m_cleanup = std::move(src.m_cleanup);
            m_data = src.m_data;
            src.m_data = nullptr;
        }

        return *this;
    }

    bool IsValid() const noexcept
    {
        return m_data != nullptr && m_data != INVALID_HANDLE_VALUE;
    }

    void Release() noexcept
    {
        if (IsValid())
        {
            m_cleanup(m_data);
            m_data = nullptr;
        }
    }

    T operator=(T lp) noexcept
    {
        Release();
        m_data = lp;
        return m_data;
    }

    operator T() noexcept { return m_data; }
    T& operator*() noexcept  { return m_data; }
    T* operator&() noexcept  { return &m_data; }
    T operator->() noexcept { return m_data; }
    bool operator!() noexcept { return m_data == nullptr; }

private:

    std::function<void(T)> m_cleanup;
    T m_data;
};