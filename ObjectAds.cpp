#include "InputOutput.h"
#include "ObjectAds.h"
#include "Helpers.h"

#include <windows.h>
#include <wchar.h>

#include <activeds.h>
#include <atlbase.h>

#pragma comment(lib,"activeds.lib")
#pragma comment(lib,"adsiid.lib")

void ObjectAds::GetBaseObject(std::wstring_view sPath)
{
    // initialize com for this thread
    InitThreadCom();

    // build initial object
    ObjectEntry tAds = {};
    tAds.Depth = 0;
    tAds.ObjectType = SE_DS_OBJECT;
    tAds.Name = std::wstring(L"LDAP://") + sPath.data();
	oProcessor.GetQueue().Push(tAds);
}

void ObjectAds::GetChildObjects(ObjectEntry& oEntry)
{
    // initialize com for this thread
    InitThreadCom();

    // analyze security on this node
    oProcessor.AnalyzeSecurity(oEntry);

    // enumerate children
    CComPtr<IADsContainer> pContainer = nullptr;
    IEnumVARIANT* pEnumerator = nullptr;
    if (FAILED(ADsOpenObject(oEntry.Name.c_str(), NULL, NULL, ADS_SECURE_AUTHENTICATION, IID_PPV_ARGS(&pContainer))) ||
        FAILED(ADsBuildEnumerator(pContainer, &pEnumerator)))
    {
        // complain
        InputOutput::AddError(L"Error occurred while enumerating distinguished name");
        oProcessor.CompleteEntry(oEntry);
        oProcessor.ItemsEnumerationFailures++;
        return;
    }

    // enumerate the object as a container
    ULONG iFetched = 0L;
    VARIANT vVar;
    VariantInit(&vVar);
    while (SUCCEEDED(ADsEnumerateNext(pEnumerator, 1, &vVar, &iFetched)) && (iFetched > 0))
    {
        CComPtr<IADs> pADs = nullptr;
        if (SUCCEEDED(V_DISPATCH(&vVar)->QueryInterface(IID_PPV_ARGS(&pADs))))
        {
            CComBSTR sDistinguishedName;
            if (SUCCEEDED(pADs->get_ADsPath(&sDistinguishedName)))
            {
                ObjectEntry tAds = {};
                tAds.Depth = oEntry.Depth + 1;
                tAds.ObjectType = SE_DS_OBJECT;
                tAds.Name = sDistinguishedName;
                oProcessor.GetQueue().Push(tAds);
            }
            else
            {
                InputOutput::AddError(L"Failed to obtained distuished name");
            }
        }

        VariantClear(&vVar);
    }

    // cleanup
    ADsFreeEnumerator(pEnumerator);
    oProcessor.CompleteEntry(oEntry);
}
