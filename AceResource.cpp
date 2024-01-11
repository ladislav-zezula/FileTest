/*****************************************************************************/
/* AceResource.cpp                        Copyright (c) Ladislav Zezula 2023 */
/*---------------------------------------------------------------------------*/
/* Description:                                                              */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 23.11.23  1.00  Lad  Created                                              */
/*****************************************************************************/

#include "FileTest.h"

//-----------------------------------------------------------------------------
// Local structures

typedef struct _LOCAL_OCTET_STRING
{
    ULONG Length;
    BYTE Data[256];
} LOCAL_OCTET_STRING, *PLOCAL_OCTET_STRING;

static void MakeOctetString(LOCAL_OCTET_STRING & OctetString, LPCVOID lpData, ULONG cbData)
{
    assert(cbData <= 256);

    memset(&OctetString, 0, sizeof(LOCAL_OCTET_STRING));
    memcpy(OctetString.Data, lpData, cbData);
    OctetString.Length = cbData;
}

static void MakeOctetString(LOCAL_OCTET_STRING & OctetString, ULONGLONG IntValue)
{
    // Prepare an 8-byte octet string (little endian)
    MakeOctetString(OctetString, &IntValue, sizeof(IntValue));
}

static void MakeOctetStringSid(LOCAL_OCTET_STRING & OctetString, PSID pSid)
{
    MakeOctetString(OctetString, pSid, RtlLengthSid(pSid));
}


//-----------------------------------------------------------------------------
// Copies data to an output buffer

NTSTATUS CopyDataAway(LPBYTE pbPtr, LPBYTE pbEnd, LPCVOID lpData, ULONG cbData, PULONG pcbMoveBy)
{
    if(cbData > (ULONG)(pbEnd - pbPtr))
        return STATUS_BUFFER_OVERFLOW;

    // Copy the data to the target buffer
    memcpy(pbPtr, lpData, cbData);

    // Give the length of the data
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbData;
    return STATUS_SUCCESS;
}

static LPBYTE ExportDataAway(LPBYTE pbPtr, LPBYTE pbEnd, LPCVOID lpData, ULONG cbData)
{
    if(CopyDataAway(pbPtr, pbEnd, lpData, cbData, NULL) != STATUS_SUCCESS)
        return NULL;
    return pbPtr;
}

static LPBYTE ExportDataAway(LPBYTE pbPtr, LPBYTE pbEnd, LOCAL_OCTET_STRING & OctetString)
{
    return ExportDataAway(pbPtr, pbEnd, &OctetString, sizeof(ULONG) + OctetString.Length);
}

//-----------------------------------------------------------------------------
// ACE_CSA_OBJECT implementation

ACE_CSA_OBJECT::ACE_CSA_OBJECT()
{
    lpData = NULL;
    cbData = 0;
}

ACE_CSA_OBJECT::~ACE_CSA_OBJECT()
{
    Clear();
}

LPBYTE ACE_CSA_OBJECT::ImportData(LPBYTE pbStructure, LPBYTE pbEnd, size_t Offset, size_t Length)
{
    LPVOID lpNewData;

    // Check for length overflow
    if((Length & 0xFFFFFFFF) != Length)
    {
        SetLastError((DWORD)STATUS_INVALID_PARAMETER);
        return NULL;
    }

    // Is there enough data in the input?
    if((pbStructure + Offset + Length) > pbEnd)
    {
        SetLastError((DWORD)STATUS_INVALID_PARAMETER);
        return NULL;
    }

    // Allocate the buffer for the data.
    // Make sure that it's always aligned to 8
    if((lpNewData = LocalAlloc(LPTR, ALIGN_TO_SIZE(Length, 8))) == NULL)
    {
        SetLastError((DWORD)STATUS_NO_MEMORY);
        return NULL;
    }

    // Free any existing data
    Clear();

    // Copy the data
    memcpy(lpNewData, pbStructure + Offset, Length);
    lpData = lpNewData;
    cbData = (ULONG)(Length);
    
    // Return the position of the data after the input
    return pbStructure + Offset + ALIGN_TO_SIZE(Length, sizeof(DWORD));
}

LPBYTE ACE_CSA_OBJECT::ImportOctet(PACE_OCTET_STRING pOctetString)
{
    LPBYTE pbOctet = (LPBYTE)(pOctetString);
    size_t cbOctet = OctetStringSize(pOctetString);

    return ImportData(pbOctet, pbOctet + cbOctet, 0, cbOctet);
}

void ACE_CSA_OBJECT::Clear()
{
    if(lpData != NULL)
        LocalFree(lpData);
    lpData = NULL;
    cbData = 0;
}

size_t ACE_CSA_OBJECT::ExportSize(size_t cbAlignSize) const
{
    return ALIGN_TO_SIZE(cbData, cbAlignSize);
}

LPBYTE ACE_CSA_OBJECT::Export(LPBYTE pbPtr, LPBYTE pbEnd) const
{
    size_t cbLength = ExportSize();

    // Check whether the object fits into the buffer
    if((pbPtr + cbLength) > pbEnd)
    {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return NULL;
    }

    // Copy the data to the buffer
    memcpy(pbPtr, lpData, cbLength);
    return pbPtr + ALIGN_TO_SIZE(cbLength, sizeof(DWORD));
}

LPBYTE ACE_CSA_OBJECT::Default(LPBYTE /* pbPtr */, LPBYTE /* pbEnd */, DWORD /* dwIndexHint */) const
{
    // Should never be called
    assert(false);
    return NULL;
}

LPBYTE ACE_CSA_OBJECT::Import(LPCVOID /* lpObject */)
{
    // Import of an unknown object is not implemented
    SetLastError((DWORD)STATUS_NOT_SUPPORTED);
    return NULL;
}

//-----------------------------------------------------------------------------
// ACE_CSA_DWORD64 implementation

LPBYTE ACE_CSA_DWORD64::Default(LPBYTE pbPtr, LPBYTE pbEnd, DWORD i) const
{
    DWORD64 DefaultValues[] = {0xDEADBABEULL, 0x12342ULL};
    DWORD64 DefaultValue = (i < _countof(DefaultValues)) ? DefaultValues[i] : 0x1234567812345678ULL + i;

    return ExportDataAway(pbPtr, pbEnd, &DefaultValue, sizeof(DefaultValue));
}

LPBYTE ACE_CSA_DWORD64::Import(LPCVOID lpObject)
{
    LPBYTE pbObject = (LPBYTE)(lpObject);

    return ImportData(pbObject, pbObject + sizeof(DWORD64), 0, sizeof(DWORD64));
}

//-----------------------------------------------------------------------------
// ACE_CSA_LPWSTR implementation

LPBYTE ACE_CSA_LPWSTR::Default(LPBYTE pbPtr, LPBYTE pbEnd, DWORD i) const
{
    LPCWSTR DefaultValues[] = {L"Daenerys", L"Targaryen", L"TheStormBorn"};
    LPCWSTR DefaultValue = DefaultValues[i];
    WCHAR szBuffer[128];

    if(i >= _countof(DefaultValues))
    {
        StringCchPrintfW(szBuffer, _countof(szBuffer), L"DefaultString%u", i);
        DefaultValue = szBuffer;
    }
    return ExportDataAway(pbPtr, pbEnd, DefaultValue, (ULONG)StringLength(DefaultValue));
}

LPBYTE ACE_CSA_LPWSTR::Import(LPCVOID lpObject)
{
    LPBYTE pbString = (LPBYTE)(lpObject);
    size_t cbString;

    // Ignore the length, calculate it on our own
    if(lpObject == NULL)
        return pbString;
    cbString = StringLength(lpObject);

    // Proceed with the import
    return ImportData(pbString, pbString + cbString, 0, cbString);
}

size_t ACE_CSA_LPWSTR::StringLength(LPCVOID lpObject) const
{
    size_t cbString = 0;

    if(lpObject != NULL)
        cbString = (wcslen((LPWSTR)(lpObject)) + 1) * sizeof(WCHAR);
    return cbString;
}

//-----------------------------------------------------------------------------
// ACE_CSA_SID implementation
// Windows kernel requires the SID to be prepended with 32-bit length: [Length] [SID]

LPBYTE ACE_CSA_SID::Default(LPBYTE pbPtr, LPBYTE pbEnd, DWORD i) const
{
    LOCAL_OCTET_STRING OctetString;

    switch(i)
    {
        case 0:
            MakeOctetStringSid(OctetString, (PSID)(SidLocAdmins));
            break;

        case 1:
            MakeOctetStringSid(OctetString, (PSID)(SidLocUsers));
            break;

        default:
            MakeOctetStringSid(OctetString, (PSID)(SidEveryone));
            break;
    }
    return ExportDataAway(pbPtr, pbEnd, OctetString);
}

LPBYTE ACE_CSA_SID::Import(LPCVOID lpObject)
{
    return ImportOctet((PACE_OCTET_STRING)(lpObject));
}

//-----------------------------------------------------------------------------
// ACE_CSA_BOOLEAN implementation
// Windows kernel requires each BOOLEAN value to have 8 bytes

size_t ACE_CSA_BOOLEAN::ExportSize(size_t cbAlignSize) const
{
    return ALIGN_TO_SIZE(sizeof(ULONG64), cbAlignSize);
}

LPBYTE ACE_CSA_BOOLEAN::Default(LPBYTE pbPtr, LPBYTE pbEnd, DWORD i) const
{
    ULONG64 DefaultValue = i & 1;

    return ExportDataAway(pbPtr, pbEnd, &DefaultValue, sizeof(DefaultValue));
}

LPBYTE ACE_CSA_BOOLEAN::Import(LPCVOID lpObject)
{
    LPBYTE pbObject = (LPBYTE)(lpObject);

    return ImportData(pbObject, pbObject + sizeof(BOOLEAN), 0, sizeof(BOOLEAN));
}

//-----------------------------------------------------------------------------
// ACE_CSA_OCTET_STRING implementation

LPBYTE ACE_CSA_OCTET_STRING::Default(LPBYTE pbPtr, LPBYTE pbEnd, DWORD i) const
{
    LOCAL_OCTET_STRING OctetString;
    BYTE OctetString0[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    BYTE OctetString1[] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x3C, 0x4D, 0x01, 0x02, 0x03, 0x04};

    switch(i)
    {
        case 0:
            MakeOctetString(OctetString, OctetString0, sizeof(OctetString0));
            break;

        case 1:
            MakeOctetString(OctetString, OctetString1, sizeof(OctetString1));
            break;

        default:
            MakeOctetString(OctetString, i);
            break;
    }
    return ExportDataAway(pbPtr, pbEnd, OctetString);
}

LPBYTE ACE_CSA_OCTET_STRING::Import(LPCVOID lpObject)
{
    return ImportOctet((PACE_OCTET_STRING)(lpObject));
}

//-----------------------------------------------------------------------------
// ACE_CSA_HELPER implementation

ACE_CSA_HELPER::ACE_CSA_HELPER(LPCWSTR szName, WORD wValueType, DWORD dwValueCount)
{
    // Setup the object so that it does not contain anything
    InitialReset();

    // Create the object name
    if(Name.Import(szName) == NULL)
        return;

    // Set the value type and count
    SetValueType(wValueType, dwValueCount);
}

ACE_CSA_HELPER::ACE_CSA_HELPER()
{
    InitialReset();
}

ACE_CSA_HELPER::~ACE_CSA_HELPER()
{
    Clear();
}

void ACE_CSA_HELPER::InitialReset()
{
    ValueType = Reserved = 0;
    ValueCount = Flags = 0;
    ppObjects = NULL;
}

void ACE_CSA_HELPER::Clear()
{
    // Reset the attribute name
    Name.Clear();

    // Free the values
    if(ppObjects != NULL)
        delete[] ppObjects;
    InitialReset();
}

NTSTATUS ACE_CSA_HELPER::SetValueName(LPCWSTR szName)
{
    return (Name.Import(szName) != NULL) ? ERROR_SUCCESS : GetLastError();
}

NTSTATUS ACE_CSA_HELPER::SetValueType(WORD wValueType, DWORD dwValueCount)
{
    ACE_CSA_OBJECT * ppSaveObjects = NULL;
    NTSTATUS Status;
    DWORD dwSaveValueCount = 0;
    BYTE CopyBuffer[MAX_ACL_LENGTH];

    // If we are changing the value type, we need to free the current values
    if(wValueType != ValueType)
    {
        // Free the current objects
        if(ppObjects != NULL)
            delete[] ppObjects;
        ppSaveObjects = ppObjects = NULL;
    }
    else if(dwValueCount != ValueCount)
    {
        dwSaveValueCount = ValueCount;
        ppSaveObjects = ppObjects;
        ppObjects = NULL;
    }
    else
    {
        return STATUS_SUCCESS;
    }

    // Setup the value type and value count
    ValueCount = dwValueCount;
    ValueType = wValueType;

    // Allocate elements and supply default values
    if((Status = AllocateElements()) == STATUS_SUCCESS)
    {
        LPBYTE pbPtr = CopyBuffer;
        LPBYTE pbEnd = pbPtr + sizeof(CopyBuffer);
        LPBYTE pbResult;

        for(DWORD i = 0; i < ValueCount; i++)
        {
            // Make sure that the copy buffer is zeroed
            memset(CopyBuffer, 0, sizeof(CopyBuffer));

            // Export the existing object or create default value
            if(ppSaveObjects && i < dwSaveValueCount)
            {
                pbResult = ppSaveObjects[i].Export(pbPtr, pbEnd);
            }
            else
            {
                pbResult = ppObjects[i].Default(pbPtr, pbEnd, i);
            }

            // Do we have some value?
            if(pbResult != NULL)
            {
                ppObjects[i].Import(pbPtr);
            }
        }
    }
    else
    {
        ValueCount = dwSaveValueCount;
        ppObjects = ppSaveObjects;
    }
    return Status;
}

NTSTATUS ACE_CSA_HELPER::SetValueData(LPCVOID lpObject, ULONG Index)
{
    // Objects must be already allocated
    assert(ppObjects != NULL);
    assert(ValueCount != 0);

    // Check for overflow
    if(Index >= ValueCount)
        return STATUS_BUFFER_OVERFLOW;

    // Import the object
    return (ppObjects[Index].Import(lpObject) != NULL) ? STATUS_SUCCESS : GetLastError();
}

NTSTATUS ACE_CSA_HELPER::AllocateElements()
{
    // Sanity checks
    assert(ppObjects == NULL);
    assert(ValueCount != 0);
    assert(ValueType != 0);

    // Allocate the elements based on element type
    switch(ValueType)
    {
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
        case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
            ppObjects = new ACE_CSA_DWORD64[ValueCount];
            break;

        case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
            ppObjects = new ACE_CSA_LPWSTR[ValueCount];
            break;

        case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
            ppObjects = new ACE_CSA_SID[ValueCount];
            break;

        case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
            ppObjects = new ACE_CSA_BOOLEAN[ValueCount];
            break;

        case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
            ppObjects = new ACE_CSA_OCTET_STRING[ValueCount];
            break;

        default:
            return STATUS_INVALID_PARAMETER;
    }

    // If the allocation failed, return error
    return (ppObjects != NULL) ? STATUS_SUCCESS : STATUS_NO_MEMORY;
}

NTSTATUS ACE_CSA_HELPER::Import(LPBYTE pbAttrRel, LPBYTE pbAttrEnd, PULONG pcbMoveBy)
{
    NTSTATUS Status = STATUS_BAD_DATA;
    ULONG cbBase = FIELD_OFFSET(CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1, Values);
    ULONG cbMoveBy = 0;

    // Free the current values
    Clear();

    // Enough data to cover CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1?
    if((pbAttrRel + cbBase) <= pbAttrEnd)
    {
        PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 pAttrRel = (PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1)(pbAttrRel);
        LPBYTE pbEndObject;

        // Import the base values
        ValueType = pAttrRel->ValueType;
        Reserved = pAttrRel->Reserved;
        Flags = pAttrRel->Flags;
        ValueCount = pAttrRel->ValueCount;
        cbMoveBy = cbBase;

        // Import the name
        if((pbEndObject = Name.Import(pbAttrRel + pAttrRel->Name)) == NULL)
            return GetLastError();
        cbMoveBy = max(cbMoveBy, (ULONG)(pbEndObject - pbAttrRel));

        // Enough to cover the value offsets too?
        if((pbAttrRel + (ValueCount * sizeof(DWORD))) <= pbAttrEnd)
        {
            // Make sure that we have the elements
            if((Status = AllocateElements()) == STATUS_SUCCESS)
            {
                for(ULONG i = 0; i < ValueCount; i++)
                {
                    // Import the n-th value. TODO: Verify size of the data!!!
                    pbEndObject = ppObjects[i].Import(pbAttrRel + pAttrRel->Values.pUint64[i]);
                    if(pbEndObject == NULL)
                        return GetLastError();

                    // Update the biggest offset
                    cbMoveBy = max(cbMoveBy, (ULONG)(pbEndObject - pbAttrRel));
                }
            }
        }
    }

    // Give the result to the caller. Always try to eat up to 8-byte boundary
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = GetSizeAlignedToMax(pbAttrRel, pbAttrEnd, cbMoveBy);
    return Status;
}

// In case NtSetSecurityObject returns STATUS_INVALID_ACL, look here:
// nt!RtlpValidRelativeAttribute(PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 pAttrRel, size_t cbAttrRel)
PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 ACE_CSA_HELPER::Export(PULONG pcbLength) const
{
    PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 pAttrRel = NULL;
    ULONG cbLength = 0;

    // Allocate buffer. Don't bother with calculating the length.
    // The maximum size of an ACE is 0xFFF8 bytes, which we can afford to allocate
    pAttrRel = (PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1)LocalAlloc(LPTR, MAX_ACL_LENGTH);
    if(pAttrRel != NULL)
    {
        LPBYTE pbStructure = (LPBYTE)(pAttrRel);
        LPBYTE pbPtr = pbStructure + FIELD_OFFSET(CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1, Values) + ValueCount * sizeof(ULONG);
        LPBYTE pbEnd = pbStructure + MAX_ACL_LENGTH;

        // Copy the base structure
        pAttrRel->ValueType  = ValueType;
        pAttrRel->Reserved   = Reserved;
        pAttrRel->Flags      = Flags;
        pAttrRel->ValueCount = ValueCount;

        // Export the attribute name
        if(Name.Export(pbPtr, pbEnd) > pbPtr)
        {
            pAttrRel->Name = (ULONG)(pbPtr - pbStructure);
            pbPtr = pbPtr + Name.ExportSize(sizeof(DWORD));
        }

        // Copy values
        for(ULONG i = 0; i < ValueCount; i++)
        {
            // Write the value offset
            pAttrRel->Values.pUint64[i] = (ULONG)(pbPtr - pbStructure);

            // Write the value itself
            pbPtr = ppObjects[i].Export(pbPtr, pbEnd);
            assert(pbPtr != NULL);
        }

        // Update the length
        cbLength = (ULONG)(pbPtr - pbStructure);
    }

    // Give the result to the caller
    if(pcbLength != NULL)
        pcbLength[0] = cbLength;
    return pAttrRel;
}

ULONG ACE_CSA_HELPER::GetSizeAlignedToMax(LPBYTE pbPtr, LPBYTE pbEnd, ULONG cbLength)
{
    ULONG cbLengthAligned;

    // Can we eat up size aligned to 8 bytes?
    cbLengthAligned = ALIGN_TO_SIZE(cbLength, 8);
    if((pbPtr + cbLengthAligned) <= pbEnd)
        return cbLengthAligned;

    // Can we eat up size aligned to 4 bytes?
    cbLengthAligned = ALIGN_TO_SIZE(cbLength, 4);
    if((pbPtr + cbLengthAligned) <= pbEnd)
        return cbLengthAligned;

    // Can we eat up size aligned to 2 bytes?
    cbLengthAligned = ALIGN_TO_SIZE(cbLength, 2);
    if((pbPtr + cbLengthAligned) <= pbEnd)
        return cbLengthAligned;

    // Return the length as-is
    assert(false);
    return cbLength;
}
