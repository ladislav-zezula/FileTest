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
    // The inner buffer should be reset at this point
    assert(lpData == NULL);
    assert(cbData == 0);

    // Check for length overflow
    if((Length & 0xFFFFFFFF) != Length)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    // Is there enough data in the input?
    if((pbStructure + Offset + Length) > pbEnd)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    // Allocate the buffer for the data.
    // Make sure that it's always aligned to 8
    if((lpData = LocalAlloc(LPTR, ALIGN_TO_SIZE(Length, 8))) == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    // Copy the data
    memcpy(lpData, pbStructure + Offset, Length);
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

size_t ACE_CSA_OBJECT::ExportSize(size_t cbAlignSize)
{
    return ALIGN_TO_SIZE(cbData, cbAlignSize);
}

LPBYTE ACE_CSA_OBJECT::Export(LPBYTE pbPtr, LPBYTE pbEnd)
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

LPBYTE ACE_CSA_OBJECT::Import(LPCVOID /* lpObject */)
{
    // Import of an unknown object is not implemented
    SetLastError(ERROR_NOT_SUPPORTED);
    return NULL;
}

//-----------------------------------------------------------------------------
// ACE_CSA_DWORD64 implementation

LPBYTE ACE_CSA_DWORD64::Import(LPCVOID lpObject)
{
    LPBYTE pbObject = (LPBYTE)(lpObject);

    return ImportData(pbObject, pbObject + sizeof(DWORD64), 0, sizeof(DWORD64));
}

//-----------------------------------------------------------------------------
// ACE_CSA_LPWSTR implementation

LPBYTE ACE_CSA_LPWSTR::Import(LPCVOID lpObject)
{
    LPBYTE pbString = (LPBYTE)(lpObject);
    size_t cbString;

    // Ignore the length, calculate it on our own
    if(lpObject == NULL)
        return pbString;
    cbString = (wcslen((LPWSTR)(lpObject)) + 1) * sizeof(WCHAR);

    // Proceed with the import
    return ImportData(pbString, pbString + cbString, 0, cbString);
}

//-----------------------------------------------------------------------------
// ACE_CSA_SID implementation
// Windows kernel requires the SID to be prepended with 32-bit length: [Length] [SID]

LPBYTE ACE_CSA_SID::Import(LPCVOID lpObject)
{
    return ImportOctet((PACE_OCTET_STRING)(lpObject));
}

//-----------------------------------------------------------------------------
// ACE_CSA_BOOLEAN implementation
// Windows kernel requires each BOOLEAN value to have 8 bytes

size_t ACE_CSA_BOOLEAN::ExportSize(size_t cbAlignSize)
{
    return ALIGN_TO_SIZE(sizeof(ULONG64), cbAlignSize);
}

LPBYTE ACE_CSA_BOOLEAN::Import(LPCVOID lpObject)
{
    LPBYTE pbObject = (LPBYTE)(lpObject);

    return ImportData(pbObject, pbObject + sizeof(BOOLEAN), 0, sizeof(BOOLEAN));
}

//-----------------------------------------------------------------------------
// ACE_CSA_OCTET_STRING implementation

LPBYTE ACE_CSA_OCTET_STRING::Import(LPCVOID lpObject)
{
    return ImportOctet((PACE_OCTET_STRING)(lpObject));
}

//-----------------------------------------------------------------------------
// ACE_CSA_HELPER implementation

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

DWORD ACE_CSA_HELPER::CreateVA(LPCWSTR szName, WORD aValueType, DWORD aValueCount, va_list argList)
{
    LPBYTE pbResult = NULL;
    DWORD dwErrCode = ERROR_SUCCESS;

    // Free the current values
    Clear();

    // Allocate new values
    if(Name.Import(szName) == NULL)
        return GetLastError();

    // Fill-in the value type
    ValueType = aValueType;
    Flags = 0;

    // Import all elements
    if((ValueCount = aValueCount) != 0)
    {
        if((dwErrCode = AllocateElements()) == ERROR_SUCCESS)
        {
            if(argList != NULL)
            {
                for(ULONG i = 0; i < ValueCount; i++)
                {
                    switch(ValueType)
                    {
                        case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
                        case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
                        {
                            DWORD64 Int64 = va_arg(argList, DWORD64);

                            pbResult = ImportObject(&Int64, i);
                            break;
                        }

                        case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
                        {
                            LPCWSTR String = va_arg(argList, LPCWSTR);

                            pbResult = ImportObject(String, i);
                            break;
                        }

                        case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
                        {
                            LPCVOID lpOctet = va_arg(argList, LPCVOID);

                            pbResult = ImportObject(lpOctet, i);
                            break;
                        }

                        case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
                        {
                            BOOLEAN BooleanValue = va_arg(argList, BOOLEAN);

                            pbResult = ImportObject(&BooleanValue, i);
                            break;
                        }

                        case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
                        {
                            LPCVOID lpOctet = va_arg(argList, LPCVOID);

                            pbResult = ImportObject(lpOctet, i);
                            break;
                        }

                        default:
                        {
                            pbResult = NULL;
                            assert(false);
                            break;
                        }
                    }

                    // Did the import succeed?
                    if(pbResult == NULL)
                    {
                        dwErrCode = GetLastError();
                        break;
                    }
                }
            }
        }
    }
    return dwErrCode;
}

DWORD ACE_CSA_HELPER::Create(LPCWSTR szName, WORD aValueType, DWORD aValueCount, ...)
{
    va_list argList;
    DWORD dwErrCode;

    va_start(argList, aValueCount);
    dwErrCode = CreateVA(szName, aValueType, aValueCount, argList);
    va_end(argList);

    return dwErrCode;
}

DWORD ACE_CSA_HELPER::Import(LPBYTE pbAttrRel, LPBYTE pbAttrEnd, PULONG pcbMoveBy)
{
    ULONG cbBase = FIELD_OFFSET(CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1, Values);
    DWORD dwErrCode = ERROR_BAD_FORMAT;
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
        cbMoveBy = max(cbMoveBy, (size_t)(pbEndObject - pbAttrRel));

        // Enough to cover the value offsets too?
        if((pbAttrRel + (ValueCount * sizeof(DWORD))) <= pbAttrEnd)
        {
            // Make sure that we have the elements
            if((dwErrCode = AllocateElements()) == ERROR_SUCCESS)
            {
                for(ULONG i = 0; i < ValueCount; i++)
                {
                    // Import the n-th value. TODO: Verify size of the data!!!
                    pbEndObject = ppObjects[i].Import(pbAttrRel + pAttrRel->Values.pUint64[i]);
                    if(pbEndObject == NULL)
                        return GetLastError();

                    // Update the biggest offset
                    if(dwErrCode != ERROR_SUCCESS)
                        return dwErrCode;
                    cbMoveBy = max(cbMoveBy, (ULONG)(pbEndObject - pbAttrRel));
                }
            }
        }
    }

    // Give the result to the caller. Always try to eat up to 8-byte boundary
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = GetSizeAlignedToMax(pbAttrRel, pbAttrEnd, cbMoveBy);
    return dwErrCode;
}

// In case NtSetSecurityObject returns STATUS_INVALID_ACL, look here:
// nt!RtlpValidRelativeAttribute(PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 pAttrRel, size_t cbAttrRel)
PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 ACE_CSA_HELPER::Export(PULONG pcbLength)
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

LPBYTE ACE_CSA_HELPER::ImportObject(LPCVOID lpObject, ULONG Index)
{
    // Objects must be already allocated
    assert(ppObjects != NULL);
    assert(ValueCount != 0);

    // Check for overflow
    if(Index >= ValueCount)
    {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return NULL;
    }

    // Import the object
    return ppObjects[Index].Import(lpObject);
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

DWORD ACE_CSA_HELPER::AllocateElements()
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
            assert(false);
            break;
    }

    // If the allocation failed, return error
    return (ppObjects != NULL) ? ERROR_SUCCESS : ERROR_NOT_ENOUGH_MEMORY;
}
