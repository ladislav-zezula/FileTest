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

void ACE_CSA_OBJECT::Clear()
{
    if(lpData != NULL)
        LocalFree(lpData);
    lpData = NULL;
    cbData = 0;
}

size_t ACE_CSA_OBJECT::ImportSize(LPBYTE /* pbStructure */, LPBYTE /* pbEnd */, ULONG /* Offset */)
{
    return 0;
}

size_t ACE_CSA_OBJECT::ExportSize(size_t cbAlignSize)
{
    return ALIGN_TO_SIZE(cbData, cbAlignSize);
}

LPBYTE ACE_CSA_OBJECT::Import(LPBYTE pbStructure, LPBYTE pbEnd, ULONG Offset)
{
    size_t cbImportSize;

    // The inner buffer should be reset at this point
    assert(lpData == NULL);
    assert(cbData == 0);

    // Try to capture the data
    if((cbImportSize = ImportSize(pbStructure, pbEnd, Offset)) == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    // Allocate the buffer for the data.
    // Make sure that it's always aligned to 8
    if((lpData = LocalAlloc(LPTR, ALIGN_TO_SIZE(cbImportSize, 8))) == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    // Copy the data
    memcpy(lpData, pbStructure + Offset, cbImportSize);
    cbData = cbImportSize;
    return pbStructure + Offset + ALIGN_TO_SIZE(cbData, sizeof(DWORD));
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

LPBYTE ACE_CSA_OBJECT::ImportObject(LPCVOID /* lpObject */)
{
    SetLastError(ERROR_NOT_SUPPORTED);
    return NULL;
}

//-----------------------------------------------------------------------------
// ACE_CSA_DWORD64 implementation

size_t ACE_CSA_DWORD64::ImportSize(LPBYTE pbStructure, LPBYTE pbEnd, ULONG Offset)
{
    return ((pbStructure + Offset + sizeof(DWORD64)) <= pbEnd) ? sizeof(DWORD64) : 0;
}

LPBYTE ACE_CSA_DWORD64::ImportObject(LPCVOID lpObject)
{
    LPBYTE pbObject = (LPBYTE)(lpObject);

    return Import(pbObject, pbObject + sizeof(DWORD64), 0);
}

//-----------------------------------------------------------------------------
// ACE_CSA_LPWSTR implementation

size_t ACE_CSA_LPWSTR::ImportSize(LPBYTE pbStructure, LPBYTE pbEnd, ULONG Offset)
{
    LPBYTE pbString = pbStructure + Offset;
    size_t cbLength = 0;

    if(StringCbLengthW((LPCWSTR)pbString, (pbEnd - pbString), &cbLength) == S_OK)
        return cbLength + sizeof(WCHAR);

    // Could not find the terminating EOS --> bad format
    SetLastError(ERROR_BAD_FORMAT);
    return 0;
}

LPBYTE ACE_CSA_LPWSTR::ImportObject(LPCVOID lpObject)
{
    LPWSTR szString = (LPWSTR)(lpObject);
    LPBYTE pbString = (LPBYTE)(lpObject);
    size_t cbLength = 0;

    // Calculate the length of the string
    if(szString == NULL)
        return pbString;
    cbLength = (wcslen(szString) + 1) * sizeof(WCHAR);

    // Import string at offset > 0, otherwise the function returns error
    return Import(pbString, pbString + cbLength, 0);
}

//-----------------------------------------------------------------------------
// ACE_CSA_SID implementation
// Windows kernel requires the SID to be prepended with 32-bit length: [Length] [SID]

size_t ACE_CSA_SID::ImportSize(LPBYTE pbStructure, LPBYTE pbEnd, ULONG Offset)
{
    ULONG Length = 0;

    // Capture the length of the SID
    if((pbStructure + Offset + sizeof(ULONG)) <= pbEnd)
    {
        // Copy the length
        memcpy(&Length, pbStructure + Offset, sizeof(ULONG));

        // Capture the length + SID
        if((pbStructure + Offset + sizeof(ULONG) + Length) <= pbEnd)
        {
            return sizeof(ULONG) + Length;
        }
    }

    // Bad format
    SetLastError(ERROR_BAD_FORMAT);
    return NULL;
}

LPBYTE ACE_CSA_SID::ImportObject(LPCVOID lpObject)
{
    LPBYTE pbStructure;
    ULONG SidRelative[MAX_SID_LENGTH];
    ULONG cbLength;
    PSID pSid = (PSID)(lpObject);

    if(pSid != NULL)
    {
        // Initialize the structure that is required for the SID in ACE attributes
        if((cbLength = RtlLengthSid(pSid)) < MAX_SID_LENGTH)
        {
            // Prepare the SID prependede by length
            memcpy(&SidRelative[1], pSid, cbLength);
            pbStructure = (LPBYTE)(SidRelative);
            SidRelative[0] = cbLength;

            // Import the SID
            return Import(pbStructure, pbStructure + sizeof(ULONG) + cbLength, 0);
        }
    }

    SetLastError(ERROR_INVALID_PARAMETER);
    return NULL;
}

//-----------------------------------------------------------------------------
// ACE_CSA_BOOLEAN implementation
// Windows kernel requires each BOOLEAN value to have 8 bytes

size_t ACE_CSA_BOOLEAN::ImportSize(LPBYTE pbStructure, LPBYTE pbEnd, ULONG Offset)
{
    return ((pbStructure + Offset + sizeof(BOOLEAN)) <= pbEnd) ? sizeof(BOOLEAN) : 0;
}

size_t ACE_CSA_BOOLEAN::ExportSize(size_t cbAlignSize)
{
    return ALIGN_TO_SIZE(sizeof(ULONG64), cbAlignSize);
}

LPBYTE ACE_CSA_BOOLEAN::ImportObject(LPCVOID lpObject)
{
    LPBYTE pbObject = (LPBYTE)(lpObject);

    return Import(pbObject, pbObject + sizeof(BOOLEAN), 0);
}

//-----------------------------------------------------------------------------
// ACE_CSA_HELPER implementation

ACE_CSA_HELPER::ACE_CSA_HELPER()
{
    ValueType = Reserved = 0;
    ValueCount = Flags = 0;
    ppObjects = NULL;
}

ACE_CSA_HELPER::~ACE_CSA_HELPER()
{
    Clear();
}

void ACE_CSA_HELPER::Clear()
{
    // Reset the attribute name
    Name.Clear();

    // Free the values
    if(ppObjects != NULL)
        delete[] ppObjects;
    ppObjects = NULL;

    // Reset values
    ValueType = Reserved = 0;
    ValueCount = Flags = 0;
}


DWORD ACE_CSA_HELPER::Create(LPCWSTR szName, WORD aValueType, DWORD aValueCount, ...)
{
    va_list argList;
    DWORD dwErrCode = ERROR_SUCCESS;

    // Free the current values
    Clear();

    // Allocate new values
    if(Name.ImportObject(szName) == NULL)
        return GetLastError();

    // Fill-in the value type
    ValueType = aValueType;

    // Import all elements
    if((ValueCount = aValueCount) != 0)
    {
        va_start(argList, aValueCount);
        if((dwErrCode = AllocateElements()) == ERROR_SUCCESS)
        {
            for(ULONG i = 0; i < ValueCount; i++)
            {
                LPBYTE pbResult = NULL;

                switch(ValueType)
                {
                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
                    {
                        DWORD64 Int64 = va_arg(argList, DWORD64);

                        pbResult = ppObjects[i].ImportObject(&Int64);
                        break;
                    }

                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
                    {
                        LPCWSTR String = va_arg(argList, LPCWSTR);

                        pbResult = ppObjects[i].ImportObject(String);
                        break;
                    }

                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
                    {
                        PSID pSid = va_arg(argList, PSID);

                        pbResult = ppObjects[i].ImportObject(pSid);
                        break;
                    }

                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
                    {
                        BOOLEAN BooleanValue = va_arg(argList, BOOLEAN);

                        pbResult = ppObjects[i].ImportObject(&BooleanValue);
                        break;
                    }

                    default:
                    {
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
        va_end(argList);
    }
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
        ULONG cbName = 0;

        // Import the base values
        ValueType = pAttrRel->ValueType;
        Reserved = pAttrRel->Reserved;
        Flags = pAttrRel->Flags;
        ValueCount = pAttrRel->ValueCount;
        cbMoveBy = cbBase;

        // Do we have an attribute name?
        if(Name.Import(pbAttrRel, pbAttrEnd, pAttrRel->Name) == NULL)
            return GetLastError();
        cbName = (ULONG)Name.ExportSize(sizeof(DWORD));

        // Update the moveby
        cbMoveBy = max(cbMoveBy, pAttrRel->Name + cbName);

        // Enough to cover the value offsets too?
        if((pbAttrRel + (ValueCount * sizeof(DWORD))) <= pbAttrEnd)
        {
            // Make sure that we have the elements
            if((dwErrCode = AllocateElements()) == ERROR_SUCCESS)
            {
                for(ULONG i = 0; i < ValueCount; i++)
                {
                    // Import the n-th value
                    pbEndObject = ppObjects[i].Import(pbAttrRel, pbAttrEnd, pAttrRel->Values.pUint64[i]);
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

        default:
            assert(false);
            break;
    }

    // If the allocation failed, return error
    return (ppObjects != NULL) ? ERROR_SUCCESS : ERROR_NOT_ENOUGH_MEMORY;
}
