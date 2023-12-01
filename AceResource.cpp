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
// Local functions - value lengths

static ULONG AceResGetValueLength(LPWSTR Value)
{
    return (wcslen(Value) + 1) * sizeof(WCHAR);
}

// Returns the length needed by the value
static ULONG AceResGetValuesLength(PCLAIM_SECURITY_ATTRIBUTE_V1 pAttrAbs)
{
    ULONG cbTotalLength = 0;
    ULONG cbLength;

    for(ULONG i = 0; i < pAttrAbs->ValueCount; i++)
    {
        // Add the size of value itself
        switch(pAttrAbs->ValueType)
        {
            case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
            case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
                cbTotalLength += sizeof(ULONG64);
                break;

            case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
                cbLength = AceResGetValueLength(pAttrAbs->Values.ppString[i]);
                cbTotalLength = cbTotalLength + ALIGN_TO_SIZE(cbLength, sizeof(DWORD));
                break;

            default:
                assert(false);
                break;
        }
    }
    return cbTotalLength;
}

//-----------------------------------------------------------------------------
// Local functions - capturing values

static LPWSTR AceResCaptureString(PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 pAttrRel, ULONG Offset, ULONG cbAttrRel, PULONG pcbLength)
{
    LPBYTE pbStructure = (LPBYTE)(pAttrRel);
    LPBYTE pbString = pbStructure + Offset;
    LPBYTE pbPtr;
    LPBYTE pbEnd = pbStructure + cbAttrRel;
    ULONG cbLength;

    // Parse the string
    for(pbPtr = pbString; pbPtr < pbEnd; pbPtr += sizeof(WCHAR))
    {
        if(*(WCHAR *)(pbPtr) == 0)
        {
            // Calculate ther length of the string
            cbLength = (ULONG)(pbPtr - pbString) + sizeof(WCHAR);

            // Give the string to the caller
            if(pcbLength != NULL)
                pcbLength[0] = cbLength;
            return (LPWSTR)(pbString);
        }
    }
    return NULL;
}

template <typename ELEMENT>
DWORD AceResCaptureElement(LPBYTE pbPtr, LPBYTE pbEnd, ELEMENT & Element, ULONG Offset)
{
    if((pbPtr + Offset + sizeof(ELEMENT)) > pbEnd)
        return ERROR_BUFFER_OVERFLOW;

    Element = *(ELEMENT *)(pbPtr + Offset);
    return ERROR_SUCCESS;
}

PULONG64 AceResCaptureArray(LPBYTE pbPtr, LPBYTE pbEnd, PULONG Array, ULONG Count, PULONG pcbMaxOffset)
{
    PULONG64 ValueArray;
    DWORD dwErrCode;
    ULONG cbMaxOffset = 0;

    if((ValueArray = new ULONG64[Count]) != NULL)
    {
        for(ULONG i = 0; i < Count; i++)
        {
            // Capture the element
            dwErrCode = AceResCaptureElement(pbPtr, pbEnd, ValueArray[i], Array[i]);
            if(dwErrCode != ERROR_SUCCESS)
            {
                SetLastError(dwErrCode);
                delete [] ValueArray;
                ValueArray = NULL;
                break;
            }

            // Move the max offset
            if((Array[i] + sizeof(ULONG64)) > cbMaxOffset)
            {
                cbMaxOffset = Array[i] + sizeof(ULONG64);
            }
        }
    }
    else
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    }

    // Give the result to the caller
    if(pcbMaxOffset != NULL)
        pcbMaxOffset[0] = cbMaxOffset;
    return ValueArray;
}

//-----------------------------------------------------------------------------
// Local functions - writing values

// For conversion from absolute to relative
static LPBYTE AceResWriteString(LPBYTE pbPtr, LPBYTE pbEnd, LPWSTR & szValue)
{
    size_t cbStringRaw = AceResGetValueLength(szValue);
    size_t cbString = ALIGN_TO_SIZE(cbStringRaw, sizeof(DWORD));

    // Check if there is enough space
    if((pbPtr + cbString) > pbEnd)
        return NULL;

    memmove(pbPtr, szValue, cbStringRaw);
    return pbPtr + cbString;
}

// For conversion from relative to absolute
static LPWSTR AceResWriteString(LPBYTE pbPtr, LPBYTE pbEnd, LPCWSTR szString, size_t cbString)
{
    // Check if there is enough space
    if((pbPtr + cbString) > pbEnd)
        return NULL;

    memmove(pbPtr, szString, cbString);
    return (LPWSTR)(pbPtr);
}

static LPBYTE AceResWriteValue(LPBYTE pbPtr, LPBYTE pbEnd, ULONG64 & Value)
{
    if((pbPtr + sizeof(ULONG)) > pbEnd)
        return NULL;

    *(PULONG64)(pbPtr) = Value;
    return pbPtr + sizeof(ULONG64);
}

static PULONG64 AceResWriteValue(LPBYTE pbPtr, LPBYTE pbEnd, PULONG64 pValue, LPBYTE pbUint64)
{
    // Check if there is enough space
    if((pbPtr + sizeof(ULONG64)) > pbEnd)
        return NULL;

    memcpy(pValue, pbUint64, sizeof(ULONG64));
    return pValue;
}

//-----------------------------------------------------------------------------
// Public functions

PCLAIM_SECURITY_ATTRIBUTE_V1 ClaimSecurityAttributeRel2Abs(
    PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 pAttrRel,
    ULONG cbAttrRel,
    PULONG pcbMoveBy)
{
    PCLAIM_SECURITY_ATTRIBUTE_V1 pAttrAbs = NULL;
    LPWSTR szStringValue;
    LPWSTR szName = NULL;
    ULONG cbBase = FIELD_OFFSET(CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1, Values) + pAttrRel->ValueCount * sizeof(ULONG);
    ULONG cbNameRaw = 0;
    ULONG cbName = 0;
    ULONG cbValues = 0;
    ULONG cbMax = cbBase;

    // The size of the base structure must not be greater than the total size
    if(cbBase < cbAttrRel)
    {
        // Read the attribute name
        if((szName = AceResCaptureString(pAttrRel, pAttrRel->Name, cbAttrRel, &cbNameRaw)) == NULL)
        {
            SetLastError(ERROR_BAD_FORMAT);
            return NULL;
        }

        // Get the length of each value
        for(ULONG i = 0; i < pAttrRel->ValueCount; i++)
        {
            ULONG cbValue = 0;

            switch(pAttrRel->ValueType)
            {
                case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
                case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
                    cbValues += sizeof(ULONG64);
                    break;

                case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
                    if((szStringValue = AceResCaptureString(pAttrRel, pAttrRel->Values.ppString[i], cbAttrRel, &cbValue)) == NULL)
                    {
                        SetLastError(ERROR_BAD_FORMAT);
                        return NULL;
                    }
                    cbValues = cbValues + sizeof(LPWSTR) + ALIGN_TO_SIZE(cbValue, sizeof(void *));
                    break;

                default:
                    assert(false);
                    break;
            }
        }

        // Align the name length to size of pointer
        cbName = ALIGN_TO_SIZE(cbNameRaw, sizeof(void *));

        // Allocate buffer for the whole structure
        pAttrAbs = (PCLAIM_SECURITY_ATTRIBUTE_V1)LocalAlloc(LPTR, sizeof(CLAIM_SECURITY_ATTRIBUTE_V1) + cbName + cbValues);
        if(pAttrAbs != NULL)
        {
            LPBYTE pbStructure = (LPBYTE)(pAttrRel);
            LPBYTE pbPtr = (LPBYTE)(pAttrAbs) + sizeof(CLAIM_SECURITY_ATTRIBUTE_V1);
            LPBYTE pbEnd = pbPtr + cbName + cbValues;

            // Copy the structure members
            pAttrAbs->ValueType = pAttrRel->ValueType;
            pAttrAbs->Reserved = pAttrRel->Reserved;
            pAttrAbs->Flags = pAttrRel->Flags;
            pAttrAbs->ValueCount = pAttrRel->ValueCount;
            
            // Copy the attribute name
            if(szName && cbName)
            {
                // Set the max value
                cbMax = max(cbMax, pAttrRel->Name + cbNameRaw);

                // Write the string
                pAttrAbs->Name = AceResWriteString(pbPtr, pbEnd, szName, cbNameRaw);
                pbPtr += cbName;
            }

            // Copy the values
            for(ULONG i = 0; i < pAttrRel->ValueCount; i++)
            {
                ULONG cbValue = 0;

                switch(pAttrRel->ValueType)
                {
                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
                    {
                        // Initialize the value for the QWORDS
                        if(pAttrAbs->Values.pUint64 == NULL)
                            pAttrAbs->Values.pUint64 = (PDWORD64)(pbPtr);

                        // Set the max value
                        cbMax = max(cbMax, pAttrRel->Values.pUint64[i] + sizeof(ULONG64));

                        // Write the ULONG64
                        if(AceResWriteValue(pbPtr, pbEnd, pAttrAbs->Values.pUint64 + i, pbStructure + pAttrRel->Values.pUint64[i]) == NULL)
                        {
                            SetLastError(ERROR_BAD_FORMAT);
                            return NULL;
                        }
                        break;
                    }

                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
                    {
                        PWSTR szString = AceResCaptureString(pAttrRel, pAttrRel->Values.ppString[i], cbAttrRel, &cbValue);

                        // Initialize the value for the strings
                        if(pAttrAbs->Values.ppString == NULL)
                        {
                            pAttrAbs->Values.ppString = (LPWSTR *)(pbPtr);
                            pbPtr = pbPtr + pAttrAbs->ValueCount * sizeof(LPWSTR);
                        }

                        pAttrAbs->Values.ppString[i] = AceResWriteString(pbPtr, pbEnd, szString, cbValue);
                        if(pAttrAbs->Values.ppString[i] == NULL)
                        {
                            SetLastError(ERROR_BAD_FORMAT);
                            return NULL;
                        }

                        // Set the max value
                        cbMax = max(cbMax, pAttrRel->Values.ppString[i] + cbValue);
                        pbPtr += cbValue;
                        break;
                    }

                    default:
                    {
                        assert(false);
                        break;
                    }
                }
            }
        }
    }
    else
    {
        SetLastError(ERROR_BAD_FORMAT);
    }

    // Give all values
    if(pAttrAbs != NULL && pcbMoveBy != NULL)
        pcbMoveBy[0] = ALIGN_TO_SIZE(cbMax, sizeof(DWORD));
    return pAttrAbs;
}

PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 ClaimSecurityAttributeAbs2Rel(
    PCLAIM_SECURITY_ATTRIBUTE_V1 pAttrAbs,
    PULONG pcbLength)
{
    PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 pAttrRel = NULL;
    ULONG cbBase = FIELD_OFFSET(CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1, Values) + pAttrAbs->ValueCount * sizeof(ULONG);
    ULONG cbName = 0;
    ULONG cbValues = 0;
    ULONG cbNameRaw = 0;

    // Calculate length of the attribute name.
    if(pAttrAbs->Name)
    {
        cbNameRaw = AceResGetValueLength(pAttrAbs->Name);
        cbName = ALIGN_TO_SIZE(cbNameRaw, sizeof(DWORD));
    }

    // Calculate length of the attribute values
    if(pAttrAbs->ValueCount)
    {
        cbValues = AceResGetValuesLength(pAttrAbs);
        cbValues = ALIGN_TO_SIZE(cbValues, sizeof(DWORD));
    }

    // Allocate buffer
    pAttrRel = (PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1)LocalAlloc(LPTR, cbBase + cbName + cbValues);
    if(pAttrRel != NULL)
    {
        LPBYTE pbStructure = (LPBYTE)(pAttrRel);
        LPBYTE pbPtr = pbStructure + cbBase;
        LPBYTE pbEnd = pbStructure + cbBase + cbName + cbValues;

        // Copy the base structure
        pAttrRel->ValueType  = pAttrAbs->ValueType;
        pAttrRel->Reserved   = pAttrAbs->Reserved;
        pAttrRel->Flags      = pAttrAbs->Flags;
        pAttrRel->ValueCount = pAttrAbs->ValueCount;

        // Copy the string
        if(pAttrAbs->Name)
        {
            memmove(pbPtr, pAttrAbs->Name, cbNameRaw);
            pAttrRel->Name = (ULONG)(pbPtr - pbStructure);
            pbPtr += cbName;
        }

        // Copy values
        for(ULONG i = 0; i < pAttrAbs->ValueCount; i++)
        {
            // Write the value offset
            pAttrRel->Values.pInt64[i] = (ULONG)(pbPtr - pbStructure);

            // Write the value itself
            switch(pAttrAbs->ValueType)
            {
                case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
                case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
                    if((pbPtr = AceResWriteValue(pbPtr, pbEnd, pAttrAbs->Values.pUint64[i])) == NULL)
                        assert(false);
                    break;

                case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
                    if((pbPtr = AceResWriteString(pbPtr, pbEnd, pAttrAbs->Values.ppString[i])) == NULL)
                        assert(false);
                    break;

                default:
                    assert(false);
                    break;
            }
        }
    }

    // Give the result to the caller
    if(pcbLength != NULL)
        pcbLength[0] = cbBase + cbName + cbValues;
    return pAttrRel;
}
