/*****************************************************************************/
/* AceCondition.cpp                       Copyright (c) Ladislav Zezula 2023 */
/*---------------------------------------------------------------------------*/
/* Description:                                                              */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 26.10.23  1.00  Lad  Created                                              */
/*****************************************************************************/

#include "FileTest.h"

LPCTSTR HexaAlphabetLower = _T("0123456789abcdef");

static const CONDITION_OPERATOR Operators[] =
{
    {L"Exists",                     CTOKEN_EXISTS,                   0x14, true,  true,  false, true,  true},
    {L"Not_Exists",                 CTOKEN_NOT_EXISTS,               0x14, true,  true,  false, true,  true},
    {L"==",                         CTOKEN_EQUAL,                    0x0F, false, false, true,  true,  false},
    {L">=",                         CTOKEN_GREATER_THAN_OR_EQUAL,    0x0F, false, false, true,  true,  false},
    {L"!=",                         CTOKEN_NOT_EQUAL,                0x0F, false, false, true,  true,  false},
    {L"<=",                         CTOKEN_LESS_THAN_OR_EQUAL,       0x0F, false, false, true,  true,  false},
    {L"&&",                         CTOKEN_AND,                      0x0C, false, true,  false, false, false},
    {L"||",                         CTOKEN_OR,                       0x0B, false, true,  false, false, false},
    {L"&",                          CTOKEN_BIT_AND,                  0x0A, false, false, true,  true,  false},
    {L"<",                          CTOKEN_LESS_THAN,                0x0F, false, false, true,  true,  false},
    {L">",                          CTOKEN_GREATER_THAN,             0x0F, false, false, true,  true,  false},
    {L"Contains",                   CTOKEN_CONTAINS,                 0x0F, false, false, true,  true,  true},
    {L"Not_Contains",               CTOKEN_NOT_CONTAINS,             0x0F, false, false, true,  true,  true},
    {L"Any_of",                     CTOKEN_ANY_OF,                   0x0F, false, false, true,  true,  true},
    {L"Not_Any_of",                 CTOKEN_NOT_ANY_OF,               0x0F, false, false, true,  true,  true},
    {L"!",                          CTOKEN_NOT,                      0x0D, true,  true,  false, true,  false},
    {L"Member_of",                  CTOKEN_MEMBER_OF,                0x0F, true,  true,  false, true,  true},
    {L"Not_Member_of",              CTOKEN_NOT_MEMBER_OF,            0x0F, true,  true,  false, true,  true},
    {L"Device_Member_of",           CTOKEN_DEVICE_MEMBER_OF,         0x0F, true,  true,  false, true,  true},
    {L"Not_Device_Member_of",       CTOKEN_NOT_DEVICE_MEMBER_OF,     0x0F, true,  true,  false, true,  true},
    {L"Member_of_any",              CTOKEN_MEMBER_OF_ANY,            0x0F, true,  true,  false, true,  true},
    {L"Not_Member_of_any",          CTOKEN_NOT_MEMBER_OF_ANY,        0x0F, true,  true,  false, true,  true},
    {L"Device_Member_of_any",       CTOKEN_DEVICE_MEMBER_OF_ANY,     0x0F, true,  true,  false, true,  true},
    {L"Not_Device_Member_of_any",   CTOKEN_NOT_DEVICE_MEMBER_OF_ANY, 0x0F, true,  true,  false, true,  true},
};

static NTSTATUS UlongAddStringSize(ULONG cbValue, LPCWSTR szString, ULONG * pcbNewValue)
{
    ULONG ccString = (ULONG)(wcslen(szString));
    ULONG cbString;

    // Check overflows
    if((cbString = ccString * sizeof(WCHAR)) < ccString)
        return STATUS_INTEGER_OVERFLOW;
    if((cbValue + cbString) < cbValue)
        return STATUS_INTEGER_OVERFLOW;

    // Perform the addition
    pcbNewValue[0] = cbValue + cbString;
    return STATUS_SUCCESS;
}

static bool IsEncodedAttributeChar(UINT ch)
{
    LPCWSTR NotEncodedAttributeChar = L"#$\"*+-./:;?@[\\]^_`{}~";

    // 0x7F and above are encoded
    if(ch < 0x7F)
    {
        // Alphanumeric chars are NOT encoded
        if(isalnum(ch))
            return false;

        // Exceptions
        for(size_t i = 0; NotEncodedAttributeChar[i] != 0; i++)
        {
            if(ch == NotEncodedAttributeChar[i])
                return false;
        }
    }
    return true;
}

static int GetOperatorIndexByToken(ACE_CONDITION_TOKEN TokenCode)
{
    for(int i = 0; i < _countof(Operators); i++)
    {
        if(Operators[i].TokenCode == TokenCode)
        {
            return i;
        }
    }
    return -1;
}

static DWORD EncodeAttributeName(
    LPWSTR Value,
    DWORD ValueSize,
    LPTSTR * EncodedString)
{
    LPTSTR szAttributeName;
    size_t nCharsCopied = 0;

    // Carefully verify all parameters
    if(Value == NULL || ValueSize == 0 || EncodedString == NULL || ValueSize & 0x01)
        return ERROR_INVALID_ACL;

    // Allocate buffer large enough for encoded attribute name
    EncodedString[0] = szAttributeName = (LPTSTR)LocalAlloc(LPTR, (ValueSize * 5) + sizeof(WCHAR));
    if(szAttributeName == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    // Get the number of chars
    for(DWORD i = 0; i < ValueSize; i += sizeof(WCHAR))
    {
        WCHAR chCharacter = Value[i];

        // Encoded chars are going to be turned into %ABCD
        if(IsEncodedAttributeChar(chCharacter))
        {
            szAttributeName[nCharsCopied++] = '%';
            szAttributeName[nCharsCopied++] = HexaAlphabetLower[(chCharacter >> 0x0C) & 0x0F];
            szAttributeName[nCharsCopied++] = HexaAlphabetLower[(chCharacter >> 0x08) & 0x0F];
            szAttributeName[nCharsCopied++] = HexaAlphabetLower[(chCharacter >> 0x04) & 0x0F];
            szAttributeName[nCharsCopied++] = HexaAlphabetLower[(chCharacter >> 0x00) & 0x0F];
        }
        
        // Non-encoded chars are copied as-is
        else
        {
            szAttributeName[nCharsCopied++] = chCharacter;
        }
    }

    // No need to terminate with zero, because it was allocated as LPTR
    return ERROR_SUCCESS;
}

static DWORD EncloseSubCondition(LPWSTR * ConditionStr)
{
    LPWSTR szSubCondition = ConditionStr[0];
    LPWSTR szNewCondition;
    size_t ccSubCondition;
    size_t ccNewCondition;
    size_t cbNewCondition;

    // Enclose the subcondition into parentheses, if not done yet
    if(szSubCondition[0] != L'(')
    {
        // Calculate new length
        ccSubCondition = wcslen(szSubCondition);

        // Verify buffer overflow
        if((ccNewCondition = ccSubCondition + 3) < ccSubCondition)
            return ERROR_ARITHMETIC_OVERFLOW;
        if((cbNewCondition = ccNewCondition * sizeof(WCHAR)) < ccNewCondition)
            return ERROR_ARITHMETIC_OVERFLOW;

        // Allocate new buffer
        if((szNewCondition = (LPWSTR)LocalAlloc(LPTR, cbNewCondition)) == NULL)
            return ERROR_NOT_ENOUGH_MEMORY;

        // Format the new buffer
        if(FAILED(StringCbPrintf(szNewCondition, cbNewCondition, L"(%ls)", szSubCondition)))
        {
            LocalFree(szNewCondition);
            return ERROR_NOT_SUPPORTED;
        }

        // Given the new condition to the caller
        ConditionStr[0] = szNewCondition;
        LocalFree(szSubCondition);
    }
    return ERROR_SUCCESS;
}

static DWORD MergeAttributeName(LPCWSTR szPrefix, size_t cbPrefixSize, LPCWSTR szData, size_t cbDataSize, LPWSTR * StrResult)
{
    LPWSTR szAttributeName = NULL;
    size_t cbFullName = cbPrefixSize + cbDataSize + sizeof(WCHAR);

    // Allocate the buffer for the token attribute
    StrResult[0] = szAttributeName = (LPWSTR)LocalAlloc(LPTR, cbFullName);
    if(szAttributeName != NULL)
    {
        // Append prefix, if any
        if(szPrefix && cbPrefixSize)
            memcpy(szAttributeName, szPrefix, cbPrefixSize);
        szAttributeName += (cbPrefixSize / sizeof(WCHAR));

        // Append data, if any
        if(szData && cbDataSize)
            memcpy(szAttributeName, szData, cbDataSize);
        szAttributeName += (cbDataSize / sizeof(WCHAR));

        // Terminate with zero
        szAttributeName[0] = 0;
        return ERROR_SUCCESS;
    }
    else
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}

static DWORD GetPrintableAttributeName(
    LPBYTE Condition,
    ULONG  ConditionSize,
    ACE_CONDITION_TOKEN Token,
    LPTSTR * ValueStr,
    DWORD * MoveBy)
{
    #define WSTRSZ(wsz)(sizeof(L##wsz) - sizeof(WCHAR))

    LPTSTR szAttributeName = NULL;
    DWORD cbDataSize;
    DWORD dwErrCode;

    // Verify parameters
    if(Condition == NULL || ValueStr == NULL)
        return ERROR_INVALID_PARAMETER;

    // Read the data length and get the pointer to data
    if(ConditionSize <= 5)
        return ERROR_INVALID_ACL;
    cbDataSize = *(LPDWORD)(Condition + 1);
    Condition += 5;

    // Encode any other attribute than CTOKEN_LOCAL_ATTRIBUTE
    if(Token != CTOKEN_LOCAL_ATTRIBUTE)
    {
        LPTSTR szEncodedName = NULL;
        size_t cbEncodedName;

        dwErrCode = EncodeAttributeName((LPWSTR)(Condition), cbDataSize, &szEncodedName);
        if(dwErrCode == ERROR_SUCCESS)
        {
            // Get the byte length
            cbEncodedName = wcslen(szEncodedName) * sizeof(TCHAR) + sizeof(TCHAR);

            // Perform merge of the attribute name
            switch(Token)
            {
                case CTOKEN_USER_ATTRIBUTE:
                    dwErrCode = MergeAttributeName(L"@USER.", WSTRSZ("@USER."), szEncodedName, cbEncodedName, ValueStr);
                    break;

                case CTOKEN_RESOURCE_ATTRIBUTE:
                    dwErrCode = MergeAttributeName(L"@RESOURCE.", WSTRSZ("@RESOURCE."), szEncodedName, cbEncodedName, ValueStr);
                    break;

                case CTOKEN_DEVICE_ATTRIBUTE:
                    dwErrCode = MergeAttributeName(L"@DEVICE.", WSTRSZ("@DEVICE."), szEncodedName, cbEncodedName, ValueStr);
                    break;

                case CTOKEN_TOKEN_ATTRIBUTE:
                    dwErrCode = MergeAttributeName(L"@TOKEN.", WSTRSZ("@TOKEN."), szEncodedName, cbEncodedName, ValueStr);
                    break;
            }

            // Free the encoded attribute name
            LocalFree(szAttributeName);
        }
    }
    else
    {
        dwErrCode = MergeAttributeName(NULL, 0, (LPCWSTR)(Condition), cbDataSize, ValueStr);
    }

    // Write the bytes eaten
    if(dwErrCode == ERROR_SUCCESS && MoveBy != NULL)
        MoveBy[0] = cbDataSize + 5;
    return dwErrCode;
}

static DWORD GetStringForInteger(
    LPBYTE Condition,
    DWORD ConditionSize,
    LPWSTR * ValueStr,
    DWORD * MoveBy)
{
    ACE_CONDITION_TOKEN TokenCode;
    LONG64 IntValue;
    LPWSTR szIntegerValue = NULL;
    HRESULT hr;
    BYTE NumFormat;
    BYTE SignByte;

    // Read the length of the condition
    if((ConditionSize - 1) < 0x0A)
        return ERROR_INVALID_ACL;
    TokenCode = (ACE_CONDITION_TOKEN)(Condition[0]);
    MoveBy[0] = 0x0A;

    // Read the integer value, sign byte and format byte
    // Note that the integer value is always 64-bit, regardless
    // of which CTOKEN_INT## is used.
    IntValue = *(ULONG64 *)(Condition + 1);
    SignByte = Condition[0x09];
    NumFormat = Condition[0x0A];

    // Allocate buffer for the largest possible integer
    if((ValueStr[0] = szIntegerValue = (LPWSTR)LocalAlloc(LPTR, 0x40)) == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    // Check the sign value
    switch(SignByte)
    {
        case 1: *szIntegerValue++ = L'+'; break;
        case 2: *szIntegerValue++ = L'-'; IntValue = -IntValue; break;
    }

    // Perform format-specific printf
    switch(NumFormat)
    {
        case 1:
            hr = StringCbPrintf(szIntegerValue, 0x40, _T("%I64o"), IntValue);
            break;

        case 3:
            hr = StringCbPrintf(szIntegerValue, 0x40, _T("0x%I64x"), IntValue);
            break;

        default:
            hr = StringCbPrintf(szIntegerValue, 0x40, _T("%I64u"), IntValue);
            break;
    }

    // Check for failed printf operation
    if(FAILED(hr))
    {
        LocalFree(ValueStr[0]);
        return ERROR_NOT_SUPPORTED;
    }

    return ERROR_SUCCESS;
}


static void GetStringForOctetString(LPWSTR szBuffer, LPBYTE pbOctetString, ULONG cbOctetString)
{
    LPBYTE pbEndOfString = pbOctetString + cbOctetString;

    // Prefix the converted string with hashtag
    *szBuffer++ = '#';

    // Convert to hexa string
    while(pbOctetString < pbEndOfString)
    {
        szBuffer[0] = HexaAlphabetLower[(pbOctetString[0] >> 0x04) & 0x0F];
        szBuffer[1] = HexaAlphabetLower[(pbOctetString[0] >> 0x00) & 0x0F];

        pbOctetString++;
        szBuffer += 2;
    }

    // Terminate buffer with zero
    szBuffer[0] = 0;
}

static DWORD LocalGetStringForSid(
    PSID pSid,
    LPWSTR * String,
    void * RootDomainSid,
    void * DomainSid,
    PSTRSD_SID_LOOKUP tSidLookupDomOrRootDomRelativeTable,
    BOOL DefaultToDomain)
{
    UNREFERENCED_PARAMETER(tSidLookupDomOrRootDomRelativeTable);
    UNREFERENCED_PARAMETER(DefaultToDomain);
    UNREFERENCED_PARAMETER(RootDomainSid);
    UNREFERENCED_PARAMETER(DomainSid);

    // Verify parameters
    if(pSid == NULL || String == NULL)
        return ERROR_INVALID_PARAMETER;

    //
    // Here, we skip the call to LookupSidInTable, because we don't have
    // a lookup table, so we would only spend lots of time disassembling
    //

    if(!ConvertSidToStringSidW(pSid, String))
        return GetLastError();
    return ERROR_SUCCESS;
}

static DWORD GetPrintableOperandValue(
    LPBYTE Condition,
    DWORD ConditionSize,
    LPWSTR * ValueStr,
    DWORD * MoveBy,
    void * RootDomainSid,
    void * DomainSid,
    PSTRSD_SID_LOOKUP tSidLookupDomOrRootDomRelativeTable,
    BOOL DefaultToDomain)
{
    LPWSTR szOperandValue = NULL;
    LPWSTR szBuffer = NULL;
    size_t cbOperandValue;
    DWORD dwErrCode = ERROR_SUCCESS;
    DWORD cbDataSize = 0;
    BYTE SidBuffer[MAX_SID_LENGTH];
    ACE_CONDITION_TOKEN TokenCode;

    // Carefully check parameters
    if(Condition == NULL || ValueStr == NULL || ConditionSize == 0)
        return ERROR_INVALID_PARAMETER;
    MoveBy[0] = 1;

    // Token-specific
    switch(TokenCode = (ACE_CONDITION_TOKEN)(Condition[0]))
    {
        case CTOKEN_PAD:                // 0x00
            dwErrCode = ERROR_INVALID_ACL;
            break;

        case CTOKEN_INT8:               // 0x01
        case CTOKEN_INT16:              // 0x02
        case CTOKEN_INT32:              // 0x03
        case CTOKEN_INT64:              // 0x04
            if((dwErrCode = GetStringForInteger(Condition, ConditionSize, ValueStr, &cbDataSize)) == ERROR_SUCCESS)
                MoveBy[0] = MoveBy[0] + 10;
            break;

        case CTOKEN_UNICODE_STRING:     // 0x10

            // Read the length of the unicode string
            if((ConditionSize - 1) < 4)
                return ERROR_INVALID_ACL;
            cbDataSize = *(DWORD *)(Condition + 1);

            // Check the length of the SID and data
            if((ConditionSize - 5) < cbDataSize)
                return ERROR_INVALID_ACL;
            MoveBy[0] = 5;

            // Check overflow
            if((cbOperandValue = cbDataSize + 6) < cbDataSize)
                return ERROR_ARITHMETIC_OVERFLOW;

            // Allocate buffer
            ValueStr[0] = szOperandValue = (LPWSTR)LocalAlloc(LPTR, cbOperandValue);
            if(szOperandValue == NULL)
            {
                dwErrCode = ERROR_NOT_ENOUGH_MEMORY;
                break;
            }

            // Enclose the string into quotation marks
            *szOperandValue++ = _T('\"');
            memcpy(szOperandValue, Condition + 5, cbDataSize);
            szOperandValue[cbDataSize / sizeof(WCHAR)] = _T('\"');
            
            // Increment the number of bytes processed and return
            MoveBy[0] = MoveBy[0] + cbDataSize;
            break;

        case CTOKEN_OCTET_STRING:       // 0x18

            // Read the length of the octet string
            if((ConditionSize - 1) < 4)
                return ERROR_INVALID_ACL;
            cbDataSize = *(DWORD *)(Condition + 1);

            // Check the length of the octet string
            if((ConditionSize - 5) < cbDataSize)
                return ERROR_INVALID_ACL;
            MoveBy[0] = 5;

            // Length of the octet string must not be 0
            if(cbDataSize == 0)
                return ERROR_INVALID_ACL;

            // Check overflow
            if((cbOperandValue = (cbDataSize + cbDataSize + 2) * sizeof(WCHAR)) < cbDataSize)
                return ERROR_ARITHMETIC_OVERFLOW;

            // Allocate buffer
            ValueStr[0] = szOperandValue = (LPWSTR)LocalAlloc(LPTR, cbOperandValue);
            if(szOperandValue == NULL)
            {
                dwErrCode = ERROR_NOT_ENOUGH_MEMORY;
                break;
            }

            // Encode the string into HEX
            GetStringForOctetString(szOperandValue, Condition + 5, cbDataSize);

            // Increment the number of bytes processed and return
            MoveBy[0] = MoveBy[0] + cbDataSize;
            break;

        case CTOKEN_COMPOSITE:          // 0x50
        {
            DWORD cbComposite = 0;
            DWORD cbOldValue = 6;
            DWORD cbNewValue;
            DWORD cbMoveBy;

            // Read the length of the composite value
            if((ConditionSize - 1) < 4)
                return ERROR_INVALID_ACL;
            cbDataSize = *(DWORD *)(Condition + 1);

            // Check the length of the composite value
            if((ConditionSize - 5) < cbDataSize)
                return ERROR_INVALID_ACL;
            cbMoveBy = 5;

            // Length of the composite value must not be 0
            if(cbDataSize == 0)
                return ERROR_INVALID_ACL;

            // Allocate buffer for the composite value
            if((ValueStr[0] = szOperandValue = (LPWSTR)LocalAlloc(LPTR, cbOldValue)) == NULL)
            {
                dwErrCode = ERROR_NOT_ENOUGH_MEMORY;
                break;
            }

            // Open the composite string
            szOperandValue[0] = '{';

            // Keep working
            while(cbComposite < cbDataSize)
            {
                // Can't have composite value inside an existing composite value
                if(Condition[cbComposite + cbMoveBy] == CTOKEN_COMPOSITE)
                    return ERROR_INVALID_ACL;

                dwErrCode = GetPrintableOperandValue(Condition + cbComposite + cbMoveBy,
                                                     ConditionSize - cbComposite - cbMoveBy,
                                                    &szBuffer,
                                                     MoveBy,
                                                     RootDomainSid,
                                                     DomainSid,
                                                     tSidLookupDomOrRootDomRelativeTable,
                                                     DefaultToDomain);
                if(dwErrCode != ERROR_SUCCESS)
                    break;
                cbComposite = cbComposite + MoveBy[0];

                // Check for arithmetic overflow
                if(!NT_SUCCESS(UlongAddStringSize(cbOldValue, szBuffer, &cbNewValue)))
                    return ERROR_ARITHMETIC_OVERFLOW;
                if((cbNewValue + 4) < cbNewValue)
                    return ERROR_ARITHMETIC_OVERFLOW;
                cbNewValue = cbNewValue + 4;

                // Enlarge the buffer
                if((ValueStr[0] = szOperandValue = (LPWSTR)LocalReAlloc(ValueStr[0], cbNewValue, LMEM_MOVEABLE)) == NULL)
                {
                    dwErrCode = ERROR_NOT_ENOUGH_MEMORY;
                    break;
                }

                // Format the value part
                if(FAILED(StringCbPrintf(szOperandValue + (cbOldValue - 4) / sizeof(WCHAR), cbNewValue - cbOldValue + 4, _T("%ls, "), szBuffer)))
                {
                    dwErrCode = ERROR_NOT_SUPPORTED;
                    break;
                }

                // Free the buffer
                cbOldValue = cbNewValue;
                LocalFree(szBuffer);
                szBuffer = NULL;
            }

            // Terminate the composite value
            szOperandValue[cbOldValue / sizeof(WCHAR) - 4] = '}';
            szOperandValue[cbOldValue / sizeof(WCHAR) - 3] = 0;
            MoveBy[0] = cbMoveBy + cbComposite;
            break;
        }

        case CTOKEN_SID:                // 0x51
        {
            DWORD cbSidString = 12;     // Length of "SID()\0" in UNICODE

            // Read the length of the SID
            if((ConditionSize - 5) < cbDataSize)
                return ERROR_INVALID_ACL;
            MoveBy[0] = 5;

            // Check the length of the SID and data
            cbDataSize = *(DWORD *)(Condition + 1);
            if(cbDataSize > sizeof(SidBuffer))
                return ERROR_INVALID_ACL;

            // Copy the SID
            memcpy(SidBuffer, Condition + 5, cbDataSize);
            dwErrCode = LocalGetStringForSid(SidBuffer, &szBuffer, RootDomainSid, DomainSid, tSidLookupDomOrRootDomRelativeTable, DefaultToDomain);
            if(dwErrCode != ERROR_SUCCESS)
                break;

            // Check overflow
            if(!NT_SUCCESS(UlongAddStringSize(cbSidString, szBuffer, &cbSidString)))
            {
                dwErrCode = ERROR_ARITHMETIC_OVERFLOW;
                break;
            }

            // Allocate buffer for the operand value
            if((ValueStr[0] = szOperandValue = (LPWSTR)LocalAlloc(LPTR, cbSidString)) == NULL)
            {
                dwErrCode = ERROR_NOT_ENOUGH_MEMORY;
                break;
            }

            // Format the SID into the operand value
            if(FAILED(StringCbPrintf(szOperandValue, cbSidString, _T("SID(%ls)"), szBuffer)))
            {
                dwErrCode = ERROR_NOT_SUPPORTED;
                break;
            }

            // Increment the number of bytes processed and return
            MoveBy[0] = MoveBy[0] + cbDataSize;
            break;
        }

        default:
            dwErrCode = ERROR_INVALID_ACL;
            break;
    }

    // Free the inner buffer and exit
    if(szBuffer != NULL)
        LocalFree(szBuffer);
    return dwErrCode;
}

static DWORD inline LGSFP_Cleanup(
    LPWSTR * OperandArray,
    ULONG dwOperandsLevel0,
    DWORD dwErrCode = ERROR_INVALID_ACL,
    DWORD dwDefErrCode = ERROR_INVALID_ACL)
{
    if(dwOperandsLevel0 != 0)
    {
        if(dwErrCode == ERROR_SUCCESS)
            dwErrCode = dwDefErrCode;
        while(dwOperandsLevel0 > 0)
            LocalFree(OperandArray[dwOperandsLevel0--]);
    }
    return dwErrCode;
}

static DWORD inline LGSFP_CleanupWithFree(
    LPVOID pvPointerToFree,
    LPWSTR * OperandArray,
    ULONG OperandCount,
    DWORD dwErrCode)
{
    if(pvPointerToFree != NULL)
        LocalFree(pvPointerToFree);
    return LGSFP_Cleanup(OperandArray, OperandCount, dwErrCode, ERROR_INVALID_ACL);
}

// advapi32.dll!_LocalpGetStringForCondition@32
// (also aclui.dll!_LocalpGetStringForCondition@32)
DWORD LocalGetStringForCondition(
    LPBYTE Condition,
    DWORD ConditionSize,
    LPWSTR * ConditionStr,
    DWORD * pdwReferencedTokenTypes,
    void * RootDomainSid,
    void * DomainSid,
    PSTRSD_SID_LOOKUP tSidLookupDomOrRootDomRelativeTable,
    bool DefaultToDomain)
{
    LPWSTR OperandArray[MAX_OPERAND_STACK + 2];
    DWORD dwOperandsLevel0 = 0;          // r13d
    DWORD dwOperandsLevel1 = 0;          // r14
    DWORD cbTotalSize;
    DWORD cbTokenSize = 0;
    DWORD dwErrCode = ERROR_SUCCESS;
    ACE_CONDITION_TOKEN TokenCode;

    UNREFERENCED_PARAMETER(pdwReferencedTokenTypes);

    if(Condition == NULL || ConditionStr == NULL || ConditionSize == 0)
        return ERROR_INVALID_PARAMETER;
    if(ConditionSize < 6 || *(LPDWORD)(Condition) != 0x78747261)
        return ERROR_INVALID_ACE_CONDITION;
    cbTotalSize = 4;

    // Keep going as long as we have some data to load
    while((cbTotalSize = cbTotalSize + cbTokenSize) < ConditionSize)
    {
        LPTSTR szTokenName = NULL;

        // Verify the current nest level
        if(dwOperandsLevel1 == MAX_OPERAND_STACK)
            return ERROR_STACK_OVERFLOW;
        cbTokenSize = 0;

        // Take the next byte and examine its meaning
        switch(TokenCode = (ACE_CONDITION_TOKEN)(Condition[cbTotalSize]))
        {
            case CTOKEN_PAD:                        // 0x00

                // Skip all padding bytes
                while(cbTotalSize < ConditionSize && Condition[cbTotalSize] == 0)
                    cbTotalSize++;

                // Are we at the end of the condition?
                if(cbTotalSize != ConditionSize)
                    return LGSFP_Cleanup(OperandArray, dwOperandsLevel0);
                break;

            case CTOKEN_INT8:                       // 0x01
            case CTOKEN_INT16:                      // 0x02
            case CTOKEN_INT32:                      // 0x03
            case CTOKEN_INT64:                      // 0x04
            case CTOKEN_UNICODE_STRING:             // 0x10
            case CTOKEN_OCTET_STRING:               // 0x18
            case CTOKEN_COMPOSITE:                  // 0x50
            case CTOKEN_SID:                        // 0x51
                dwErrCode = GetPrintableOperandValue(Condition + cbTotalSize,
                                                     ConditionSize - cbTotalSize,
                                                    &szTokenName,
                                                    &cbTokenSize,
                                                     RootDomainSid,
                                                     DomainSid,
                                                     tSidLookupDomOrRootDomRelativeTable,
                                                     DefaultToDomain);
                if(dwErrCode != ERROR_SUCCESS)
                    return LGSFP_CleanupWithFree(szTokenName, OperandArray, dwOperandsLevel0, dwErrCode);

                // Insert the operand to the operand array
                OperandArray[++dwOperandsLevel1] = szTokenName;
                dwOperandsLevel0++;
                szTokenName = NULL;
                break;

            case CTOKEN_EQUAL:                      // 0x80
            case CTOKEN_NOT_EQUAL:                  // 0x81
            case CTOKEN_LESS_THAN:                  // 0x82
            case CTOKEN_LESS_THAN_OR_EQUAL:         // 0x83
            case CTOKEN_GREATER_THAN:               // 0x84
            case CTOKEN_GREATER_THAN_OR_EQUAL:      // 0x85
            case CTOKEN_CONTAINS:                   // 0x86
            case CTOKEN_EXISTS:                     // 0x87
            case CTOKEN_ANY_OF:                     // 0x88
            case CTOKEN_MEMBER_OF:                  // 0x89
            case CTOKEN_DEVICE_MEMBER_OF:           // 0x8a
            case CTOKEN_MEMBER_OF_ANY:              // 0x8b
            case CTOKEN_DEVICE_MEMBER_OF_ANY:       // 0x8c
            case CTOKEN_NOT_EXISTS:                 // 0x8d
            case CTOKEN_NOT_CONTAINS:               // 0x8e
            case CTOKEN_NOT_ANY_OF:                 // 0x8f
            case CTOKEN_NOT_MEMBER_OF:              // 0x90
            case CTOKEN_NOT_DEVICE_MEMBER_OF:       // 0x91
            case CTOKEN_NOT_MEMBER_OF_ANY:          // 0x92
            case CTOKEN_NOT_DEVICE_MEMBER_OF_ANY:   // 0x93
            case CTOKEN_AND:                        // 0xa0
            case CTOKEN_OR:                         // 0xa1
            case CTOKEN_NOT:                        // 0xa2
            {
                LPCWSTR szOperator;
                LPWSTR szExpression = NULL;     // rsi
                DWORD cbExpression;
                DWORD cbOperator;
                int nOperatorIndex;

                // For binary operators, there must be at least two operands
                if((TokenCode == CTOKEN_AND || TokenCode == CTOKEN_OR) && (dwOperandsLevel1 < 2))
                    return LGSFP_Cleanup(OperandArray, dwOperandsLevel0);

                // Special for NOT: need to enclose the operand in parentheses
                if(TokenCode == CTOKEN_NOT)
                {
                    if(dwOperandsLevel1 < 1)
                        return LGSFP_Cleanup(OperandArray, dwOperandsLevel0);

                    if((dwErrCode = EncloseSubCondition(&OperandArray[dwOperandsLevel0])) != ERROR_SUCCESS)
                        return LGSFP_Cleanup(OperandArray, dwOperandsLevel0, dwErrCode);
                }

                // Find the operator in the array
                if((nOperatorIndex = GetOperatorIndexByToken(TokenCode)) < 0)
                    return LGSFP_Cleanup(OperandArray, dwOperandsLevel0);
                szOperator = Operators[nOperatorIndex].Op;
                cbOperator = (DWORD)(wcslen(szOperator) * sizeof(WCHAR));

                // Is it an unary operator?
                if(Operators[nOperatorIndex].Unary)
                {
                    LPWSTR szFormatString;
                    LPWSTR szOperand;               // rdi

                    // There must be at least 1 operand
                    if(dwOperandsLevel1 < 1)
                        return LGSFP_Cleanup(OperandArray, dwOperandsLevel0);

                    szOperand = OperandArray[dwOperandsLevel1];
                    if(!NT_SUCCESS(UlongAddStringSize(cbOperator, szOperand, &cbOperator)))
                        return LGSFP_Cleanup(OperandArray, dwOperandsLevel0, ERROR_ARITHMETIC_OVERFLOW);

                    // Allocate expression string
                    if((szExpression = (LPWSTR)LocalAlloc(LPTR, (cbExpression = cbOperator + 8))) == NULL)
                        return LGSFP_Cleanup(OperandArray, dwOperandsLevel0, ERROR_NOT_ENOUGH_MEMORY);

                    // If not CTOKEN_NOT, we need to check operand
                    if(TokenCode != CTOKEN_NOT)
                    {
                        // The operand must NOT contain user, device or token
                        if(TokenCode == CTOKEN_EXISTS || TokenCode == CTOKEN_MEMBER_OF_ANY)
                        {
                            if(!_wcsnicmp(szOperand, L"@USER.", 6) ||
                               !_wcsnicmp(szOperand, L"@TOKEN.", 7) ||
                               !_wcsnicmp(szOperand, L"@DEVICE.", 8))
                            {
                                return LGSFP_CleanupWithFree(szExpression, OperandArray, dwOperandsLevel0, ERROR_INVALID_ACL);
                            }
                        }

                        szFormatString = L"(%ls %ls)";
                    }
                    else
                    {
                        szFormatString = L"(%ls%ls)";
                    }

                    // Format the binary operation
                    if(FAILED(StringCbPrintf(szExpression, cbExpression, szFormatString, szOperator, szOperand)))
                        return LGSFP_Cleanup(OperandArray, dwOperandsLevel0, ERROR_NOT_SUPPORTED);

                    // Replace the current operand with the new one
                    OperandArray[dwOperandsLevel1] = szExpression;
                    LocalFree(szOperand);

                    // Prepare next token
                    cbTokenSize = 1;
                }
                else
                {
                    LPWSTR szOperand1;              // rdi
                    LPWSTR szOperand2;              // r12

                    // There must be at least 2 operands
                    if(dwOperandsLevel1 < 2)
                        return LGSFP_Cleanup(OperandArray, dwOperandsLevel0);

                    // Add size of operator and size of operand2
                    szOperand2 = OperandArray[dwOperandsLevel1];
                    if(!NT_SUCCESS(UlongAddStringSize(cbOperator, szOperand2, &cbOperator)))
                        return LGSFP_Cleanup(OperandArray, dwOperandsLevel0, ERROR_ARITHMETIC_OVERFLOW);

                    // Add size of operator and size of operand1
                    szOperand1 = OperandArray[dwOperandsLevel1 - 1];
                    if(!NT_SUCCESS(UlongAddStringSize(cbOperator, szOperand1, &cbOperator)))
                        return LGSFP_Cleanup(OperandArray, dwOperandsLevel0, ERROR_ARITHMETIC_OVERFLOW);

                    // Allocate expression string
                    if((szExpression = (LPWSTR)LocalAlloc(LPTR, (cbExpression = cbOperator + 10))) == NULL)
                        return LGSFP_Cleanup(OperandArray, dwOperandsLevel0, ERROR_NOT_ENOUGH_MEMORY);

                    // Format the binary operation
                    if(FAILED(StringCbPrintf(szExpression, cbExpression, L"(%ls %ls %ls)", szOperand1, szOperator, szOperand2)))
                        return LGSFP_Cleanup(OperandArray, dwOperandsLevel0, ERROR_NOT_SUPPORTED);

                    // Free both operands
                    LocalFree(szOperand2);
                    LocalFree(szOperand1);

                    // Remove operands from the operand array
                    OperandArray[dwOperandsLevel1--] = NULL;
                    OperandArray[dwOperandsLevel1] = szExpression;
                    dwOperandsLevel0--;

                    // Prepare next token
                    cbTokenSize = 1;
                }
                break;
            }

            case CTOKEN_LOCAL_ATTRIBUTE:            // 0xf8
            case CTOKEN_USER_ATTRIBUTE:             // 0xf9
            case CTOKEN_RESOURCE_ATTRIBUTE:         // 0xfa
            case CTOKEN_DEVICE_ATTRIBUTE:           // 0xfb
                dwErrCode = GetPrintableAttributeName(Condition + cbTotalSize,
                                                      ConditionSize - cbTotalSize,
                                                      TokenCode,
                                                     &szTokenName,
                                                     &cbTokenSize);
                if(dwErrCode != ERROR_SUCCESS)
                    return LGSFP_CleanupWithFree(szTokenName, OperandArray, dwOperandsLevel0, dwErrCode);

                // Insert the attribute name to the operand array
                OperandArray[++dwOperandsLevel1] = szTokenName;
                dwOperandsLevel0++;
                szTokenName = NULL;
                break;

            default:
                return LGSFP_Cleanup(OperandArray, dwOperandsLevel0);
        }
    }

    // There must be exactly one final operand at this point
    if(dwOperandsLevel0 != 1)
        return LGSFP_Cleanup(OperandArray, dwOperandsLevel0, ERROR_SUCCESS);
    ConditionStr[0] = OperandArray[1];

    // Make sure that we enclosed the condition into parentheses
    if((dwErrCode = EncloseSubCondition(ConditionStr)) != ERROR_SUCCESS)
        LGSFP_Cleanup(OperandArray, dwOperandsLevel0, dwErrCode);
    return ERROR_SUCCESS;
}
