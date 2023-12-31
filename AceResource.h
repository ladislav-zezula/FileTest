/*****************************************************************************/
/* AceResource.h                          Copyright (c) Ladislav Zezula 2023 */
/*---------------------------------------------------------------------------*/
/* Helpers for SYSTEM_RESOURCE_ATTRIBUTE_ACE                                 */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 23.11.23  1.00  Lad  Created                                              */
/*****************************************************************************/

#ifndef __ACE_RESOURCE_H__
#define __ACE_RESOURCE_H__

//-----------------------------------------------------------------------------
// Not defined in older SDKs

#ifndef CLAIM_SECURITY_ATTRIBUTE_TYPE_INVALID

#define CLAIM_SECURITY_ATTRIBUTE_TYPE_INVALID   0x00

#define CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64     0x01
#define CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64    0x02

//
//  Case insensitive attribute value string by default.
//  Unless the flag CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE
//  is set indicating otherwise.
//

#define CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING    0x03            // Zero terminated UTF-16 string
#define CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN      0x04            // Refused by Windows up to 11
#define CLAIM_SECURITY_ATTRIBUTE_TYPE_SID       0x05            // 4 bytes of length, followed by the SID
#define CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN   0x06            // Each item has 8 bytes, upper 4 bytes must be zero
#define CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING  0x10        // 4 bytes of length, followed by array of BYTEs

//
// Attribute Flags
//

//
//  Attribute must not be inherited across process spawns.
//

#define CLAIM_SECURITY_ATTRIBUTE_NON_INHERITABLE      0x0001


//
//  Attribute value is compared in a case sensitive way. It is valid with string value
//  or composite type containing string value. For other types of value, this flag
//  will be ignored. Currently, it is valid with the two types:
//  CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING and CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN.
//
#define CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE         0x0002

//
// Attribute is considered only for Deny Aces.
//

#define CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY 0x0004

//
// Attribute is disabled by default.
//

#define CLAIM_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT 0x0008

//
// Attribute is disabled.
//

#define CLAIM_SECURITY_ATTRIBUTE_DISABLED 0x0010

//
// Attribute is mandatory.
//

#define CLAIM_SECURITY_ATTRIBUTE_MANDATORY 0x0020


#define CLAIM_SECURITY_ATTRIBUTE_VALID_FLAGS   (    \
                        CLAIM_SECURITY_ATTRIBUTE_NON_INHERITABLE       |  \
                        CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE  |  \
                        CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY     |  \
                        CLAIM_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT   |  \
                        CLAIM_SECURITY_ATTRIBUTE_DISABLED              |  \
                        CLAIM_SECURITY_ATTRIBUTE_MANDATORY )


//
// Reserve upper 16 bits for custom flags. These should be preserved but not
// validated as they do not affect security in any way.
//
#define CLAIM_SECURITY_ATTRIBUTE_CUSTOM_FLAGS   0xFFFF0000

typedef struct _CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1
{
    DWORD   Name;               // Name of the attribute. Offset from beginning of structure.
    WORD    ValueType;          // Data type of attribute.
    WORD    Reserved;           // Must be 0
    DWORD   Flags;              // Attribute Flags
    DWORD   ValueCount;         // Number of values.

    //  The actual value itself.
    union
    {
        DWORD pInt64[ANYSIZE_ARRAY];
        DWORD pUint64[ANYSIZE_ARRAY];
        DWORD ppString[ANYSIZE_ARRAY];
        DWORD pFqbn[ANYSIZE_ARRAY];
        DWORD pOctetString[ANYSIZE_ARRAY];
    } Values;
} CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1, *PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1;

#endif

//-----------------------------------------------------------------------------
// Octet string structure

typedef struct _ACE_OCTET_STRING
{
    ULONG cbData;
    BYTE  pbData[1];
} ACE_OCTET_STRING, *PACE_OCTET_STRING;

inline size_t OctetStringSize(PACE_OCTET_STRING pOctetString)
{
    return sizeof(ULONG) + pOctetString->cbData;
}

//-----------------------------------------------------------------------------
// Helpers

struct ACE_CSA_OBJECT
{
    ACE_CSA_OBJECT();
    ~ACE_CSA_OBJECT();

    LPBYTE ImportData(LPBYTE pbStructure, LPBYTE pbEnd, size_t Offset, size_t Length);
    LPBYTE ImportOctet(PACE_OCTET_STRING pOctetString);
    void Clear();

    virtual size_t ExportSize(size_t cbAlignSize = 1);
    virtual LPBYTE Export(LPBYTE pbPtr, LPBYTE pbEnd);
    virtual LPBYTE Import(LPCVOID lpObject);

    void * lpData;
    size_t cbData;
};

struct ACE_CSA_DWORD64 : public ACE_CSA_OBJECT
{
    LPBYTE Import(LPCVOID lpObject);
};

struct ACE_CSA_LPWSTR : public ACE_CSA_OBJECT
{
    LPBYTE Import(LPCVOID lpObject);
};

struct ACE_CSA_SID : public ACE_CSA_OBJECT
{
    LPBYTE Import(LPCVOID lpObject);
};

struct ACE_CSA_BOOLEAN : public ACE_CSA_OBJECT
{
    size_t ExportSize(size_t cbAlignSize = 1);
    LPBYTE Import(LPCVOID lpObject);
};

struct ACE_CSA_OCTET_STRING : public ACE_CSA_OBJECT
{
    LPBYTE Import(LPCVOID lpObject);
};

struct ACE_CSA_HELPER
{
    ACE_CSA_HELPER();
    ~ACE_CSA_HELPER();
    void InitialReset();
    void Clear();

    DWORD CreateVA(LPCWSTR szName, WORD ValueType, DWORD ValueCount, va_list argList = NULL);
    DWORD Create(LPCWSTR szName, WORD ValueType, DWORD ValueCount, ...);
    DWORD Import(LPBYTE pbAttrRel, LPBYTE pbAttrEnd, PULONG pcbMoveBy = NULL);

    PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 Export(PULONG pcbLength = NULL);
    LPBYTE ImportObject(LPCVOID lpObject, ULONG nIndex);

    ULONG GetSizeAlignedToMax(LPBYTE pbPtr, LPBYTE pbEnd, ULONG cbLength);
    DWORD AllocateElements();

    ACE_CSA_LPWSTR Name;
    WORD ValueType;
    WORD Reserved;
    DWORD Flags;
    DWORD ValueCount;

    ACE_CSA_OBJECT * ppObjects;
};

#endif // __ACE_RESOURCE_H__
