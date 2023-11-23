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

#define CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING    0x03

//
//  Fully-qualified binary name.
//

typedef struct _CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE
{
    DWORD64             Version;
    PWSTR               Name;
} CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE, * PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE;

#define CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN      0x04

#define CLAIM_SECURITY_ATTRIBUTE_TYPE_SID       0x05

#define CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN   0x06


typedef struct _CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
{
    PVOID   pValue;         //  Pointer is BYTE aligned.
    DWORD   ValueLength;    //  In bytes
} CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE,
* PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

#define CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING  0x10

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

//
//  An individual security attribute.
//

typedef struct _CLAIM_SECURITY_ATTRIBUTE_V1
{
    PWSTR   Name;               // Name of the attribute. Case insensitive Unicode string.
    WORD    ValueType;          // Data type of attribute.
    WORD    Reserved;           // Must be zero
    DWORD   Flags;              // Attribute Flags
    DWORD   ValueCount;         // Number of values.

    // The actual value itself.
    union
    {
        PLONG64                                      pInt64;
        PDWORD64                                     pUint64;
        PWSTR * ppString;
        PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE         pFqbn;
        PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
    } Values;
} CLAIM_SECURITY_ATTRIBUTE_V1, * PCLAIM_SECURITY_ATTRIBUTE_V1;

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
} CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1, * PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1;

#endif

//-----------------------------------------------------------------------------
// Helpers

PCLAIM_SECURITY_ATTRIBUTE_V1 ClaimSecurityAttributeRel2Abs(
    LPBYTE pbPtr,
    LPBYTE pbEnd,
    PULONG pcbMoveBy
    );

#endif // __ACE_RESOURCE_H__
