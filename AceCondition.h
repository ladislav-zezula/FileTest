/*****************************************************************************/
/* AceCondition.h                         Copyright (c) Ladislav Zezula 2023 */
/*---------------------------------------------------------------------------*/
/* Interface to the ACE condition converter                                  */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 26.10.23  1.00  Lad  Created                                              */
/*****************************************************************************/

#ifndef __ACE_CONDITION_H__
#define __ACE_CONDITION_H__

#define MAX_OPERAND_STACK    0xFF
#define MAX_SID_LENGTH       0x44

// Defines related to conditional ACE tokens
typedef enum _ACE_CONDITION_TOKEN
{
    CTOKEN_PAD                      = 0x00,
    CTOKEN_INT8                     = 0x01,     // Has data
    CTOKEN_INT16                    = 0x02,     // Has data
    CTOKEN_INT32                    = 0x03,     // Has data
    CTOKEN_INT64                    = 0x04,     // Has data
    CTOKEN_UNICODE_STRING           = 0x10,     // Has data
    CTOKEN_OCTET_STRING             = 0x18,     // Has data
    CTOKEN_COMPOSITE                = 0x50,     // Has data
    CTOKEN_SID                      = 0x51,     // Has data
    CTOKEN_EQUAL                    = 0x80,
    CTOKEN_NOT_EQUAL                = 0x81,
    CTOKEN_LESS_THAN                = 0x82,
    CTOKEN_LESS_THAN_OR_EQUAL       = 0x83,
    CTOKEN_GREATER_THAN             = 0x84,
    CTOKEN_GREATER_THAN_OR_EQUAL    = 0x85,
    CTOKEN_CONTAINS                 = 0x86,
    CTOKEN_EXISTS                   = 0x87,
    CTOKEN_ANY_OF                   = 0x88,
    CTOKEN_MEMBER_OF                = 0x89,
    CTOKEN_DEVICE_MEMBER_OF         = 0x8a,
    CTOKEN_MEMBER_OF_ANY            = 0x8b,
    CTOKEN_DEVICE_MEMBER_OF_ANY     = 0x8c,
    CTOKEN_NOT_EXISTS               = 0x8d,
    CTOKEN_NOT_CONTAINS             = 0x8e,
    CTOKEN_NOT_ANY_OF               = 0x8f,
    CTOKEN_NOT_MEMBER_OF            = 0x90,
    CTOKEN_NOT_DEVICE_MEMBER_OF     = 0x91,
    CTOKEN_NOT_MEMBER_OF_ANY        = 0x92,
    CTOKEN_NOT_DEVICE_MEMBER_OF_ANY = 0x93,
    CTOKEN_AND                      = 0xa0,
    CTOKEN_OR                       = 0xa1,
    CTOKEN_NOT                      = 0xa2,
    CTOKEN_BIT_AND                  = 0xa3,
    CTOKEN_LOCAL_ATTRIBUTE          = 0xf8,     // Has data
    CTOKEN_USER_ATTRIBUTE           = 0xf9,     // Has data
    CTOKEN_RESOURCE_ATTRIBUTE       = 0xfa,     // Has data
    CTOKEN_DEVICE_ATTRIBUTE         = 0xfb,     // Has data
    CTOKEN_TOKEN_ATTRIBUTE          = 0xfc,     // Has data
} ACE_CONDITION_TOKEN, *PACE_CONDITION_TOKEN;


typedef enum _STRSD_SID_TYPE
{
    ST_DOMAIN_RELATIVE = 0,
    ST_WORLD,
    ST_LOCALSY,
    ST_LOCAL,
    ST_CREATOR,
    ST_NTAUTH,
    ST_BUILTIN,
    ST_ROOT_DOMAIN_RELATIVE,
    ST_LABEL,
    ST_APP_PACKAGE,
    ST_USER_MODE_DRIVER,
    ST_AUTHENTICATION_AUTHORITY,
} STRSD_SID_TYPE, *PSTRSD_SID_TYPE;


typedef struct _STRSD_SID_LOOKUP
{
    bool   Valid;
    USHORT Key[4];
    ULONG  KeyLen;
    void * Sid;
    void * Rid;
    STRSD_SID_TYPE SidType;
    ULONG SidBuff[18];
} STRSD_SID_LOOKUP, *PSTRSD_SID_LOOKUP;


typedef struct _CONDITION_OPERATOR
{
    LPCWSTR Op;
    ACE_CONDITION_TOKEN TokenCode;
    DWORD   Precedence;
    bool    Unary;
    bool    FollowedByAttribute;
    bool    PrecededByAttribute;
    bool    Operational;
    bool    RequiresDelimiter;
} CONDITION_OPERATOR, *PCONDITION_OPERATOR;


// Prototype of the LocalGetStringForCondition inside aclui.dll
typedef DWORD(WINAPI * LGSFC)(
    LPBYTE Condition,
    DWORD ConditionSize,
    LPWSTR * ConditionStr,
    DWORD * pdwReferencedTokenTypes,
    void * RootDomainSid,
    void * DomainSid,
    PSTRSD_SID_LOOKUP tSidLookupDomOrRootDomRelativeTable,
    bool DefaultToDomain);

extern LPCTSTR HexaAlphabetLower;

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
    bool DefaultToDomain
    );

#endif  // __ACE_CONDITION_H__
