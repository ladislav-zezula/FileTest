/*****************************************************************************/
/* Page09Security.cpp                     Copyright (c) Ladislav Zezula 2005 */
/*---------------------------------------------------------------------------*/
/* Description :                                                             */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 15.08.05  1.00  Lad  The first version of Page09Security.cpp              */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local variables

#define TREE_ITEM_OWNER             OWNER_SECURITY_INFORMATION
#define TREE_ITEM_GROUP             GROUP_SECURITY_INFORMATION
#define TREE_ITEM_DACL              DACL_SECURITY_INFORMATION
#define TREE_ITEM_SACL              SACL_SECURITY_INFORMATION
#define TREE_ITEM_LABEL             LABEL_SECURITY_INFORMATION
#define TREE_ITEM_SID_NONE          0x10000000      // Under OWNER/GROUP, no SID present
#define TREE_ITEM_SID               0x10000001      // Under OWNER/GROUP: Present SID
#define TREE_ITEM_NULL_ACL          0x10000003      // NULL Acl ("click to create new")
#define TREE_ITEM_EMPTY_ACL         0x10000004      // Empty Acl ("click to create new")
#define TREE_ITEM_ACE               0x20000000      // An ACE. Lower 8 bits indicate the ACE type
#define TREE_ITEM_ACE_HEADER_TYPE   0x30000005      // ACE_HEADER::AceType
#define TREE_ITEM_ACE_HEADER_FLAGS  0x30000006      // ACE_HEADER::AceFlags
#define TREE_ITEM_ACE_HEADER_SIZE   0x30000007      // ACE_HEADER::AceSize
#define TREE_ITEM_ACE_MASK          0x30000008      // ACE::Mask
#define TREE_ITEM_ADS_ACE_MASK      0x30000009      // ACE::Mask for ADS ACEs
#define TREE_ITEM_MANDATORY_MASK    0x3000000A      // ACE::Mask for SYSTEM_MANDATORY_LABEL_ACE
#define TREE_ITEM_MANDATORY_LABEL   0x3000000B      // Integrity level as 32-bit value (SECURITY_MANDATORY_LABEL_AUTHORITY)
#define TREE_ITEM_ACE_FLAGS         0x3000000C      // ACE:Flags
#define TREE_ITEM_COMPOUND_TYPE     0x3000000D      // ACE:CompoundAceType
#define TREE_ITEM_COMPOUND_RESERVED 0x3000000E      // ACE:Reserved
#define TREE_ITEM_ACE_OBJ_GUID      0x3000000F      // ACE:ObjectType
#define TREE_ITEM_ACE_OBJ_GUID2     0x30000010      // ACE:InheritedObjectType
#define TREE_ITEM_SID1_NONE         0x30000011      // The first SID (user/server)
#define TREE_ITEM_SID1              0x30000012      // The first SID (user/server)
#define TREE_ITEM_SID2_NONE         0x30000013      // The first SID (user/server)
#define TREE_ITEM_SID2              0x30000014      // The second SID (client)
#define TREE_ITEM_ACE_CONDITION     0x30000015      // ACE Condition
#define TREE_ITEM_TYPE_MASK         0xF0000000
#define TREE_ITEM_VALUE_MASK        0x0FFFFFFF

#define MAXIMUM_ACL_SIZE            0xFFF8          // The biggest ACL that can possibly exist

typedef enum _ITEM_TYPE
{
    ItemTypeUnknown,
    ItemTypeOwner,                                  // The item contains "OWNER_SECURITY_INFORMATION"
    ItemTypeGroup,                                  // The item contains "GROUP_SECURITY_INFORMATION"
    ItemTypeDacl,                                   // The item contains "DACL_SECURITY_INFORMATION"
    ItemTypeSacl,                                   // The item contains "SACL_SECURITY_INFORMATION"
    ItemTypeNoAcl,                                  // The item says that an ACL is not present
    ItemTypeNullAcl,                                // The item says that the ACL is present but it's NULL
    ItemTypeSid,                                    // The item contains Security Identifier (SID)
    ItemTypeAce,                                    // The item contains Access Control Entry (ACE) from DACL
    ItemTypeUint08,                                 // The item contains 8-bit integer
    ItemTypeUint16,                                 // The item contains 16-bit integer
    ItemTypeUint32,                                 // The item contains 32-bit integer
    ItemTypeUint64,                                 // The item contains 64-bit integer
    ItemTypeGuid,                                   // The item is an object GUID
    ItemTypeGuid2,                                  // The item is an inherited object GUID
    ItemTypeMandSid,                                // The item is a mandatory label SID
    ItemTypeCondition,                              // The item is an ACE condition
} ITEM_TYPE, *PITEM_TYPE;

typedef enum _TREE_ITEM_DATA
{
    ItemDataNULL,                                   // The item's data are NULL
    ItemDataEmpty,                                  // The item's data are empty (example: an empty ACL)
    ItemDataValid,
} TREE_ITEM_DATA, *PTREE_ITEM_DATA;

typedef struct _TREE_ITEM_INFO
{
    ITEM_TYPE ItemType;
    UINT nIDFormat1;                                // Format string when no data
    UINT nIDFormat2;                                // Format string when there are data

    // Array of flag values and flag names
    TFlagInfo * pFlagInfos;

    // Converts the binary item to string representation that will be shown in the tree view item
    bool (*ToString) (const _TREE_ITEM_INFO * pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy);

    // Converts the string representation to binary item
    bool (*StringTo) (const _TREE_ITEM_INFO * pItemInfo, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy);

    // Creates a new item of that type
    bool (*CreateNew)(const _TREE_ITEM_INFO * pItemInfo, LPBYTE pbDataBuffer, size_t * pcbDataBuffer);
    
    // Type of the item data
    TREE_ITEM_DATA ItemData;
} TREE_ITEM_INFO, *PTREE_ITEM_INFO;
typedef const TREE_ITEM_INFO *PCTREE_ITEM_INFO;

typedef struct _ACE_FIELD_INFO
{
    ULONG AceLayoutFlag;
    TREE_ITEM_INFO TreeItem;

} ACE_FIELD_INFO, *PACE_FIELD_INFO;

// Format strings for various item types
static LPCTSTR szUnknownSid      = _T("<UNKNOWN-SID>");
static LPCTSTR szNullAcl         = _T("<NULL ACL. Double-click to create new...>");
static LPCTSTR szEmptyAcl        = _T("<Empty ACL. Double-click to create new...>");
static LPCTSTR szAceHdrFlagsFmt  = _T("AceFlags: 0x%02lX  ");
static LPCTSTR szAceMaskFmt      = _T("Mask: 0x%08lX  ");
static LPCTSTR szIntLevelFmt     = _T("IntLevel: 0x%08lX");
static LPCTSTR szAceFlagsFmt     = _T("Flags: 0x%08lX ");
static LPCTSTR szAceObjTypeFmt   = _T("ObjectType: %s");
static LPCTSTR szAceObjTypeFmt2  = _T("InheritedObjectType: %s");

static LPCTSTR szAceTypeSuffix = _T("_TYPE");

static SID_IDENTIFIER_AUTHORITY SiaNull  = SECURITY_NULL_SID_AUTHORITY;
static SID_IDENTIFIER_AUTHORITY SiaWorld = SECURITY_WORLD_SID_AUTHORITY;
static SID_IDENTIFIER_AUTHORITY SiaLabel = SECURITY_MANDATORY_LABEL_AUTHORITY;

static const ACL EmptyAcl = {ACL_REVISION_DS, 0, sizeof(ACL)};

static TFlagInfo SecurityInformations[] =
{
    FLAGINFO_BITV(OWNER_SECURITY_INFORMATION),
    FLAGINFO_BITV(GROUP_SECURITY_INFORMATION),
    FLAGINFO_BITV(DACL_SECURITY_INFORMATION),
    FLAGINFO_BITV(SACL_SECURITY_INFORMATION),
    FLAGINFO_BITV(LABEL_SECURITY_INFORMATION),
    FLAGINFO_BITV(ATTRIBUTE_SECURITY_INFORMATION),
    FLAGINFO_BITV(SCOPE_SECURITY_INFORMATION),
    FLAGINFO_BITV(PROCESS_TRUST_LABEL_SECURITY_INFORMATION),
    FLAGINFO_BITV(ACCESS_FILTER_SECURITY_INFORMATION),
    FLAGINFO_BITV(BACKUP_SECURITY_INFORMATION),
    FLAGINFO_BITV(PROTECTED_DACL_SECURITY_INFORMATION),
    FLAGINFO_BITV(PROTECTED_SACL_SECURITY_INFORMATION),
    FLAGINFO_BITV(UNPROTECTED_DACL_SECURITY_INFORMATION),
    FLAGINFO_BITV(UNPROTECTED_SACL_SECURITY_INFORMATION),
    FLAGINFO_END()
};


static TFlagInfo AclRevFlags[] =
{
    FLAGINFO_NUMV(ACL_REVISION1),
    FLAGINFO_NUMV(ACL_REVISION2),
    FLAGINFO_NUMV(ACL_REVISION3),
    FLAGINFO_NUMV(ACL_REVISION_DS),
    FLAGINFO_END()
};

static TFlagInfo AceHdrTypes[] =
{
    FLAGINFO_NUMV(ACCESS_ALLOWED_ACE_TYPE),
    FLAGINFO_NUMV(ACCESS_DENIED_ACE_TYPE),
    FLAGINFO_NUMV(SYSTEM_AUDIT_ACE_TYPE),
    FLAGINFO_NUMV(SYSTEM_ALARM_ACE_TYPE),
    FLAGINFO_NUMV(ACCESS_ALLOWED_COMPOUND_ACE_TYPE),
    FLAGINFO_NUMV(ACCESS_ALLOWED_OBJECT_ACE_TYPE),
    FLAGINFO_NUMV(ACCESS_DENIED_OBJECT_ACE_TYPE),
    FLAGINFO_NUMV(SYSTEM_AUDIT_OBJECT_ACE_TYPE),
    FLAGINFO_NUMV(SYSTEM_ALARM_OBJECT_ACE_TYPE),
    FLAGINFO_NUMV(ACCESS_ALLOWED_CALLBACK_ACE_TYPE),
    FLAGINFO_NUMV(ACCESS_DENIED_CALLBACK_ACE_TYPE),
    FLAGINFO_NUMV(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE),
    FLAGINFO_NUMV(ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE),
    FLAGINFO_NUMV(SYSTEM_AUDIT_CALLBACK_ACE_TYPE),
    FLAGINFO_NUMV(SYSTEM_ALARM_CALLBACK_ACE_TYPE),
    FLAGINFO_NUMV(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE),
    FLAGINFO_NUMV(SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE),
    FLAGINFO_NUMV(SYSTEM_MANDATORY_LABEL_ACE_TYPE),
    FLAGINFO_END()
};

static TFlagInfo AceHdrFlags[] =
{
    FLAGINFO_BITV(OBJECT_INHERIT_ACE),
    FLAGINFO_BITV(CONTAINER_INHERIT_ACE),
    FLAGINFO_BITV(NO_PROPAGATE_INHERIT_ACE),
    FLAGINFO_BITV(INHERIT_ONLY_ACE),
    FLAGINFO_BITV(INHERITED_ACE),
    FLAGINFO_BITV(SUCCESSFUL_ACCESS_ACE_FLAG),
    FLAGINFO_BITV(FAILED_ACCESS_ACE_FLAG),
    FLAGINFO_END()
};

static TFlagInfo AceMasks[] =
{
    FLAGINFO_BITV(FILE_READ_DATA),
    FLAGINFO_BITV(FILE_WRITE_DATA),
    FLAGINFO_BITV(FILE_APPEND_DATA),
    FLAGINFO_BITV(FILE_READ_EA),
    FLAGINFO_BITV(FILE_WRITE_EA),
    FLAGINFO_BITV(FILE_EXECUTE),
    FLAGINFO_BITV(FILE_DELETE_CHILD),
    FLAGINFO_BITV(FILE_READ_ATTRIBUTES),
    FLAGINFO_BITV(FILE_WRITE_ATTRIBUTES),
    FLAGINFO_BITV(DELETE),
    FLAGINFO_BITV(READ_CONTROL),
    FLAGINFO_BITV(WRITE_DAC),
    FLAGINFO_BITV(WRITE_OWNER),
    FLAGINFO_BITV(SYNCHRONIZE),
    FLAGINFO_BITV(GENERIC_WRITE),
    FLAGINFO_BITV(GENERIC_READ),
    FLAGINFO_BITV(GENERIC_WRITE),
    FLAGINFO_BITV(GENERIC_EXECUTE),
    FLAGINFO_BITV(GENERIC_ALL),
    FLAGINFO_END()
};

static TFlagInfo AdsAceMasks[] =
{
    FLAGINFO_BITV(ADS_RIGHT_DS_CREATE_CHILD),
    FLAGINFO_BITV(ADS_RIGHT_DS_DELETE_CHILD),
    FLAGINFO_BITV(ADS_RIGHT_ACTRL_DS_LIST),
    FLAGINFO_BITV(ADS_RIGHT_DS_SELF),
    FLAGINFO_BITV(ADS_RIGHT_DS_READ_PROP),
    FLAGINFO_BITV(ADS_RIGHT_DS_WRITE_PROP),
    FLAGINFO_BITV(ADS_RIGHT_DS_DELETE_TREE),
    FLAGINFO_BITV(ADS_RIGHT_DS_LIST_OBJECT),
    FLAGINFO_BITV(ADS_RIGHT_DS_CONTROL_ACCESS),
    FLAGINFO_BITV(ADS_RIGHT_DELETE),
    FLAGINFO_BITV(ADS_RIGHT_READ_CONTROL),
    FLAGINFO_BITV(ADS_RIGHT_WRITE_DAC),
    FLAGINFO_BITV(ADS_RIGHT_WRITE_OWNER),
    FLAGINFO_BITV(ADS_RIGHT_SYNCHRONIZE),
    FLAGINFO_BITV(ADS_RIGHT_ACCESS_SYSTEM_SECURITY),
    FLAGINFO_BITV(ADS_RIGHT_GENERIC_READ),
    FLAGINFO_BITV(ADS_RIGHT_GENERIC_WRITE),
    FLAGINFO_BITV(ADS_RIGHT_GENERIC_EXECUTE),
    FLAGINFO_BITV(ADS_RIGHT_GENERIC_ALL),
    FLAGINFO_END()
};

static TFlagInfo LabelMasks[] =
{
    FLAGINFO_BITV(SYSTEM_MANDATORY_LABEL_NO_WRITE_UP),
    FLAGINFO_BITV(SYSTEM_MANDATORY_LABEL_NO_READ_UP),
    FLAGINFO_BITV(SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP),
    FLAGINFO_END()
};

static TFlagInfo CAceTypes[] =
{
    FLAGINFO_BITV(COMPOUND_ACE_IMPERSONATION),
    FLAGINFO_END()
};

static TFlagInfo ObjAceFlags[] =
{
    FLAGINFO_BITV(ACE_OBJECT_TYPE_PRESENT),
    FLAGINFO_BITV(ACE_INHERITED_OBJECT_TYPE_PRESENT),
    FLAGINFO_END()
};

static TFlagInfo CompoundAceTypes[] =
{
    FLAGINFO_BITV(COMPOUND_ACE_IMPERSONATION),
    FLAGINFO_END()
};

static TFlagInfo IntgrLevels[] =
{
    FLAGINFO_NUMV(SECURITY_MANDATORY_UNTRUSTED_RID),
    FLAGINFO_NUMV(SECURITY_MANDATORY_LOW_RID),
    FLAGINFO_NUMV(SECURITY_MANDATORY_MEDIUM_RID),
    FLAGINFO_NUMV(SECURITY_MANDATORY_MEDIUM_PLUS_RID),
    FLAGINFO_NUMV(SECURITY_MANDATORY_HIGH_RID),
    FLAGINFO_NUMV(SECURITY_MANDATORY_SYSTEM_RID),
    FLAGINFO_NUMV(SECURITY_MANDATORY_PROTECTED_PROCESS_RID),
    FLAGINFO_END()
};

static DWORD AceSizes[] =
{
    sizeof(ACCESS_ALLOWED_ACE),                 // ACCESS_ALLOWED_ACE_TYPE
    sizeof(ACCESS_DENIED_ACE),                  // ACCESS_DENIED_ACE_TYPE
    sizeof(SYSTEM_AUDIT_ACE),                   // SYSTEM_AUDIT_ACE_TYPE
    sizeof(SYSTEM_ALARM_ACE),                   // SYSTEM_ALARM_ACE_TYPE
    sizeof(COMPOUND_ACCESS_ALLOWED_ACE),        // COMPOUND_ACCESS_ALLOWED_ACE_TYPE
    sizeof(ACCESS_ALLOWED_OBJECT_ACE),          // ACCESS_ALLOWED_OBJECT_ACE_TYPE
    sizeof(ACCESS_DENIED_OBJECT_ACE),           // ACCESS_DENIED_OBJECT_ACE_TYPE
    sizeof(SYSTEM_AUDIT_OBJECT_ACE),            // SYSTEM_AUDIT_OBJECT_ACE_TYPE
    sizeof(SYSTEM_ALARM_OBJECT_ACE),            // SYSTEM_ALARM_OBJECT_ACE_TYPE
    sizeof(ACCESS_ALLOWED_CALLBACK_ACE),        // ACCESS_ALLOWED_CALLBACK_ACE_TYPE
    sizeof(ACCESS_DENIED_CALLBACK_ACE),         // ACCESS_DENIED_CALLBACK_ACE_TYPE
    sizeof(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE), // ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
    sizeof(ACCESS_DENIED_CALLBACK_OBJECT_ACE),  // ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
    sizeof(SYSTEM_AUDIT_CALLBACK_ACE),          // SYSTEM_AUDIT_CALLBACK_ACE_TYPE
    sizeof(SYSTEM_ALARM_CALLBACK_ACE),          // SYSTEM_ALARM_CALLBACK_ACE_TYPE
    sizeof(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE),   // SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
    sizeof(SYSTEM_ALARM_CALLBACK_OBJECT_ACE),   // SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
    sizeof(SYSTEM_MANDATORY_LABEL_ACE),         // SYSTEM_MANDATORY_LABEL_ACE_TYPE
};

static ULONG OBJECT_ACE_Flags = 0;              // XXX_YYY_OBJECT_ACE::Flags, used during parsing ACE to tree items

//-----------------------------------------------------------------------------
// Local functions - SID

static bool StringCchCut(LPTSTR szBuffer, size_t ccBuffer, LPCTSTR szStringToCut)
{
    LPTSTR szBufferEnd;
    size_t nLength1 = _tcslen(szBuffer);
    size_t nLength2 = _tcslen(szStringToCut);

    UNREFERENCED_PARAMETER(ccBuffer);

    if(nLength1 > nLength2)
    {
        szBufferEnd = szBuffer + nLength1 - nLength2;
        if(!_tcsicmp(szBufferEnd, szStringToCut))
        {
            szBufferEnd[0] = 0;
            return true;
        }
    }
    return false;
}

// Creates a new SID of "Everyone" depending on the ACE type
// Caller must free the returned SID using RtlFreeSid
static PSID Sid_CreateNew(DWORD AceType)
{
    // We only create two types of SID - "Everyone" and "Mandatory Medium"
    if(AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
        return ACE_HELPER::CreateMandatoryLabelSid();

    return ACE_HELPER::CreateAccessSid();
}

static PACL Acl_CreateNew()
{
    PACL pAcl = NULL;
    PSID pSid;
    ULONG SidLength;
    ULONG AclLength;

    if((pSid = Sid_CreateNew(ACCESS_ALLOWED_ACE_TYPE)) != NULL)
    {
        if((SidLength = RtlLengthSid(pSid)) != 0)
        {
            AclLength = sizeof(ACL) + FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + SidLength;

            if((pAcl = (PACL)LocalAlloc(LPTR, AclLength)) != NULL)
            {
                // Fill the ACL
                pAcl->AclRevision = ACL_REVISION_DS;
                pAcl->AclSize = (WORD)(AclLength);

                // Set the first ACE
                RtlAddAccessAllowedAce(pAcl, ACL_REVISION_DS, GENERIC_ALL, pSid);
            }
        }
        RtlFreeSid(pSid);
    }
    return pAcl;
}

void SidToString(PSID pvSid, LPTSTR szString, size_t cchString, bool bAddUserName)
{
    PSID_IDENTIFIER_AUTHORITY pSia;
    SID * pSid = (SID *)pvSid;
    LPTSTR szStringEnd = szString + cchString;
    UCHAR SubAuthCount;

    // Add the "S-%u-" begin with revision
    pSia = GetSidIdentifierAuthority(pSid);
    StringCchPrintfEx(szString, (szStringEnd - szString), &szString, NULL, 0, _T("S-%u-%u"),
                                                                              pSid->Revision,
                                                                              pSia->Value[5]);
    // Add the subauthorities
    SubAuthCount = *GetSidSubAuthorityCount(pSid);
    for(DWORD i = 0; i < SubAuthCount; i++)
    {
        DWORD dwSubAuth = *GetSidSubAuthority(pSid, i);

        StringCchPrintfEx(szString, (szStringEnd - szString), &szString, NULL, 0, L"-%u", dwSubAuth);
    }

    // If we are required to add user name, do it.
    if(bAddUserName)
    {
        SID_NAME_USE SidNameUse;
        TCHAR szDomainName[128] = _T("");
        TCHAR szUserName[128] = _T("");
        DWORD cchDomainName = _countof(szDomainName);
        DWORD cchUserName = _countof(szUserName);

        if(LookupAccountSid(NULL, pSid, szUserName, &cchUserName, szDomainName, &cchDomainName, &SidNameUse))
        {
            if(szDomainName[0] != 0)
                StringCchPrintf(szString, (szStringEnd - szString), _T(" (%s\\%s)"), szDomainName, szUserName);
            else
                StringCchPrintf(szString, (szStringEnd - szString), _T(" (%s)"), szUserName);
        }
        else
        {
            StringCchPrintf(szString, (szStringEnd - szString), _T(" (Unknown SID)"));
        }
    }
}
/*
// Changes an user name service ("fltmgr") into a properly prefixed name ("NT_SERVICE\\fltmgr")
static bool CheckForServiceAccount(LPTSTR szUserName)
{
    TCHAR szSaveUserName[MAX_PATH];
    TCHAR szKeyName[MAX_PATH];
    HKEY hSubKey;

    // Save the user name
    StringCchCopy(szSaveUserName, _countof(szSaveUserName), szUserName);

    // If the name resembles a service, give it the NT_SERVICE prefix. This only applies in Vista or newer
    if(g_dwWinVer >= 0x0600 && _tcschr(szUserName, _T('\\')) == NULL)
    {
        StringCchPrintf(szKeyName, _countof(szKeyName), _T("SYSTEM\\CurrentControlSet\\Services\\%s"), szUserName);
        if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKeyName, 0, KEY_QUERY_VALUE, &hSubKey) == ERROR_SUCCESS)
        {
            StringCchPrintf(szUserName, MAX_PATH, _T("NT SERVICE\\%s"), szSaveUserName);
            RegCloseKey(hSubKey);
            return true;
        }
    }

    return false;
}

bool StringToSid(LPTSTR szSid, PSID * ppSid)
{
    SID_IDENTIFIER_AUTHORITY Sia = SiaNull;
    SID_NAME_USE SidNameUse;
    LPTSTR szSidStart;
    PSID  pNewSid = NULL;
    TCHAR szDomainName[128] = _T("");
    DWORD dwSubAuthCount = 0;
    DWORD dwSubAuth[SID_MAX_SUB_AUTHORITIES];
    DWORD dwDomainName = _countof(szDomainName);
    DWORD dwRevision = SID_REVISION;
    DWORD dwLength = 0;
    BOOL bResult;

    // Verify the string sid value
    if(szSid == NULL || szSid[0] == 0)
        return false;

    // Case 1: Sid is entered as text form ("S-1-....")
    if((szSidStart = _tcsstr(szSid, _T("S-1-"))) != NULL)
    {
        // Skip the begin
        dwRevision = SID_REVISION;
        szSid = szSidStart + 4;

        // Get the identifier authority
        Sia.Value[5] = (BYTE)StrToInt(szSid, &szSid, 10);
        if(szSid[0] != _T('-'))
            return false;

        // Get the subauthorities
        memset(dwSubAuth, 0, sizeof(dwSubAuth));
        while(szSid[0] == _T('-') && dwSubAuthCount < SID_MAX_SUB_AUTHORITIES)
        {
            dwSubAuth[dwSubAuthCount++] = StrToInt(szSid + 1, &szSid, 10);
        }

        // If an unknown character found, do nothing
        if(szSid[0] == 0 || szSid[0] == _T(' '))
        {
            // Create the SID
            RtlAllocateAndInitializeSid(&Sia, (UCHAR)dwSubAuthCount,
                                                     dwSubAuth[0],
                                                     dwSubAuth[0],
                                                     dwSubAuth[0],
                                                     dwSubAuth[0],
                                                     dwSubAuth[0],
                                                     dwSubAuth[0],
                                                     dwSubAuth[0],
                                                     dwSubAuth[0],
                                                     ppSid);
            return (*ppSid != NULL);
        }

        return false;
    }

    // Case 2: Domain\Username
    __LookupAccountName:
    bResult = LookupAccountName(NULL, szSid, pNewSid, &dwLength, szDomainName, &dwDomainName, &SidNameUse);

    // If we haven't received the length, try some well-known user names
    if(bResult == FALSE && dwLength == 0)
    {
        if(GetLastError() == ERROR_NONE_MAPPED && CheckForServiceAccount(szSid))
            goto __LookupAccountName;
    }

    // If we received a non-zero length, allocate SID and try again
    if(bResult == FALSE && dwLength != 0)
    {
        pNewSid = Sid_Allocate(dwLength);
        bResult = LookupAccountName(NULL, szSid, pNewSid, &dwLength, szDomainName, &dwDomainName, &SidNameUse);
    }

    // If succeeded, give the SID
    if(bResult)
        *ppSid = pNewSid;
    return (bool)(bResult != FALSE);
}
*/

//
// The SID in the SYSTEM_MANDATORY_LABEL_ACE has the following format:
//
// - IdentifierAuthority is set to SECURITY_MANDATORY_LABEL_AUTHORITY
// - The last subauthority is set to one of the SECURITY_MANDATORY_XXXX values
//
static LPBYTE SidToIntegrityLevel(PSID pSid)
{
    DWORD dwSubAuthCount;

    if(pSid != NULL && RtlLengthSid(pSid) > FIELD_OFFSET(SYSTEM_MANDATORY_LABEL_ACE, SidStart))
    {
        PSID_IDENTIFIER_AUTHORITY pSia = GetSidIdentifierAuthority(pSid);

        // Retrieve integrity level from SID
        if(!memcmp(pSia, &SiaLabel, sizeof(SID_IDENTIFIER_AUTHORITY)))
        {
            // Get the number of sub-authorities
            if((dwSubAuthCount = *GetSidSubAuthorityCount(pSid)) > 0)
            {
                return (LPBYTE)(GetSidSubAuthority(pSid, dwSubAuthCount - 1));
            }
        }
    }

    // Return default integrity level
    assert(false);
    return NULL;
}

//-----------------------------------------------------------------------------
// Local functions ACEs, ACLs

static PACL Acl_CreateEmpty(DWORD dwAclSize = MAXIMUM_ACL_SIZE)
{
    PACL pAcl;

    // Allocate new ACL of the maximum size
    pAcl = (PACL)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, MAXIMUM_ACL_SIZE);
    if(pAcl != NULL)
        InitializeAcl(pAcl, dwAclSize, ACL_REVISION);

    // Return the ACL
    return pAcl;
}

static PACL Acl_FinishBuild(PACL pAcl)
{
    PACE_HEADER pAceHeader;
    DWORD dwAceCount = pAcl->AceCount;
    DWORD dwAceSize = sizeof(ACL);

    // Acount the size of all ACEs
    for(DWORD i = 0; i < dwAceCount; i++)
    {
        // Retrieve the n-th ACE
        if(!GetAce(pAcl, i, (LPVOID *)&pAceHeader))
            break;

        // Add the size to the ACL
        dwAceSize = dwAceSize + pAceHeader->AceSize;
    }

    // Adjust the size of the ACL
    pAcl->AclSize = (WORD)dwAceSize;
    return pAcl;
}

//-----------------------------------------------------------------------------
// Local functions - tree items

static LPCSTR GetAceTypeString(DWORD AceType)
{
    static CHAR szBuffer[64];
    BYTE MaxAceType = (BYTE)(_countof(AceHdrTypes) - 1);

    // Insert the "root" item with ACE type
    if(AceType < MaxAceType)
        return AceHdrTypes[AceType].szFlagText;

    // Prepare string for an unknown ACE type
    StringCchPrintfA(szBuffer, _countof(szBuffer), "UNKNOWN_ACE_TYPE (%02x)", AceType);
    return szBuffer;
}

// The item text is expected to be in format "Name: 0x12345678"
static LPTSTR GetItemTextValue(LPTSTR szItemText)
{
    LPTSTR szSpacePtr;

    // Retrieve the first occurence of ":"
    szItemText = _tcschr(szItemText, _T(':'));
    if(szItemText != NULL)
    {
        // Skip the colon
        szItemText++;

        // Skip spaces
        while(szItemText[0] == ' ')
            szItemText++;

        // If the number is followed by a space, cut it
        szSpacePtr = _tcschr(szItemText, _T(' '));
        if(szSpacePtr != NULL)
            szSpacePtr[0] = 0;
    }

    // Return the text
    return szItemText;
}

static bool TreeView_ItemToValue32(HWND hWndTree, HTREEITEM hItem, LPDWORD PtrValue)
{
    TVITEM tvi;
    LPTSTR szValue;
    TCHAR szItemText[256];
    DWORD dwErrCode;

    // Get the text from the
    tvi.mask = TVIF_TEXT;
    tvi.hItem = hItem;
    tvi.pszText = szItemText;
    tvi.cchTextMax = _countof(szItemText);
    if(TreeView_GetItem(hWndTree, &tvi))
    {
        // Retrieve the value
        szValue = GetItemTextValue(szItemText);
        if(szValue != NULL)
        {
            // Convert the 32-bit value to an integer
            dwErrCode = Text2Hex32(szValue, PtrValue);
            return (dwErrCode == ERROR_SUCCESS);
        }
    }

    return false;
}

static bool TreeView_ItemToGuid(HWND hWndTree, HTREEITEM hItem, LPGUID PtrGuid)
{
    TVITEM tvi;
    LPTSTR szValue;
    TCHAR szItemText[256];

    // Get the text from the
    tvi.mask = TVIF_TEXT;
    tvi.hItem = hItem;
    tvi.pszText = szItemText;
    tvi.cchTextMax = _countof(szItemText);
    if(TreeView_GetItem(hWndTree, &tvi))
    {
        // Retrieve the value
        szValue = GetItemTextValue(szItemText);
        if(szValue != NULL)
        {
            return StringToGuid(szValue, PtrGuid);
        }
    }

    return false;
}

static void TV_MakeItemText(
    PCTREE_ITEM_INFO pItemInfo,
    LPTSTR szBuffer,
    size_t ccBuffer,
    LPBYTE pbPtr,
    LPBYTE pbEnd,
    PULONG pcbMoveBy = NULL)
{
    ULONG cbMoveBy = 0;
    TCHAR szDataText[0x400] = {0};
    UINT nIDFormat = pItemInfo->nIDFormat1;

    // Do we have data and format for it?
    if(pItemInfo->nIDFormat2)
    {
        if(pItemInfo->ToString != NULL)
        {
            // Format the numeric or whatever value
            if(pItemInfo->ToString(pItemInfo, szDataText, _countof(szDataText), pbPtr, pbEnd, &cbMoveBy))
            {
                nIDFormat = pItemInfo->nIDFormat2;
            }
        }
    }

    // Finally, format the data to the item
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    rsprintf(szBuffer, ccBuffer, nIDFormat, szDataText);
}

static bool TV_TextToEditText(const _TREE_ITEM_INFO * /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPCTSTR szItemText)
{
    LPCTSTR szBegin = szItemText;
    LPCTSTR szFinal = szItemText + _tcslen(szItemText);
    LPCTSTR szTemp;

    // Skip the prefix ("AclRevision: ")
    if((szTemp = _tcsstr(szBegin, _T(": "))) != NULL)
        szBegin = szTemp + 2;

    // Find the end
    if((szTemp = _tcsstr(szBegin, _T("  "))) != NULL)
        szFinal = szTemp;

    // Copy the string
    StringCchCopyN(szBuffer, ccBuffer, szBegin, (szFinal - szBegin));
    return true;
}

static bool CopyDataAway(LPBYTE pbPtr, LPBYTE pbEnd, LPCVOID lpData, ULONG cbData, PULONG pcbMoveBy = NULL)
{
    if((ULONG)(pbEnd - pbPtr) >= cbData)
    {
        // Copy the SID
        memcpy(pbPtr, lpData, cbData);

        // Give the SID length
        if(pcbMoveBy != NULL)
            pcbMoveBy[0] = cbData;
        return true;
    }
    return false;
}


//-----------------------------------------------------------------------------
// Conversion of String <-> Binary Data: Hex

static bool ToString_Hex(PCTREE_ITEM_INFO pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    ULONG dwIntValue = 0;
    ULONG cbMoveBy = 0;

#define FORMAT_VALUE_INTEGER(format, type)                       \
    if((pbPtr + sizeof(type)) > pbEnd) { return false; }         \
    dwIntValue = *(type *)(pbPtr);                               \
    StringCchPrintf(szBuffer, ccBuffer, _T(format), dwIntValue); \
    cbMoveBy = sizeof(type);

    // Determine the integer size
    switch(pItemInfo->ItemType)
    {
        case ItemTypeUint08:
            FORMAT_VALUE_INTEGER("0x%02x", BYTE);
            break;

        case ItemTypeUint16:
            FORMAT_VALUE_INTEGER("0x%04x", USHORT);
            break;

        case ItemTypeUint32:
            FORMAT_VALUE_INTEGER("0x%08x", ULONG);
            break;

        default:
            assert(false);
            return false;
    }

    // If the value has flags, we add the flags suffix
    if(pItemInfo->pFlagInfos != NULL)
    {
        // Convert the flags to their text representations
        TFlagString fs(pItemInfo->pFlagInfos, dwIntValue);

        if(fs.GetConvertedFlagsCount())
        {
            StringCchCat(szBuffer, ccBuffer, _T("  "));
            StringCchCat(szBuffer, ccBuffer, fs);
        }
    }

    // Give the move by
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return (cbMoveBy != 0);
}

static bool StringTo_Hex(PCTREE_ITEM_INFO pItemInfo, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    ULONG dwIntValue = 0;
    ULONG cbMoveBy = 0;

#define READ_VALUE_INTEGER(type)                                \
    if((pbPtr + sizeof(type)) <= pbEnd)                         \
    {                                                           \
        if(Text2Hex32(szString, &dwIntValue) == ERROR_SUCCESS)  \
        {                                                       \
            *(type *)(pbPtr) = (type)(dwIntValue);              \
            cbMoveBy = sizeof(type);                            \
        }                                                       \
    }

    // Determine the integer size
    switch(pItemInfo->ItemType)
    {
        case ItemTypeUint08:
            READ_VALUE_INTEGER(BYTE);
            break;

        case ItemTypeUint16:
            READ_VALUE_INTEGER(USHORT);
            break;

        case ItemTypeUint32:
            READ_VALUE_INTEGER(ULONG);
            break;

        default:
            assert(false);
            return false;
    }

    // Give the pcbMoveBy
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return (cbMoveBy != 0);
}

//-----------------------------------------------------------------------------
// Conversion of String <-> Binary Data: SID

static TREE_ITEM_INFO ItemType_IntLevel = {ItemTypeUint32,  0, IDS_FORMAT_INT_LEVEL, IntgrLevels};

static bool ToString_Sid(PCTREE_ITEM_INFO pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    LPBYTE pbIntegrityLevel;
    ULONG cbMoveBy = 0;

    // If there is a SID, format it to the buffer
    if(pbPtr && pbEnd > pbPtr)
    {
        PSID pSid = (PSID)(pbPtr);

        switch(pItemInfo->ItemType)
        {
            case ItemTypeSid:       // Convert the SID to string
            {
                SidToString(pSid, szBuffer, ccBuffer, true);
                cbMoveBy = RtlLengthSid(pSid);
                break;
            }

            case ItemTypeMandSid:
            {
                if((pbIntegrityLevel = SidToIntegrityLevel(pSid)) != NULL)
                    ToString_Hex(&ItemType_IntLevel, szBuffer, ccBuffer, pbIntegrityLevel, pbIntegrityLevel + sizeof(DWORD));
                cbMoveBy = RtlLengthSid(pSid);
                break;
            }
        }
    }
    else
    {
        rsprintf(szBuffer, ccBuffer, IDS_NOT_PRESENT);
    }

    // Give the length to move
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return TRUE;
}

static bool StringTo_Sid(PCTREE_ITEM_INFO pItemInfo, LPCTSTR szText, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    SID_NAME_USE SidNameUse;
    TCHAR szDomainName[256];
    DWORD ccDomainName = _countof(szDomainName);
    DWORD cbSid = (ULONG)(pbEnd - pbPtr);
    PSID pSid = NULL;
    bool bResult = false;

    // Mandatory SIDs have just integrity level
    if(pItemInfo->ItemType == ItemTypeMandSid)
    {
        DWORD dwIntLevel = SECURITY_MANDATORY_MEDIUM_RID;

        if(StringTo_Hex(&ItemType_IntLevel, szText, (LPBYTE)(&dwIntLevel), (LPBYTE)(&dwIntLevel) + sizeof(ULONG)))
        {
            if((pSid = ACE_HELPER::CreateMandatoryLabelSid(dwIntLevel)) != NULL)
            {
                bResult = CopyDataAway(pbPtr, pbEnd, pSid, cbSid, pcbMoveBy);
                RtlFreeSid(pSid);
            }
        }
        return bResult;
    }

    // SIDs entered in the raw format: "S-1-"
    if(!_tcsnicmp(szText, _T("S-1-"), 4))
    {
        if(ConvertStringSidToSid(szText, &pSid))
        {
            if((cbSid = RtlLengthSid(pSid)) != 0)
            {
                if((ULONG)(pbEnd - pbPtr) >= cbSid)
                {
                    bResult = CopyDataAway(pbPtr, pbEnd, pSid, cbSid, pcbMoveBy);
                    LocalFree(pSid);
                    return bResult;
                }
            }
        }
    }

    // Convert the account name to SID
    if(LookupAccountName(NULL, szText, (PSID)(pbPtr), &cbSid, szDomainName, &ccDomainName, &SidNameUse))
    {
        if(pcbMoveBy != NULL)
            pcbMoveBy[0] = cbSid;
        return true;
    }
    return false;
}

static bool CreateNew_Sid(PCTREE_ITEM_INFO /* pItemInfo */, LPBYTE pbDataBuffer, size_t * pcbDataBuffer)
{
    PSID pSid;
    size_t cbDataBuffer = pcbDataBuffer[0];
    bool bResult = false;

    // Create new SID
    if((pSid = Sid_CreateNew(ACCESS_ALLOWED_ACE_TYPE)) != NULL)
    {
        ULONG SidLength = RtlLengthSid(pSid);

        if(SidLength <= cbDataBuffer)
        {
            memcpy(pbDataBuffer, pSid, SidLength);
            pcbDataBuffer[0] = SidLength;
            bResult = true;
        }
        RtlFreeSid(pSid);
    }
    return bResult;
}

//-----------------------------------------------------------------------------
// Conversion of String <-> Binary Data: GUID

// Get GUID from object-based ACEs, like ACCESS_ALLOWED_OBJECT_ACE
// * ACCESS_ALLOWED_OBJECT_ACE::ObjectType is only present if ACE_OBJECT_TYPE_PRESENT
// * ACCESS_ALLOWED_OBJECT_ACE::InheritedObjectType is only present if ACE_INHERITED_OBJECT_TYPE_PRESENT
static bool ToString_Guid(PCTREE_ITEM_INFO pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    ULONG FlagToTest = (pItemInfo->ItemType == ItemTypeGuid2) ? ACE_INHERITED_OBJECT_TYPE_PRESENT : ACE_OBJECT_TYPE_PRESENT;
    ULONG cbMoveBy = 0;
    bool bResult = false;

    // Only present if the 
    if(OBJECT_ACE_Flags & FlagToTest)
    {
        if((pbPtr + sizeof(GUID)) <= pbEnd)
        {
            GuidToString((LPGUID)(pbPtr), szBuffer, ccBuffer);
            cbMoveBy = sizeof(GUID);
            bResult = true;
        }
    }
    else
    {
        LoadString(g_hInst, IDS_NOT_PRESENT, szBuffer, (int)(ccBuffer));
        bResult = true;
    }

    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return bResult;
}

static bool StringTo_Guid(PCTREE_ITEM_INFO /* pItemInfo */, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    ULONG cbMoveBy = 0;

    if((pbPtr + sizeof(GUID)) <= pbEnd)
    {
        if(StringToGuid(szString, (LPGUID)(pbPtr)))
        {
            cbMoveBy = sizeof(GUID);
        }
    }

    // Give the pcbMoveBy
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return (cbMoveBy != 0);
}


static bool CreateNew_Guid(PCTREE_ITEM_INFO pItemInfo, LPBYTE pbDataBuffer, size_t * pcbDataBuffer)
{
    size_t cbDataBuffer = pcbDataBuffer[0];
    ULONG FlagToSet = (pItemInfo->ItemType == ItemTypeGuid2) ? ACE_INHERITED_OBJECT_TYPE_PRESENT : ACE_OBJECT_TYPE_PRESENT;
    bool bResult = false;

    // Create new NULL GUID
    if(cbDataBuffer >= sizeof(GUID))
    {
        memset(pbDataBuffer, 0, sizeof(GUID));
        OBJECT_ACE_Flags |= FlagToSet;
        pcbDataBuffer[0] = sizeof(GUID);
        bResult = true;
    }
    return bResult;
}

static bool ToString_Cnd(PCTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    ULONG cbMoveBy = 0;
    bool bResult = false;

    // If there is a SID, format it to the buffer
    if(pbPtr && pbEnd > pbPtr)
    {
        LPTSTR szCondition = NULL;
        DWORD dwErrCode;

        dwErrCode = LocalGetStringForCondition(pbPtr, (DWORD)(pbEnd - pbPtr), &szCondition, NULL, NULL, NULL, NULL, false);
        if(dwErrCode == ERROR_SUCCESS && szCondition != NULL)
        {
            StringCchCopy(szBuffer, ccBuffer, szCondition);
            LocalFree(szCondition);
            cbMoveBy = (ULONG)(pbEnd - pbPtr);
            bResult = true;
        }
    }
    else
    {
        LoadString(g_hInst, IDS_EMPTY_STREAM, szBuffer, (int)(ccBuffer));
        bResult = true;
    }

    // Give the length to move
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return bResult;
}

static bool ToString_Ace(PCTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    PACE_HEADER pAceHeader = (PACE_HEADER)(pbPtr);
    ULONG cbMoveBy = 0;

    if((pbPtr + sizeof(ACE_HEADER)) < pbEnd)
    {
        LPCSTR szAceType = GetAceTypeString(pAceHeader->AceType);

        StringCchPrintf(szBuffer, ccBuffer, _T("%hs"), szAceType);
        StringCchCut(szBuffer, ccBuffer, szAceTypeSuffix);
        cbMoveBy = pAceHeader->AceSize;
    }
    else
    {
        LoadString(g_hInst, IDS_NOT_PRESENT, szBuffer, (int)(ccBuffer));
    }

    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return true;
}

static bool CreateNew_Ace(PCTREE_ITEM_INFO pItemInfo, LPBYTE pbDataBuffer, size_t * pcbDataBuffer)
{
    LPBYTE pbEnd = pbDataBuffer + pcbDataBuffer[0];
    LPBYTE pbPtr = pbDataBuffer;
    bool bResult = false;

    // Create ACCESS_ALLOWED_ACE / SYSTEM_MANDATORY_LABEL_ACE
    if((pbPtr + FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart)) <= pbEnd)
    {
        PACCESS_ALLOWED_ACE pAce = (PACCESS_ALLOWED_ACE)(pbPtr);
        ULONG cbSid = 0;
        PSID pSid;

        pAce->Header.AceType = (pItemInfo->ItemType == ItemTypeSacl) ? SYSTEM_MANDATORY_LABEL_ACE_TYPE : ACCESS_ALLOWED_ACE_TYPE;
        pAce->Header.AceSize = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart);
        pAce->Mask = GENERIC_ALL;
        pbPtr += FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart);

        // Append the SID
        if((pSid = Sid_CreateNew(pAce->Header.AceType)) != NULL)
        {
            // Retrieve the length of the SID
            cbSid = RtlLengthSid(pSid);

            // Enough space for the SID?
            if((pbPtr + cbSid) <= pbEnd)
            {
                // Copy the SID to the ACE
                memcpy(pbPtr, pSid, cbSid);
                RtlFreeSid(pSid);
                bResult = true;
            }

            // Update the ACE size
            pAce->Header.AceSize = (WORD)(pAce->Header.AceSize + cbSid);
        }

        // Update the ACE length
        pcbDataBuffer[0] = pAce->Header.AceSize;
    }
    return bResult;
}

static bool CreateNew_Acl(PCTREE_ITEM_INFO pItemInfo, LPBYTE pbDataBuffer, size_t * pcbDataBuffer)
{
    LPBYTE pbEnd = pbDataBuffer + pcbDataBuffer[0];
    LPBYTE pbPtr = pbDataBuffer;
    bool bResult = false;

    // Pre-fill the entire buffer with zeros
    memset(pbPtr, 0, (pbEnd - pbPtr));

    // Create the ACL header
    if((pbPtr + sizeof(ACL)) <= pbEnd)
    {
        PACE_HEADER pAceHeader;
        size_t cbDataBuffer = 0;
        PACL pAcl = (PACL)(pbPtr);

        // Fill-in the ACL header
        pAcl->AclRevision = ACL_REVISION_DS;
        pAcl->AclSize = sizeof(ACL);
        pbPtr += sizeof(ACL);

        // Setup the pointer to the ACE
        pAceHeader = (PACE_HEADER)(pbPtr);
        cbDataBuffer = pbEnd - pbPtr;

        // Create an ACE
        if((bResult = CreateNew_Ace(pItemInfo, pbPtr, &cbDataBuffer)) != false)
        {
            pAcl->AclSize = pAcl->AclSize + pAceHeader->AceSize;
            pAcl->AceCount++;
            pcbDataBuffer[0] = pAcl->AclSize;
        }
    }
    return bResult;
}

static TREE_ITEM_INFO TreeItem_Owner    = {ItemTypeOwner,   IDS_OWNER_SECURITY_INFORMATION};
static TREE_ITEM_INFO TreeItem_Group    = {ItemTypeGroup,   IDS_GROUP_SECURITY_INFORMATION};
static TREE_ITEM_INFO TreeItem_Dacl     = {ItemTypeDacl,    IDS_DACL_SECURITY_INFORMATION};
static TREE_ITEM_INFO TreeItem_Sacl     = {ItemTypeSacl,    IDS_SACL_SECURITY_INFORMATION};
static TREE_ITEM_INFO TreeItem_NullAcl  = {ItemTypeNullAcl, IDS_NULL_ACL,    IDS_FORMAT_STR,       NULL,        NULL,         NULL,         CreateNew_Acl};
static TREE_ITEM_INFO TreeItem_NoAcl    = {ItemTypeNoAcl,   IDS_NOT_PRESENT, IDS_FORMAT_STR,       NULL,        NULL,         NULL,         CreateNew_Acl};
static TREE_ITEM_INFO TreeItem_UserSid  = {ItemTypeSid,     IDS_NOT_PRESENT, IDS_FORMAT_SID,       NULL,        ToString_Sid, StringTo_Sid, CreateNew_Sid};
static TREE_ITEM_INFO TreeItem_AclRev   = {ItemTypeUint08,  0,               IDS_FORMAT_ACL_REVIS, AclRevFlags, ToString_Hex, StringTo_Hex};
static TREE_ITEM_INFO TreeItem_AclSbz1  = {ItemTypeUint08,  0,               IDS_FORMAT_ACL_SBZ1,  NULL,        ToString_Hex, StringTo_Hex};
static TREE_ITEM_INFO TreeItem_AclSize  = {ItemTypeUint16,  0,               IDS_FORMAT_ACL_SIZE,  NULL,        ToString_Hex, StringTo_Hex};
static TREE_ITEM_INFO TreeItem_AceCnt   = {ItemTypeUint16,  0,               IDS_FORMAT_ACL_COUNT, NULL,        ToString_Hex, StringTo_Hex};
static TREE_ITEM_INFO TreeItem_AclSbz2  = {ItemTypeUint16,  0,               IDS_FORMAT_ACL_SBZ2,  NULL,        ToString_Hex, StringTo_Hex};
static TREE_ITEM_INFO TreeItem_Ace      = {ItemTypeAce,     IDS_NULL_ACL,    IDS_FORMAT_STR,       NULL,        ToString_Ace};

static PCTREE_ITEM_INFO AclFieldInfos[] =
{
    &TreeItem_AclRev,
    &TreeItem_AclSbz1,
    &TreeItem_AclSize,
    &TreeItem_AceCnt,
    &TreeItem_AclSbz2,
};

static ACE_FIELD_INFO AceFieldInfos[] =
{
    {ACE_FIELD_HTYPE,           {ItemTypeUint08,    0, IDS_FORMAT_ACE_HTYPE,  NULL,        ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_HFLAGS,          {ItemTypeUint08,    0, IDS_FORMAT_ACE_HFLAGS, AceHdrFlags, ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_HSIZE,           {ItemTypeUint16,    0, IDS_FORMAT_ACE_HSIZE,  NULL,        ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_ACCESS_MASK,     {ItemTypeUint32,    0, IDS_FORMAT_ACE_MASK,   AceMasks,    ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_ADS_ACCESS_MASK, {ItemTypeUint32,    0, IDS_FORMAT_ACE_MASK,   AdsAceMasks, ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_MANDATORY_MASK,  {ItemTypeUint32,    0, IDS_FORMAT_ACE_MASK,   LabelMasks,  ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_FLAGS,           {ItemTypeUint32,    0, IDS_FORMAT_ACE_FLAGS,  ObjAceFlags, ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_CTYPE,           {ItemTypeUint16,    0, IDS_FORMAT_ACE_CTYPE,  CAceTypes,   ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_CRESERVED,       {ItemTypeUint16,    0, IDS_FORMAT_RESERVED,   NULL,        ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_OBJECT_TYPE1,    {ItemTypeGuid,      0, IDS_FORMAT_OBJ_TYPE,   NULL,        ToString_Guid, StringTo_Guid, CreateNew_Guid}},
    {ACE_FIELD_OBJECT_TYPE2,    {ItemTypeGuid2,     0, IDS_FORMAT_OBJ_TYPEI,  NULL,        ToString_Guid, StringTo_Guid, CreateNew_Guid}},
    {ACE_FIELD_ACCESS_SID,      {ItemTypeSid,       0, IDS_FORMAT_SID,        NULL,        ToString_Sid,  StringTo_Sid}},
    {ACE_FIELD_SERVER_SID,      {ItemTypeSid,       0, IDS_FORMAT_SSID,       NULL,        ToString_Sid,  StringTo_Sid}},
    {ACE_FIELD_CLIENT_SID,      {ItemTypeSid,       0, IDS_FORMAT_CSID,       NULL,        ToString_Sid,  StringTo_Sid}},
    {ACE_FIELD_MANDATORY_SID,   {ItemTypeMandSid,   0, IDS_FORMAT_INT_LEVEL,  IntgrLevels, ToString_Sid,  StringTo_Sid}},
    {ACE_FIELD_CONDITION,       {ItemTypeCondition, 0, IDS_FORMAT_CONDITION,  NULL,        ToString_Cnd,  NULL}}
};

//-----------------------------------------------------------------------------
// Inserting items

static int GetDefaultCharLimit(PCTREE_ITEM_INFO pItemInfo)
{
    if(pItemInfo->ItemType == ItemTypeUint08)
        return 8;
    if(pItemInfo->ItemType == ItemTypeUint16)
        return 16;
    if(pItemInfo->ItemType == ItemTypeUint32)
        return 32;
    if(pItemInfo->ItemType == ItemTypeUint64)
        return 64;
    return 256;
}

static PTREE_ITEM_INFO TV_GetItemParam(HWND hWndTree, HTREEITEM hItem)
{
    return (PTREE_ITEM_INFO)TreeView_GetItemParam(hWndTree, hItem);
}

static BYTE TV_GetAceType(HWND hWndTree, HTREEITEM hItem)
{
    TVITEM tvi = {TVIF_TEXT};
    TCHAR szItemText[128];
    CHAR szItemTextA[128];

    // Retrieve the item text
    tvi.hItem = hItem;
    tvi.pszText = szItemText;
    tvi.cchTextMax = _countof(szItemText);
    TreeView_GetItem(hWndTree, &tvi);

    // Convert to ANSI
    StringCchCat(szItemText, _countof(szItemText), szAceTypeSuffix);
    StringCchCopyX(szItemTextA, _countof(szItemTextA), szItemText);

    // Search the array
    for(size_t i = 0; AceHdrTypes[i].szFlagText != NULL; i++)
    {
        if(!_stricmp(AceHdrTypes[i].szFlagText, szItemTextA))
        {
            return (BYTE)(i);
        }
    }

    // Default value
    return ACCESS_ALLOWED_ACE_TYPE;
}

static HTREEITEM TV_GetAceSibling(HWND hWndTree, HTREEITEM hItem, BOOL bNextItem)
{
    PTREE_ITEM_INFO pItemInfo;
    HTREEITEM hSibling;
    WPARAM wParam = (bNextItem == FALSE) ? TVGN_PREVIOUS : TVGN_NEXT;

    // Get the previous sibling item
    hSibling = (HTREEITEM)SendMessage(hWndTree, TVM_GETNEXTITEM, wParam, (LPARAM)(hItem));
    if(hSibling != NULL)
    {
        if((pItemInfo = TV_GetItemParam(hWndTree, hSibling)) != NULL)
        {
            if(pItemInfo->ItemType == ItemTypeAce)
            {
                return hSibling;
            }
        }
    }
    return NULL;
}

static void TV_SwapItems(TVITEM & tvi1, TVITEM & tvi2)
{
    TVITEM tvi = tvi2;

    // Swap the items
    tvi2.pszText = tvi1.pszText;
    tvi2.lParam = tvi1.lParam;

    tvi1.pszText = tvi.pszText;
    tvi1.lParam = tvi.lParam;
}

static HTREEITEM TV_SwapItems_NewItem(HWND hWndTree, HTREEITEM hParent, const TVITEM & tvi)
{
    TVINSERTSTRUCT tvis = {NULL};

    tvis.hParent = hParent;
    tvis.hInsertAfter = TVI_LAST;
    tvis.item.mask = tvi.mask;
    tvis.item.lParam = tvi.lParam;
    tvis.item.pszText = tvi.pszText;
    return TreeView_InsertItem(hWndTree, &tvis);
}

static void TV_SwapItems(HWND hWndTree, HTREEITEM hParent1, HTREEITEM hItem1, HTREEITEM hParent2, HTREEITEM hItem2)
{
    HTREEITEM hItemToDelete = NULL;
    HTREEITEM hNextParent1 = hItem1;
    HTREEITEM hNextParent2 = hItem2;
    TVITEM tvi1 = {TVIF_TEXT | TVIF_PARAM};
    TVITEM tvi2 = {TVIF_TEXT | TVIF_PARAM};
    UINT uNextItem = TVGN_CHILD;
    int ccItemText = 0x1000;

    // Fill the items
    tvi1.cchTextMax = ccItemText;
    tvi1.pszText = new TCHAR[ccItemText];
    tvi1.hItem = hItem1;
    tvi2.cchTextMax = ccItemText;
    tvi2.pszText = new TCHAR[ccItemText];
    tvi2.hItem = hItem2;

    // Did the allocation succeed?
    if(tvi1.pszText && tvi2.pszText)
    {
        // Disable redrawing
        SendMessage(hWndTree, WM_SETREDRAW, FALSE, 0);

        // Keep going as long as we have at least one item
        while(tvi1.hItem || tvi2.hItem)
        {
            // Both items are valid --> swap items
            if(tvi1.hItem && tvi2.hItem)
            {
                TreeView_GetItem(hWndTree, &tvi1);
                TreeView_GetItem(hWndTree, &tvi2);
                TV_SwapItems(tvi1, tvi2);
                TreeView_SetItem(hWndTree, &tvi1);
                TreeView_SetItem(hWndTree, &tvi2);
            }

            // Only the first is valid -> move under the new parent
            else if(tvi1.hItem)
            {
                if(hItemToDelete == NULL)
                    hItemToDelete = tvi1.hItem;
                TreeView_GetItem(hWndTree, &tvi1);
                TV_SwapItems_NewItem(hWndTree, hParent2, tvi1);
            }

            // Only the second is valid -> move under the new parent
            else if(tvi2.hItem)
            {
                if(hItemToDelete == NULL)
                    hItemToDelete = tvi2.hItem;
                TreeView_GetItem(hWndTree, &tvi2);
                TV_SwapItems_NewItem(hWndTree, hParent1, tvi2);
            }

            tvi1.hItem = TreeView_GetNextItem(hWndTree, tvi1.hItem, uNextItem);
            tvi2.hItem = TreeView_GetNextItem(hWndTree, tvi2.hItem, uNextItem);
            hParent1 = hNextParent1;
            hParent2 = hNextParent2;
            uNextItem = TVGN_NEXT;
        }

        // Delete additional items
        while(hItemToDelete != NULL)
        {
            HTREEITEM nNextItem = TreeView_GetNextSibling(hWndTree, hItemToDelete);

            // Delete the item param, then delete the item
            TreeView_SetItemParam(hWndTree, hItemToDelete, 0);
            TreeView_DeleteItem(hWndTree, hItemToDelete);
            hItemToDelete = nNextItem;
        }

        // Free buffers
        delete [] tvi2.pszText;
        delete [] tvi1.pszText;

        // Enable redrawing and paint
        SendMessage(hWndTree, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(hWndTree, NULL, TRUE);
    }
}

static HTREEITEM TV_InsertNewItem(
    HWND hWndTree,
    HTREEITEM hParent,
    HTREEITEM hInsertAfter,
    PCTREE_ITEM_INFO pItemInfo,
    LPBYTE pbPtr = NULL,
    LPBYTE pbEnd = NULL,
    PULONG pcbMoveBy = NULL)
{
    PTREE_ITEM_INFO pNewInfo;
    TVINSERTSTRUCT tvis;
    HTREEITEM hItem = NULL;
    TCHAR szItemText[0x400];
    ULONG cbMoveBy = 0;

    // Create copy of the item info structure
    if((pNewInfo = (PTREE_ITEM_INFO)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, sizeof(TREE_ITEM_INFO))) != NULL)
    {
        // Copy the item data
        memcpy(pNewInfo, pItemInfo, sizeof(TREE_ITEM_INFO));

        // Prepare the item text
        TV_MakeItemText(pNewInfo, szItemText, _countof(szItemText), pbPtr, pbEnd, &cbMoveBy);

        // Does the item have data?
        pNewInfo->ItemData = (pbPtr && pbEnd > pbPtr && cbMoveBy) ? ItemDataValid : ItemDataNULL;

        // Insert the item to the tree
        tvis.hParent = (hParent != NULL) ? hParent : TVI_ROOT;
        tvis.hInsertAfter = (hInsertAfter != NULL) ? hInsertAfter : TVI_LAST;
        tvis.item.mask = TVIF_TEXT | TVIF_PARAM;
        tvis.item.pszText = szItemText;
        tvis.item.lParam = (LPARAM)(pNewInfo);
        hItem = TreeView_InsertItem(hWndTree, &tvis);

        // Expand the item
        if(hParent != TVI_ROOT && hItem != NULL)
        {
            TreeView_Expand(hWndTree, hParent, TVE_EXPAND);
            TreeView_SelectItem(hWndTree, hItem);
        }
    }

    // Give the number of bytes eaten
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return hItem;
}

static HTREEITEM TV_InsertNewItemSid(
    HWND hWndTree,
    HTREEITEM hParent,
    HTREEITEM hInsertAfter,
    PTREE_ITEM_INFO pItemInfo,
    PSID pSid)
{
    LPBYTE pbSid = (LPBYTE)(pSid);
    LPBYTE pbEnd = (LPBYTE)(pSid);

    // Remove all children, if any
    TreeView_DeleteChildren(hWndTree, hParent);

    // Insert the SID item
    if(pSid != NULL)
        pbEnd += RtlLengthSid(pSid);
    return TV_InsertNewItem(hWndTree, hParent, hInsertAfter, pItemInfo, pbSid, pbEnd);
}

static void TV_InsertNewItemAceFields(
    HWND hWndTree,
    HTREEITEM hParent,
    const ACE_HELPER & AceHelper,
    LPBYTE pbPtr,
    LPBYTE pbEnd)
{
    HTREEITEM hInsertAfter = TVI_FIRST;

    // Special: Save the value of XXX_YYY_OBJECT_ACE::Flags
    if(AceHelper.AceLayout & ACE_FIELD_FLAGS)
        OBJECT_ACE_Flags = AceHelper.Flags;

    // Insert all ACE members according to the bit mask in the ace helper
    for(size_t i = 0; i < _countof(AceFieldInfos); i++)
    {
        ULONG cbMoveBy = 0;

        // Special: Save the value of XXX_YYY_OBJECT_ACE::Flags
        if((AceHelper.AceLayout & ACE_FIELD_FLAGS) && (AceFieldInfos[i].AceLayoutFlag == ACE_FIELD_FLAGS))
            OBJECT_ACE_Flags = AceHelper.Flags;

        // Is that flag present there?
        if(AceHelper.AceLayout & AceFieldInfos[i].AceLayoutFlag)
        {
            hInsertAfter = TV_InsertNewItem(hWndTree,
                                            hParent,
                                            hInsertAfter,
                                           &AceFieldInfos[i].TreeItem,
                                            pbPtr, pbEnd, &cbMoveBy);
            if(hInsertAfter == NULL)
                break;
            pbPtr += cbMoveBy;
        }
    }
}

static HTREEITEM TV_InsertNewItemAce(
    HWND hWndTree,
    HTREEITEM hParent,
    HTREEITEM hInsertAfter,
    PACE_HEADER pAceHeader)
{
    HTREEITEM hAceItem;
    ACE_HELPER AceHelper;
    LPBYTE pbPtr = (LPBYTE)(pAceHeader);
    LPBYTE pbEnd = pbPtr + pAceHeader->AceSize;

    // Reset the XXX_YYY_OBJECT_ACE::Flags
    OBJECT_ACE_Flags = 0;

    // Insert the main ACE item
    hAceItem = TV_InsertNewItem(hWndTree, hParent, hInsertAfter, &TreeItem_Ace, pbPtr, pbEnd);
    if(hAceItem != NULL)
    {
        // Set the ACE to the ACE helper, we can parse the ACE fields easier
        AceHelper.SetAce(pAceHeader);

        // Insert the ACE fields
        TV_InsertNewItemAceFields(hWndTree, hAceItem, AceHelper, pbPtr, pbEnd);
    }
    
    // Reset the XXX_YYY_OBJECT_ACE::Flags
    OBJECT_ACE_Flags = 0;
    return hAceItem;
}

static HTREEITEM TV_InsertNewItemAclFields(
    HWND hWndTree,
    HTREEITEM hParent,
    HTREEITEM hInsertAfter,
    const ACL * pAcl)
{
    LPBYTE pbPtr = (LPBYTE)(pAcl);
    LPBYTE pbEnd = pbPtr + pAcl->AclSize;
    ULONG AceCount = pAcl->AceCount;

    // Insert fields from the ACE header
    for(size_t i = 0; i < _countof(AclFieldInfos); i++)
    {
        ULONG cbMoveBy = 0;

        hInsertAfter = TV_InsertNewItem(hWndTree,
                                        hParent,
                                        hInsertAfter,
                                        AclFieldInfos[i],
                                        pbPtr, pbEnd, &cbMoveBy);
        if(hInsertAfter == NULL)
            break;
        pbPtr += cbMoveBy;
    }

    // Parse the ACEs
    while(AceCount > 0 && (pbPtr + sizeof(ACE_HEADER)) < pbEnd)
    {
        PACE_HEADER pAceHeader = (PACE_HEADER)(pbPtr);

        // Insert the ACE to the list
        if((hInsertAfter = TV_InsertNewItemAce(hWndTree, hParent, hInsertAfter, pAceHeader)) == NULL)
            break;

        // Move the data pointer by the size of the ACE
        pbPtr += pAceHeader->AceSize;
        AceCount--;
    }
    return hInsertAfter;
}

static void TV_InsertNewItemAcl(
    HWND hWndTree,
    HTREEITEM hParent,
    HTREEITEM hInsertAfter,
    PCTREE_ITEM_INFO pItemInfo,
    PACL pAcl,
    BOOLEAN pAclPresent)
{
    HTREEITEM hAclItem;

    // Insert the main item
    if((hAclItem = TV_InsertNewItem(hWndTree, hParent, hInsertAfter, pItemInfo)) != NULL)
    {
        // (pAcl == NULL) can mean either NULL ACL or ACL is not present
        // https://learn.microsoft.com/en-us/windows/win32/secauthz/null-dacls-and-empty-dacls
        if(pAcl == NULL)
        {
            if(pAclPresent)
                TV_InsertNewItem(hWndTree, hAclItem, hInsertAfter, &TreeItem_NullAcl);
            else
                TV_InsertNewItem(hWndTree, hAclItem, hInsertAfter, &TreeItem_NoAcl);
        }

        // If the ACL is valid, insert ACEs. Note that there may be no ACEs present,
        // forming an empty ACL that denies everything to to everyone
        else if (pAcl->AclSize != 0)
        {
            // Insert the ACL fields
            hInsertAfter = TV_InsertNewItemAclFields(hWndTree,
                                                     hAclItem,
                                                     NULL,
                                                     pAcl);
        }
    }
}

static bool TreeView_ItemToSid(HWND hWndTree, HTREEITEM hItem, PSID * ppSid, bool bCanCreateNewSid)
{
    TVITEM tvi;
    TCHAR szItemText[256];

    // Get the text from the treeview item
    tvi.mask = TVIF_TEXT | TVIF_PARAM;
    tvi.hItem = hItem;
    tvi.pszText = szItemText;
    tvi.cchTextMax = _countof(szItemText);
    TreeView_GetItem(hWndTree, &tvi);

    // Convert the tree item to SID
    switch(tvi.lParam)
    {
        case TREE_ITEM_SID_NONE:
        case TREE_ITEM_SID1_NONE:
        case TREE_ITEM_SID2_NONE:
            if(bCanCreateNewSid)
                *ppSid = Sid_CreateNew(ACCESS_ALLOWED_ACE_TYPE);
            break;

        case TREE_ITEM_SID:
        case TREE_ITEM_SID1:
        case TREE_ITEM_SID2:
            //StringToSid(szItemText, ppSid);
            break;
    }

    return (*ppSid != NULL);
}

static bool TreeView_ItemToSid(HWND hWndTree, HTREEITEM hItem, ACE_HELPER & AceHelper, size_t nSidIndex)
{
    PSID pSid = NULL;
    bool bResult = false;

    if(TreeView_ItemToSid(hWndTree, hItem, &pSid, false))
    {
        AceHelper.SetAllocatedSid(pSid, nSidIndex);
        bResult = true;
    }

    return bResult;
}

static bool TreeView_ItemToMandatorySid(HWND hWndTree, HTREEITEM hItem, ACE_HELPER & AceHelper)
{
    DWORD dwIntLevel = SECURITY_MANDATORY_MEDIUM_RID;
    PSID pSid = NULL;
    bool bResult = false;

    // Convert the item to SID
    if(TreeView_ItemToValue32(hWndTree, hItem, &dwIntLevel))
    {
        // Create new mandatory label SID
        //DWORD nSubAuthorities[] = { dwIntLevel };
        //pSid = Sid_AllocateAndInitialize(&SiaLabel, RTL_NUMBER_OF(nSubAuthorities), nSubAuthorities);
        if(pSid != NULL)
        {
            // Store the SID to the ACE_HELPER structure
            AceHelper.SetAllocatedSid(pSid, 0);
            bResult = true;
        }
    }

    return bResult;
}

static bool TreeView_ItemToAce(
    HWND hWndTree,
    HTREEITEM hItem,
    ACE_HELPER & AceHelper)
{
    DWORD dwAceType = 0;

    // Fill the entire structure with zeros
    AceHelper.Reset();

    // Retrieve the (first/next) child
    hItem = TreeView_GetChild(hWndTree, hItem);
    while(hItem != NULL)
    {
        bool bResult = false;

        // Get the values of the ACE according the item type
        switch(TreeView_GetItemParam(hWndTree, hItem))
        {
            case TREE_ITEM_ACE_HEADER_TYPE:     // Save the ACE_Header::AceType
                if(TreeView_ItemToValue32(hWndTree, hItem, &dwAceType))
                    bResult = AceHelper.SetAceType(dwAceType);
                break;

            case TREE_ITEM_ACE_HEADER_FLAGS:    // Save the ACE_Header::AceFlags
                bResult = TreeView_ItemToValue32(hWndTree, hItem, &AceHelper.AceFlags);
                break;

            case TREE_ITEM_ACE_HEADER_SIZE:     // Save the ACE_HEADER::AceSize (even if it will not be used)
                bResult = TreeView_ItemToValue32(hWndTree, hItem, &AceHelper.AceSize);
                break;

            case TREE_ITEM_ACE_MASK:
            case TREE_ITEM_ADS_ACE_MASK:
            case TREE_ITEM_MANDATORY_MASK:
                bResult = TreeView_ItemToValue32(hWndTree, hItem, &AceHelper.Mask);
                break;

            case TREE_ITEM_ACE_FLAGS:
                bResult = TreeView_ItemToValue32(hWndTree, hItem, &AceHelper.Flags);
                break;

            case TREE_ITEM_ACE_OBJ_GUID:
                bResult = TreeView_ItemToGuid(hWndTree, hItem, &AceHelper.ObjectType);
                break;

            case TREE_ITEM_ACE_OBJ_GUID2:
                bResult = TreeView_ItemToGuid(hWndTree, hItem, &AceHelper.InheritedObjectType);
                break;

            case TREE_ITEM_MANDATORY_LABEL:
                bResult = TreeView_ItemToMandatorySid(hWndTree, hItem, AceHelper);
                break;

            case TREE_ITEM_SID1:
                bResult = TreeView_ItemToSid(hWndTree, hItem, AceHelper, 0);
                break;

            case TREE_ITEM_SID2:
                bResult = TreeView_ItemToSid(hWndTree, hItem, AceHelper, 1);
                break;
        }

        // If an error happened, do nothing
        if(!bResult)
            return false;
        hItem = TreeView_GetNextSibling(hWndTree, hItem);
    }

    return true;
}

static bool TreeView_ItemToAcl_Add(
    HWND hWndTree,
    HTREEITEM hItem,
    PACL pAcl)
{
    ACE_HELPER AceHelper;
    LPARAM lParam;
    BOOL bResult = FALSE;

    // Work while we have an ACE item
    while(hItem != NULL)
    {
        // Retrieve the type of the ACE
        lParam = TreeView_GetItemParam(hWndTree, hItem);
        if((lParam & TREE_ITEM_TYPE_MASK) != TREE_ITEM_ACE)
            return false;

        // Retrieve the (first/next) child
        bResult = TreeView_ItemToAce(hWndTree, hItem, AceHelper);
        if(bResult == FALSE)
            return false;

        // Create an ACE that reflects the type
        switch(lParam & TREE_ITEM_VALUE_MASK)
        {
            case ACCESS_ALLOWED_ACE_TYPE:
                bResult = AddAccessAllowedAceEx(pAcl, ACL_REVISION, AceHelper.AceFlags, AceHelper.Mask, AceHelper.Sid[0]);
                break;

            case ACCESS_DENIED_ACE_TYPE:
                bResult = AddAccessDeniedAceEx(pAcl, ACL_REVISION, AceHelper.AceFlags, AceHelper.Mask, AceHelper.Sid[0]);
                break;

            case SYSTEM_AUDIT_ACE_TYPE:
                bResult = AddAuditAccessAceEx(pAcl, ACL_REVISION, AceHelper.AceFlags, AceHelper.Mask, AceHelper.Sid[0], FALSE, FALSE);
                break;

            default:    // Let our helper to add the ACE
                bResult = AceHelper.AddToAcl(pAcl);
                break;
        }

        // Get the next sibling
        hItem = TreeView_GetNextSibling(hWndTree, hItem);
    }

    // We need to free the SID
    return (bool)(bResult != FALSE);
}

static BOOL TreeView_ItemToAcl(
    HWND hWndTree,
    HTREEITEM hAclItem1,
    HTREEITEM hAclItem2,
    PACL * ppAcl)
{
    LPARAM lParam1;
    PACL pAcl = NULL;

    // The variant with no ACLs
    if(hAclItem1 == NULL && hAclItem2 == NULL)
    {
        *ppAcl = NULL;
        return TRUE;
    }

    // The variant with only one tree item
    if(hAclItem1 != NULL && hAclItem2 == NULL)
    {
        // Retrieve the item param
        lParam1 = TreeView_GetItemParam(hWndTree, hAclItem1);

        // If the param means NULL ACL, give the caller a NULL ACL
        if(lParam1 == TREE_ITEM_NULL_ACL)
        {
            *ppAcl = NULL;
            return TRUE;
        }

        // If the param means an empty ACL, create an empty ACL
        if(lParam1 == TREE_ITEM_EMPTY_ACL)
        {
            *ppAcl = Acl_CreateEmpty(sizeof(ACL));
            return TRUE;
        }
    }

    // Build a new ACL of the maximum size
    assert(hAclItem1 || hAclItem2);
    pAcl = Acl_CreateEmpty();
    if(pAcl == NULL)
        return FALSE;

    // If the primary item is an ACL item, we insert all ACEs to the ACL
    if(hAclItem1 != NULL)
        TreeView_ItemToAcl_Add(hWndTree, hAclItem1, pAcl);

    // If the secondary item is an ACL item, we insert all ACEs to the ACL
    if(hAclItem2 != NULL)
        TreeView_ItemToAcl_Add(hWndTree, hAclItem2, pAcl);

    // Finalize the ACL
    *ppAcl = Acl_FinishBuild(pAcl);
    return TRUE;
}

static void TreeView_SecurityDescriptorToTreeView(
    HWND hWndTree,
    PSECURITY_DESCRIPTOR pSD)
{
    HTREEITEM hItem;
    TCHAR szNotPresent[128];
    PSID pOwner = NULL;
    PSID pGroup = NULL;
    PACL pAcl = NULL;
    BOOLEAN bDefaulted;
    BOOLEAN bAclPresent;

    // Turn off redrawing for faster response
    SendMessage(hWndTree, WM_SETREDRAW, FALSE, 0);

    // Clear all current tree view items
    TreeView_DeleteAllItems(hWndTree);
    LoadString(g_hInst, IDS_NOT_PRESENT, szNotPresent, _countof(szNotPresent));

    //
    // Insert tree item for owner security information
    //

    hItem = TV_InsertNewItem(hWndTree, NULL, NULL, &TreeItem_Owner);
    RtlGetOwnerSecurityDescriptor(pSD, &pOwner, &bDefaulted);
    TV_InsertNewItemSid(hWndTree, hItem, NULL, &TreeItem_UserSid, pOwner);

    //
    // Insert tree item for group security information
    //

    hItem = TV_InsertNewItem(hWndTree, NULL, NULL, &TreeItem_Group);
    RtlGetGroupSecurityDescriptor(pSD, &pGroup, &bDefaulted);
    TV_InsertNewItemSid(hWndTree, hItem, NULL, &TreeItem_UserSid, pGroup);

    //
    // Insert tree item for DACL security information
    //

    pAcl = NULL;
    bAclPresent = FALSE;
    RtlGetDaclSecurityDescriptor(pSD, &bAclPresent, &pAcl, &bDefaulted);
    TV_InsertNewItemAcl(hWndTree, NULL, NULL, &TreeItem_Dacl, pAcl, bAclPresent);

    //
    // Insert tree item for SACL security information
    //

    pAcl = NULL;
    bAclPresent = FALSE;
    RtlGetSaclSecurityDescriptor(pSD, &bAclPresent, &pAcl, &bDefaulted);
    TV_InsertNewItemAcl(hWndTree, NULL, NULL, &TreeItem_Sacl, pAcl, bAclPresent);

    // Enable redrawing back
    SendMessage(hWndTree, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hWndTree, NULL, TRUE);
}

void TreeView_DeferItemText(HWND hDlg, WPARAM wParam, LPARAM lParam)
{
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    TVITEM tvi;

    // Apply the text to the tree item
    tvi.mask    = TVIF_TEXT;
    tvi.hItem   = (HTREEITEM)wParam;
    tvi.pszText = (LPTSTR)lParam;
    TreeView_SetItem(hWndTree, &tvi);

    // Free the text
    delete [] tvi.pszText;
}

static SECURITY_INFORMATION GetDialogSecurityInfo(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    // Clear all five main flags
    pData->SecurityInformation &= ~(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION);

    // Set all flags whose check box is set
    if(IsDlgButtonChecked(hDlg, IDC_OWNER_INFORMATION) == BST_CHECKED)
        pData->SecurityInformation |= OWNER_SECURITY_INFORMATION;
    if(IsDlgButtonChecked(hDlg, IDC_GROUP_INFORMATION) == BST_CHECKED)
        pData->SecurityInformation |= GROUP_SECURITY_INFORMATION;
    if(IsDlgButtonChecked(hDlg, IDC_DACL_INFORMATION) == BST_CHECKED)
        pData->SecurityInformation |= DACL_SECURITY_INFORMATION;
    if(IsDlgButtonChecked(hDlg, IDC_SACL_INFORMATION) == BST_CHECKED)
        pData->SecurityInformation |= SACL_SECURITY_INFORMATION;
    if(IsDlgButtonChecked(hDlg, IDC_LABEL_INFORMATION) == BST_CHECKED)
        pData->SecurityInformation |= LABEL_SECURITY_INFORMATION;
    return pData->SecurityInformation;
}

static void SetDialogSecurityInfo(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    int nChecked;

    nChecked = (pData->SecurityInformation & OWNER_SECURITY_INFORMATION) ? BST_CHECKED : BST_UNCHECKED;
    CheckDlgButton(hDlg, IDC_OWNER_INFORMATION, nChecked);

    nChecked = (pData->SecurityInformation & GROUP_SECURITY_INFORMATION) ? BST_CHECKED : BST_UNCHECKED;
    CheckDlgButton(hDlg, IDC_GROUP_INFORMATION, nChecked);

    nChecked = (pData->SecurityInformation & DACL_SECURITY_INFORMATION) ? BST_CHECKED : BST_UNCHECKED;
    CheckDlgButton(hDlg, IDC_DACL_INFORMATION, nChecked);

    nChecked = (pData->SecurityInformation & SACL_SECURITY_INFORMATION) ? BST_CHECKED : BST_UNCHECKED;
    CheckDlgButton(hDlg, IDC_SACL_INFORMATION, nChecked);

    nChecked = (pData->SecurityInformation & LABEL_SECURITY_INFORMATION) ? BST_CHECKED : BST_UNCHECKED;
    CheckDlgButton(hDlg, IDC_LABEL_INFORMATION, nChecked);
}

static void UpdateContextMenu(HWND hWndTree, HTREEITEM hItem, HMENU hMainMenu)
{
    HMENU hSubMenu = GetSubMenu(hMainMenu, 0);
    UINT uEnabled;

    // Move ACE up is only allowed when the ACE is not the first one
    uEnabled = (TV_GetAceSibling(hWndTree, hItem, FALSE) == NULL) ? MF_GRAYED : MF_ENABLED;
    EnableMenuItem(hSubMenu, IDC_MOVE_ACE_UP, uEnabled);

    // Move ACE down is only allowed when the ACE is not the last one
    uEnabled = (TV_GetAceSibling(hWndTree, hItem, TRUE) == NULL) ? MF_GRAYED : MF_ENABLED;
    EnableMenuItem(hSubMenu, IDC_MOVE_ACE_DOWN, uEnabled);
}

static HTREEITEM TreeView_GetPreviousItem(HWND hWndTree, HTREEITEM hItem)
{
    hItem = TreeView_GetPrevSibling(hWndTree, hItem);
    if(hItem == NULL)
        hItem = TVI_FIRST;

    return hItem;
}

static BOOL DeferSetItemTextValue(HWND hDlg, HTREEITEM hItem, LPCTSTR szItemText)
{
    LPTSTR szBuffer;
    
    // Create copy of the buffer
    if((szBuffer = NewStr(szItemText)) == NULL)
        return FALSE;

    // Yes, accept changes
    PostMessage(hDlg, WM_DEFER_ITEM_TEXT, (WPARAM)(hItem), (LPARAM)(szBuffer));
    return TRUE;
}

static NTSTATUS QueryObjectSecurity(HANDLE hObject, SECURITY_INFORMATION SecInfo, PSECURITY_DESCRIPTOR * ppSD, DWORD * pcbSD)
{
    PSECURITY_DESCRIPTOR lpSD = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    DWORD dwTryCount = 0;
    ULONG cbSD = 0;

    // Try 5 times at the most
    while(dwTryCount++ < 5)
    {
        // Try to query the object security into the current buffer
        Status = NtQuerySecurityObject(hObject, SecInfo, lpSD, cbSD, &cbSD);
        if(NT_SUCCESS(Status))
            break;

        // Free the old buffer
        if(lpSD != NULL)
            HeapFree(g_hHeap, 0, lpSD);
        lpSD = NULL;

        // Allocate new buffer
        if((lpSD = (PSECURITY_DESCRIPTOR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, cbSD)) == NULL)
        {
            Status = STATUS_NO_MEMORY;
            break;
        }
    }

    // If we are trying too many times, bail out
    ppSD[0] = lpSD;
    pcbSD[0] = cbSD;
    return Status;
}

//-----------------------------------------------------------------------------
// Message handlers

static TAnchors * pAnchors = NULL;

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    TFileTestData * pData;
    PROPSHEETPAGE * pPage = (PROPSHEETPAGE *)lParam;

    // Remember the data pointer
    SetDialogData(hDlg, pPage->lParam);
    pData = (TFileTestData *)pPage->lParam;

    // Initialize the "More ..." hyperlink
    InitURLButton(hDlg, IDC_MORE_SECURITY_INFORMATION, FALSE);

    // Configure dialog resizing
    if(pData->bEnableResizing)
    {
        pAnchors = new TAnchors();
        pAnchors->AddAnchor(hDlg, IDC_MAIN_FRAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SECURITY, akAll);
        pAnchors->AddAnchor(hDlg, IDC_QUERY_SECURITY, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_SET_BLANK, akLeftCenter | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_SET_SECURITY, akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_FRAME, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_INFORMATION_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_INFORMATION, akLeft | akRight | akBottom);
    }

    // Set the security information to the dialog
    SetDialogSecurityInfo(hDlg);

    // Set blank security descriptor
    PostMessage(hDlg, WM_COMMAND, MAKEWPARAM(IDC_SET_BLANK, BN_CLICKED), 0);
    return TRUE;
}

static int OnSetAclType(HWND hDlg, UINT nIDCtrl)
{
    PTREE_ITEM_INFO pItemInfo;
    HTREEITEM hItem;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    PACL pAcl;

    // Get the selected item
    if((hItem = TreeView_GetSelection(hWndTree)) != NULL)
    {
        // Retrieve the item info
        if((pItemInfo = TV_GetItemParam(hWndTree, hItem)) != NULL)
        {
            // The item must be DACL or SACL
            if(pItemInfo->ItemType == ItemTypeDacl || pItemInfo->ItemType == ItemTypeSacl)
            {
                // Delete all children
                TreeView_DeleteChildren(hWndTree, hItem);

                // For each item, do the specific action
                switch(nIDCtrl)
                {
                    case IDC_SET_NULL_ACL:
                    {
                        TV_InsertNewItem(hWndTree, hItem, NULL, &TreeItem_NullAcl);
                        break;
                    }

                    case IDC_SET_EMPTY_ACL:
                    {
                        TV_InsertNewItemAclFields(hWndTree, hItem, NULL, &EmptyAcl);
                        break;
                    }

                    case IDC_SET_FULL_CONTROL:
                    {
                        if((pAcl = Acl_CreateNew()) != NULL)
                        {
                            TV_InsertNewItemAclFields(hWndTree, hItem, NULL, pAcl);
                            LocalFree(pAcl);
                        }
                        break;
                    }
                }
            }
        }
    }
    return TRUE;
}

static int OnInsertSiblingAce(HWND hDlg, BOOL bBeforeSelected)
{
    PTREE_ITEM_INFO pItemInfo;
    HTREEITEM hParent;
    HTREEITEM hItem = NULL;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    BYTE AceBuffer[256];

    // Retrieve the currently selected item
    if((hItem = TreeView_GetSelection(hWndTree)) != NULL)
    {
        // Get the parent item
        hParent = TreeView_GetParent(hWndTree, hItem);

        // Get the item info of the *parent* item
        if((pItemInfo = TV_GetItemParam(hWndTree, hParent)) != NULL)
        {
            HTREEITEM hInsertAfter = hItem;
            size_t cbAceBuffer = sizeof(AceBuffer);

            // Get previous or next
            if(bBeforeSelected)
            {
                if((hInsertAfter = TreeView_GetPreviousItem(hWndTree, hItem)) == NULL)
                {
                    hInsertAfter = TVI_FIRST;
                }
            }

            // Insert the item
            if(CreateNew_Ace(pItemInfo, AceBuffer, &cbAceBuffer))
            {
                hItem = TV_InsertNewItemAce(hWndTree, hParent, hInsertAfter, (PACE_HEADER)(AceBuffer));
                if(hItem != NULL)
                {
                    TreeView_Select(hWndTree, hItem, TVGN_CARET);
                }
            }
        }
    }
    return TRUE;
}

static int OnSwapAceWith(HWND hDlg, BOOL bWithPrevious)
{
    ACE_HELPER AceHelper1;
    ACE_HELPER AceHelper2;
    HTREEITEM hSwapWith;
    HTREEITEM hParent;
    HTREEITEM hItem;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);

    // Retrieve the item where to insert it
    hItem = TreeView_GetSelection(hWndTree);
    hParent = TreeView_GetParent(hWndTree, hItem);

    // Get the previous or next item to swap with
    if(bWithPrevious == FALSE)
    {
        hSwapWith = TreeView_GetNextSibling(hWndTree, hItem);
        TV_SwapItems(hWndTree, hParent, hItem, hParent, hSwapWith);
    }
    else
    {
        hSwapWith = TreeView_GetPrevSibling(hWndTree, hItem);
        TV_SwapItems(hWndTree, hParent, hSwapWith, hParent, hItem);
    }

    // Select the target item
    TreeView_Select(hWndTree, hSwapWith, TVGN_CARET);
    return TRUE;
}

static int OnSetAceType(HWND hDlg)
{
    PCTREE_ITEM_INFO pItemInfo;
    PACE_HEADER pAceHeader = NULL;
    ACE_HELPER AceHelper;
    HTREEITEM hItem;
    DWORD dwAceType = ACCESS_ALLOWED_ACE_TYPE;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    BYTE AceBuffer[256];

    if((hItem = TreeView_GetSelection(hWndTree)) != NULL)
    {
        if((pItemInfo = TV_GetItemParam(hWndTree, hItem)) != NULL)
        {
            // Retrieve the current ACE type
            dwAceType = TV_GetAceType(hWndTree, hItem);

            // Ask the user for new ACE type
            if(FlagsDialog(hDlg, IDS_ACE_TYPE, AceHdrTypes, dwAceType) == IDOK)
            {
                // Stop redrawing
                SendMessage(hWndTree, WM_SETREDRAW, FALSE, 0);

                // Set the ACE type
                if(AceHelper.SetAceType(dwAceType))
                {
                    // Set the GENERIC_ALL to the mask
                    AceHelper.Mask = GENERIC_ALL;

                    // Build the ACE
                    if((pAceHeader = AceHelper.BuildAce(AceBuffer, sizeof(AceBuffer))) != NULL)
                    {
                        LPBYTE pbPtr = (LPBYTE)(pAceHeader);
                        LPBYTE pbEnd = pbPtr + pAceHeader->AceSize;
                        TCHAR szItemText[128];

                        // Update the item text of the parent item
                        ToString_Ace(pItemInfo, szItemText, _countof(szItemText), pbPtr, pbEnd);
                        TreeView_SetItemText(hWndTree, hItem, szItemText);

                        // Insert the new children
                        TreeView_DeleteChildren(hWndTree, hItem);
                        TV_InsertNewItemAceFields(hWndTree, hItem, AceHelper, pbPtr, pbEnd);

                        // Select the root item
                        TreeView_SelectItem(hWndTree, hItem);
                    }
                }

                // Enable redrawing back
                SendMessage(hWndTree, WM_SETREDRAW, TRUE, 0);
                InvalidateRect(hWndTree, NULL, TRUE);

                // If something failed, show the error
                if(pAceHeader == NULL)
                {
                    SetResultInfo(hDlg, RSI_NTSTATUS, STATUS_CANNOT_EDIT_THIS);
                }
            }
        }
    }
    return TRUE;
}

static int OnDeleteAce(HWND hDlg)
{
    HTREEITEM hParent;
    HTREEITEM hItem;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    DWORD dwChildCount;

    hItem = TreeView_GetSelection(hWndTree);
    hParent = TreeView_GetParent(hWndTree, hItem);
    if(hParent != NULL && hItem != NULL)
    {
        // Delete the tree item
        if(TreeView_DeleteItem(hWndTree, hItem))
        {
            // Retrieve the child count
            dwChildCount = TreeView_GetChildCount(hWndTree, hParent);
            if(dwChildCount == 0)
            {
                // Insert the ACL as empty
                hItem = InsertTreeItem(hWndTree, hParent, szEmptyAcl, TREE_ITEM_EMPTY_ACL);
                TreeView_Select(hWndTree, hItem, TVGN_CARET);
            }
        }
    }

    return TRUE;
}

static int OnSetBlankSecurityDescriptor(HWND hDlg)
{
    SECURITY_DESCRIPTOR sd;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);

    // Initialize the tree view with blank security descriptor
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    TreeView_SecurityDescriptorToTreeView(hWndTree, &sd);
    return TRUE;
}

static int OnMoreSecurityInformation(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    // Read the security information from this dialog
    GetDialogSecurityInfo(hDlg);
    FlagsDialog(hDlg, IDS_SECURITY_INFORMATION, SecurityInformations, pData->SecurityInformation);
    SetDialogSecurityInfo(hDlg);
    return TRUE;
}

static int OnQuerySecurity(HWND hDlg)
{
    PSECURITY_DESCRIPTOR lpSD = NULL;
    TFileTestData * pData = GetDialogData(hDlg);
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG cbSD = 0;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);

    // Get the mask about which security information we want
    GetDialogSecurityInfo(hDlg);

    // Query the security information
    Status = QueryObjectSecurity(pData->hFile, pData->SecurityInformation, &lpSD, &cbSD);

    // If succeeded, load our tree view with security information
    if(NT_SUCCESS(Status))
        TreeView_SecurityDescriptorToTreeView(hWndTree, lpSD);
    if(lpSD != NULL)
        HeapFree(g_hHeap, 0, lpSD);
    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_INFO_INT32, Status, cbSD);
    return TRUE;
}

static int OnSetSecurity(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    SECURITY_DESCRIPTOR sd;
    SECURITY_INFORMATION AppliedSecInfo = 0;
    HTREEITEM hChildItem[5];
    HTREEITEM hAclItem1 = NULL;
    HTREEITEM hAclItem2 = NULL;
    HTREEITEM hItem;
    NTSTATUS Status = STATUS_SUCCESS;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    PSID pOwner = NULL;
    PSID pGroup = NULL;
    PACL pDacl = NULL;
    PACL pSacl = NULL;

    // Get the mask about which security information we want
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    GetDialogSecurityInfo(hDlg);

    // Get handles of all child items
    hChildItem[0] = TreeView_GetChild(hWndTree, TVI_ROOT);
    hChildItem[1] = TreeView_GetNextSibling(hWndTree, hChildItem[0]);
    hChildItem[2] = TreeView_GetNextSibling(hWndTree, hChildItem[1]);
    hChildItem[3] = TreeView_GetNextSibling(hWndTree, hChildItem[2]);
    hChildItem[4] = TreeView_GetNextSibling(hWndTree, hChildItem[3]);

    //
    // Put owner into the security descriptor
    //

    if(pData->SecurityInformation & OWNER_SECURITY_INFORMATION)
    {
        hItem = TreeView_GetChild(hWndTree, hChildItem[0]);
        if(hItem != NULL)
        {
            if(TreeView_ItemToSid(hWndTree, hItem, &pOwner, false) && pOwner != NULL)
            {
                SetSecurityDescriptorOwner(&sd, pOwner, FALSE);
                AppliedSecInfo |= OWNER_SECURITY_INFORMATION;
            }
        }
    }

    //
    // Put group into the security descriptor
    //

    if(pData->SecurityInformation & GROUP_SECURITY_INFORMATION)
    {
        hItem = TreeView_GetChild(hWndTree, hChildItem[1]);
        if(hItem != NULL)
        {
            if(TreeView_ItemToSid(hWndTree, hItem, &pGroup, false) && pGroup != NULL)
            {
                SetSecurityDescriptorGroup(&sd, pGroup, FALSE);
                AppliedSecInfo |= GROUP_SECURITY_INFORMATION;
            }
        }
    }

    //
    // Put DACL into the security descriptor
    //

    if(pData->SecurityInformation & DACL_SECURITY_INFORMATION)
    {
        hItem = TreeView_GetChild(hWndTree, hChildItem[2]);
        if(hItem != NULL)
        {
            if(TreeView_ItemToAcl(hWndTree, hItem, NULL, &pDacl))
            {
                SetSecurityDescriptorDacl(&sd, TRUE, pDacl, FALSE);
                AppliedSecInfo |= DACL_SECURITY_INFORMATION;
            }
        }
    }

    //
    // Put SACL into the security descriptor
    // Note: We have to combine SACL from two tree items
    //

    if(pData->SecurityInformation & (SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION))
    {
        // Get handles to wanted tree items
        if(pData->SecurityInformation & SACL_SECURITY_INFORMATION)
            hAclItem1 = TreeView_GetChild(hWndTree, hChildItem[3]);
        if(pData->SecurityInformation & LABEL_SECURITY_INFORMATION)
            hAclItem2 = TreeView_GetChild(hWndTree, hChildItem[4]);

        if(TreeView_ItemToAcl(hWndTree, hAclItem1, hAclItem2, &pSacl))
        {
            SetSecurityDescriptorSacl(&sd, TRUE, pSacl, FALSE);
            AppliedSecInfo |= (pData->SecurityInformation & (SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION));
        }
    }

    // Apply the security descriptor to the file
    if(AppliedSecInfo != 0)
    {
        // Set the result to the dialog controls
        Status = NtSetSecurityObject(pData->hFile, AppliedSecInfo, &sd);
        SetResultInfo(hDlg, RSI_NTSTATUS | RSI_NOINFO, Status);
    }

    // Free all 4 parts of the security information
    if(pSacl != NULL)
        HeapFree(g_hHeap, 0, pSacl);
    if(pDacl != NULL)
        HeapFree(g_hHeap, 0, pDacl);
    if(pGroup != NULL)
        RtlFreeSid(pGroup);
    if(pOwner != NULL)
        RtlFreeSid(pOwner);
    return TRUE;
}

static int OnSetActive(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    BOOL bEnable = FALSE;

    if(IsHandleValid(pData->hFile))
        bEnable = TRUE;
    EnableDlgItems(hDlg, bEnable, IDC_QUERY_SECURITY, IDC_SET_SECURITY, 0);

    return TRUE;
}

static int OnBeginLabelEdit(HWND hDlg, LPNMTVDISPINFO pTVDispInfo)
{
    PTREE_ITEM_INFO pItemInfo = (PTREE_ITEM_INFO)(pTVDispInfo->item.lParam);
    HWND hWndTree = pTVDispInfo->hdr.hwndFrom;
    HWND hWndEdit;
    BOOL bStartEditing = FALSE;
    TCHAR szEditText[256];

    // Both ToString and StringTo methods must be present
    if(pItemInfo && pItemInfo->ToString && pItemInfo->StringTo)
    {
        // Convert the item text to the editable text
        if(TV_TextToEditText(pItemInfo, szEditText, _countof(szEditText), pTVDispInfo->item.pszText))
        {
            // Retrieve the handle to the edit box
            if((hWndEdit = TreeView_GetEditControl(hWndTree)) != NULL)
            {
                // Apply the text limit to the edit text
                Edit_LimitText(hWndEdit, GetDefaultCharLimit(pItemInfo));

                // Apply the editable text to the edit field
                SetWindowText(hWndEdit, szEditText);
                bStartEditing = TRUE;
            }
        }
    }

    // If the editing started successfully, 
    // make sure that Esc key will not close the entire FileTest
    if(bStartEditing)
    {
        DisableCloseDialog(hDlg, bStartEditing);
        SetWindowLongPtr(hDlg, DWLP_MSGRESULT, FALSE);
    }
    else
    {
        SetResultInfo(hDlg, RSI_NTSTATUS, STATUS_CANNOT_EDIT_THIS);
        SetWindowLongPtr(hDlg, DWLP_MSGRESULT, TRUE);
    }
    return TRUE;
}

static int OnEndLabelEdit(HWND hDlg, LPNMTVDISPINFO pTVDispInfo)
{
    PTREE_ITEM_INFO pItemInfo = (PTREE_ITEM_INFO)(pTVDispInfo->item.lParam);
    LPBYTE pbBuffer;
    ULONG cbBuffer = 0x1000;
    ULONG cbMoveBy = 0;
    BOOL bAcceptChanges = FALSE;
    TCHAR szItemText[256];

    // If pszText contains NULL, it means that the user cancelled the editing
    if(pTVDispInfo->item.pszText && pTVDispInfo->item.pszText[0])
    {
        // Do we have the "EndEdit" callback?
        if(pItemInfo && pItemInfo->ToString && pItemInfo->StringTo)
        {
            if((pbBuffer = (LPBYTE)LocalAlloc(LPTR, cbBuffer)) != NULL)
            {
                // First we convert the item to binary format
                if(pItemInfo->StringTo(pItemInfo, pTVDispInfo->item.pszText, pbBuffer, pbBuffer + cbBuffer, &cbMoveBy))
                {
                    // Convert the item to text
                    TV_MakeItemText(pItemInfo, szItemText, _countof(szItemText), pbBuffer, pbBuffer + cbMoveBy);
                    bAcceptChanges = DeferSetItemTextValue(hDlg, pTVDispInfo->item.hItem, szItemText);
                }
                else
                {
                    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_INFO_INT32, STATUS_INVALID_DATA_FORMAT, 0);
                }

                LocalFree(pbBuffer);
            }
        }
    }

    // Enable the exit button
    DisableCloseDialog(hDlg, FALSE);
    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, bAcceptChanges);
    return TRUE;
}

static int OnDeleteItem(HWND /* hDlg */, LPNMTREEVIEW pNMTreeView)
{
    if(pNMTreeView->itemOld.lParam != NULL)
        HeapFree(g_hHeap, 0, (LPVOID)(pNMTreeView->itemOld.lParam));
    return TRUE;
}

static int OnTVContextMenu(HWND hDlg, LPARAM lParam)
{
    PTREE_ITEM_INFO pItemInfo;
    HTREEITEM hItem;
    POINT pt;
    HMENU hMainMenu = NULL;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    RECT rect;

    // Get the selected item
    if((hItem = TreeView_GetSelection(hWndTree)) != NULL)
    {
        // Get the LPARAM of the tree item.
        if((pItemInfo = TV_GetItemParam(hWndTree, hItem)) != NULL)
        {
            switch(pItemInfo->ItemType)
            {
                case ItemTypeDacl:
                case ItemTypeSacl:
                    hMainMenu = FindContextMenu(IDR_ACL_TYPE_MENU);
                    break;

                case ItemTypeAce:
                    hMainMenu = FindContextMenu(IDR_ACE_MENU);
                    break;
            }
        }

        // If we picked a menu, execute it
        if(hMainMenu != 0)
        {
            // Update the menu
            UpdateContextMenu(hWndTree, hItem, hMainMenu);

            // If we don't have the coords, make them from the tree item
            if(lParam == 0xFFFFFFFF)
            {
                TreeView_GetItemRect(hWndTree, hItem, &rect, TRUE);
                pt.x = rect.left;
                pt.y = rect.bottom;
                ClientToScreen(hWndTree, &pt);
                lParam = MAKELPARAM(pt.x, pt.y);
            }

            // Execute the menu
            return ExecuteContextMenu(hDlg, hMainMenu, lParam);
        }
    }

    return FALSE;
}

static int OnTVRightClick(HWND hDlg)
{
    TVHITTESTINFO hti;
    HTREEITEM hItem;
    POINT pt;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);

    // Select the right-clicked tree view item
    GetCursorPos(&pt);
    ScreenToClient(hWndTree, &pt);
    hti.pt = pt;
    hti.flags = TVHT_ONITEMLABEL;
    hItem = TreeView_HitTest(hWndTree, &hti);

    // If there is an item clicked, select it
    if(hItem != NULL)
        TreeView_Select(hWndTree, hItem, TVGN_CARET);

    return FALSE;
}

static int OnTVDoubleClick(HWND hDlg)
{
    PTREE_ITEM_INFO pItemInfo;
    TREE_ITEM_INFO SaveItemInfo;
    HTREEITEM hInsertAfter = TVI_FIRST;
    HTREEITEM hParent;
    HTREEITEM hItem;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    BYTE DataBuffer[0x200];
    size_t cbDataBuffer = sizeof(DataBuffer);

    // Reset the XXX_YYY_OBJECT_ACE::Flags
    OBJECT_ACE_Flags = 0;

    // Get the handle to the selected item
    if((hItem = TreeView_GetSelection(hWndTree)) != NULL)
    {
        // Retrieve the parent of the item
        hParent = TreeView_GetParent(hWndTree, hItem);

        // Retrieve the tree item info of the selected item
        if((pItemInfo = TV_GetItemParam(hWndTree, hItem)) != NULL)
        {
            // Double click on ACE root brings the possibility to choose ACE type
            if(pItemInfo->ItemType == ItemTypeAce)
            {
                PostMessage(hDlg, WM_COMMAND, MAKEWPARAM(IDC_SET_ACE_TYPE, 0), 0);
                SetWindowLongPtr(hDlg, DWLP_MSGRESULT, TRUE);
                return TRUE;
            }

            // Save the item info to the stack
            memcpy(&SaveItemInfo, pItemInfo, sizeof(TREE_ITEM_INFO));
            pItemInfo = &SaveItemInfo;

            // Does the item have handler for double click?
            if(pItemInfo->CreateNew != NULL && pItemInfo->ItemData != ItemDataValid)
            {
                PTREE_ITEM_INFO pNewInfo = pItemInfo;

                // Special case: When replacing NO_ACL or NULL_ACL, we want to pass parent item
                if(pItemInfo->ItemType == ItemTypeNoAcl || pItemInfo->ItemType == ItemTypeNullAcl)
                    pNewInfo = TV_GetItemParam(hWndTree, hParent);

                // Let the item to create new one
                if(pItemInfo->CreateNew(pNewInfo, DataBuffer, &cbDataBuffer))
                {
                    // Get the previous item
                    hInsertAfter = TreeView_GetPreviousItem(hWndTree, hItem);

                    // Delete the subitems of the item
                    TreeView_DeleteItem(hWndTree, hItem);

                    // Insert the new item with the created data
                    switch(SaveItemInfo.ItemType)
                    {
                        case ItemTypeGuid:
                        case ItemTypeGuid2:
                            TV_InsertNewItem(hWndTree, hParent, hInsertAfter, &SaveItemInfo, DataBuffer, &DataBuffer[cbDataBuffer]);
                            break;

                        case ItemTypeSid:
                            TV_InsertNewItemSid(hWndTree, hParent, hInsertAfter, &SaveItemInfo, (PSID)(DataBuffer));
                            break;

                        case ItemTypeNoAcl:
                            TV_InsertNewItemAclFields(hWndTree, hParent, hInsertAfter, (PACL)(DataBuffer));
                            break;
                    }
                }
            }
        }
    }
/*
    // The ACE type item is the same like the ACE type subitem
    if(IsTreeItemAce(lParam))
    {
        lParam = TREE_ITEM_ACE_HEADER_TYPE;
        bGoToParent = false;
    }

    // Edit the item
    switch(lParam)
    {
        case TREE_ITEM_SID_NONE:
        case TREE_ITEM_SID1_NONE:
        case TREE_ITEM_SID2_NONE:
            OnCreateNewSid(hDlg, hWndTree, hSelItem);
            break;

        case TREE_ITEM_ACE_HEADER_TYPE:
            if(bGoToParent)
                hSelItem = TreeView_GetParent(hWndTree, hSelItem);
            OnEditAceTypeModal(hDlg, hWndTree, hSelItem);
            break;

        case TREE_ITEM_ACE_HEADER_FLAGS:
            OnEditNumericItemModal(hDlg, hWndTree, hSelItem, AceHdrFlags, szAceHdrFlagsFmt, IDS_ACE_FLAGS);
            break;

        case TREE_ITEM_ACE_MASK:
            OnEditNumericItemModal(hDlg, hWndTree, hSelItem, AceMasks, szAceMaskFmt, IDS_ACE_MASK);
            break;

        case TREE_ITEM_ADS_ACE_MASK:
            OnEditNumericItemModal(hDlg, hWndTree, hSelItem, AdsAceMasks, szAceMaskFmt, IDS_ADS_ACE_MASK);
            break;

        case TREE_ITEM_MANDATORY_MASK:
            OnEditNumericItemModal(hDlg, hWndTree, hSelItem, MandatoryMasks, szAceMaskFmt, IDS_MANDATORY_MASK);
            break;

        case TREE_ITEM_ACE_OBJ_GUID:
        case TREE_ITEM_ACE_OBJ_GUID2:
            ObjectGuidHelpDialog(hDlg);
            break;

        case TREE_ITEM_MANDATORY_LABEL:
            OnEditNumericItemModal(hDlg, hWndTree, hSelItem, IntgrLevels, szIntLevelFmt, IDS_INTEGRITY_LEVEL);
            break;
    }
*/
    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, TRUE);
    return TRUE;
}

static void OnTVKeyDown(HWND hDlg, NMTVKEYDOWN * pNMTVKeyDown)
{
    if(pNMTVKeyDown->wVKey == VK_SPACE)
    {
        OnTVDoubleClick(hDlg);
        return;
    }

    if(pNMTVKeyDown->wVKey == 'C' && GetAsyncKeyState(VK_CONTROL) < 0)
    {
        TreeView_CopyToClipboard(pNMTVKeyDown->hdr.hwndFrom);
        return;
    }
}

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    if(nNotify == BN_CLICKED || nNotify == 1)
    {
        switch(nIDCtrl)
        {
            case ID_EDIT_LABEL:
                return TreeView_EditLabel_ID(hDlg, IDC_SECURITY);

            case ID_DOUBLE_CLICK:
                return OnTVDoubleClick(hDlg);

            case IDC_SET_NULL_ACL:
            case IDC_SET_EMPTY_ACL:
            case IDC_SET_FULL_CONTROL:
                return OnSetAclType(hDlg, nIDCtrl);

            case IDC_NEW_ACE_BEFORE:
                return OnInsertSiblingAce(hDlg, TRUE);

            case IDC_NEW_ACE_AFTER:
                return OnInsertSiblingAce(hDlg, FALSE);

            case IDC_MOVE_ACE_UP:
                return OnSwapAceWith(hDlg, TRUE);

            case IDC_MOVE_ACE_DOWN:
                return OnSwapAceWith(hDlg, FALSE);

            case IDC_SET_ACE_TYPE:
                return OnSetAceType(hDlg);

            case IDC_DELETE_ACE:
                return OnDeleteAce(hDlg);

            case IDC_SET_BLANK:
                return OnSetBlankSecurityDescriptor(hDlg);

            case IDC_MORE_SECURITY_INFORMATION:
                return OnMoreSecurityInformation(hDlg);

            case IDC_QUERY_SECURITY:
                return OnQuerySecurity(hDlg);

            case IDC_SET_SECURITY:
                return OnSetSecurity(hDlg);
        }
    }
    return FALSE;
}

static int OnNotify(HWND hDlg, NMHDR * pNMHDR)
{
    switch(pNMHDR->code)
    {
        case PSN_SETACTIVE:
            return OnSetActive(hDlg);

        case NM_RCLICK:
            if(pNMHDR->idFrom == IDC_SECURITY)
                return OnTVRightClick(hDlg);
            break;

        case NM_DBLCLK:
            if(pNMHDR->idFrom == IDC_SECURITY)
                return OnTVDoubleClick(hDlg);
            break;

        case TVN_KEYDOWN:
            OnTVKeyDown(hDlg, (NMTVKEYDOWN *)pNMHDR);
            break;

        case TVN_BEGINLABELEDIT:
            return OnBeginLabelEdit(hDlg, (LPNMTVDISPINFO)pNMHDR);

        case TVN_ENDLABELEDIT:
            return OnEndLabelEdit(hDlg, (LPNMTVDISPINFO)pNMHDR);

        case TVN_DELETEITEM:
            return OnDeleteItem(hDlg, (LPNMTREEVIEW)pNMHDR);
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// Public functions

INT_PTR CALLBACK PageProc09(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // Handlers specific to our dialog
    switch(uMsg)
    {
        case WM_INITDIALOG:
            OnInitDialog(hDlg, lParam);
            return TRUE;

        case WM_SIZE:
            if(pAnchors != NULL)
                pAnchors->OnSize();
            return FALSE;

        case WM_DRAWITEM:
            if(wParam == IDC_MORE_SECURITY_INFORMATION)
                DrawURLButton(hDlg, (LPDRAWITEMSTRUCT)lParam);
            return TRUE;

        case WM_DEFER_ITEM_TEXT:
            TreeView_DeferItemText(hDlg, wParam, lParam);
            return TRUE;

        case WM_CONTEXTMENU:
            return OnTVContextMenu(hDlg, lParam);

        case WM_COMMAND:
            return OnCommand(hDlg, HIWORD(wParam), LOWORD(wParam));

        case WM_NOTIFY:
            return OnNotify(hDlg, (NMHDR *)lParam);

        case WM_DESTROY:
            if(pAnchors != NULL)
                delete pAnchors;
            pAnchors = NULL;
            return FALSE;
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// Testing code

#ifdef __TEST_MODE__

static const BYTE Condition1[] =
{
    0x61, 0x72, 0x74, 0x78, 0xF8, 0x1C, 0x00, 0x00, 0x00, 0x57, 0x00, 0x49,
    0x00, 0x4E, 0x00, 0x3A, 0x00, 0x2F, 0x00, 0x2F, 0x00, 0x53, 0x00, 0x59,
    0x00, 0x53, 0x00, 0x41, 0x00, 0x50, 0x00, 0x50, 0x00, 0x49, 0x00, 0x44,
    0x00, 0x10, 0x46, 0x00, 0x00, 0x00, 0x4D, 0x00, 0x69, 0x00, 0x63, 0x00,
    0x72, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x6F, 0x00, 0x66, 0x00, 0x74, 0x00,
    0x2E, 0x00, 0x42, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x67, 0x00, 0x57, 0x00,
    0x65, 0x00, 0x61, 0x00, 0x74, 0x00, 0x68, 0x00, 0x65, 0x00, 0x72, 0x00,
    0x5F, 0x00, 0x38, 0x00, 0x77, 0x00, 0x65, 0x00, 0x6B, 0x00, 0x79, 0x00,
    0x62, 0x00, 0x33, 0x00, 0x64, 0x00, 0x38, 0x00, 0x62, 0x00, 0x62, 0x00,
    0x77, 0x00, 0x65, 0x00, 0x86, 0x00, 0x00, 0x00
};

static const BYTE Condition2[] =
{
    0x61, 0x72, 0x74, 0x78, 0xF8, 0x1C, 0x00, 0x00, 0x00, 0x57, 0x00, 0x49,
    0x00, 0x4E, 0x00, 0x3A, 0x00, 0x2F, 0x00, 0x2F, 0x00, 0x53, 0x00, 0x59,
    0x00, 0x53, 0x00, 0x41, 0x00, 0x50, 0x00, 0x50, 0x00, 0x49, 0x00, 0x44,
    0x00, 0x10, 0x46, 0x00, 0x00, 0x00, 0x4D, 0x00, 0x69, 0x00, 0x63, 0x00,
    0x72, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x6F, 0x00, 0x66, 0x00, 0x74, 0x00,
    0x2E, 0x00, 0x42, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x67, 0x00, 0x57, 0x00,
    0x65, 0x00, 0x61, 0x00, 0x74, 0x00, 0x68, 0x00, 0x65, 0x00, 0x72, 0x00,
    0x5F, 0x00, 0x38, 0x00, 0x77, 0x00, 0x65, 0x00, 0x6B, 0x00, 0x79, 0x00,
    0x62, 0x00, 0x33, 0x00, 0x64, 0x00, 0x38, 0x00, 0x62, 0x00, 0x62, 0x00,
    0x77, 0x00, 0x65, 0x00, 0x80, 0xF8, 0x1C, 0x00, 0x00, 0x00, 0x57, 0x00,
    0x49, 0x00, 0x4E, 0x00, 0x3A, 0x00, 0x2F, 0x00, 0x2F, 0x00, 0x53, 0x00,
    0x59, 0x00, 0x53, 0x00, 0x41, 0x00, 0x50, 0x00, 0x50, 0x00, 0x49, 0x00,
    0x44, 0x00, 0x01, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x81, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x00
};

static PSID GetSid(LPCTSTR szUserName, LPDWORD pcbSid)
{
    SID_NAME_USE SidNameUse;
    PSID pSid = NULL;
    DWORD cbSid = 0;
    DWORD cbDomain = 128;
    TCHAR szDomain[128];

    LookupAccountName(NULL, szUserName, pSid, &cbSid, szDomain, &cbDomain, &SidNameUse);
    if(cbSid != 0)
    {
        if((pSid = LocalAlloc(LPTR, cbSid)) != NULL)
        {
            if(LookupAccountName(NULL, szUserName, pSid, &cbSid, szDomain, &cbDomain, &SidNameUse))
            {
                pcbSid[0] = cbSid;
                return pSid;
            }
            LocalFree(pSid);
        }
    }
    return NULL;
}

static bool AppendAceGuid(PVOID pvAce, LPGUID pGuid, ULONG AddFlag)
{
    PACCESS_ALLOWED_OBJECT_ACE pAce = (PACCESS_ALLOWED_OBJECT_ACE)(pvAce);
    LPBYTE pbAce = (LPBYTE)(pAce);
    LPBYTE pbPtr = pbAce + pAce->Header.AceSize;

    if(pGuid != NULL)
    {
        memcpy(pbPtr, pGuid, sizeof(GUID));
        pAce->Flags |= AddFlag;
        pbPtr += sizeof(GUID);
    }

    // Fixup the ACE size
    pAce->Header.AceSize = (WORD)(pbPtr - pbAce);
    return true;
}

static bool AppendAceSid(PACE_HEADER pAceHeader, PSID pSid)
{
    LPBYTE pbAceStart = (LPBYTE)(pAceHeader);
    LPBYTE pbAcePtr = pbAceStart + pAceHeader->AceSize;
    ULONG SidLength;

    // Copy the SID, if any
    if(pSid != NULL && (SidLength = RtlLengthSid(pSid)) != 0)
    {
        memcpy(pbAcePtr, pSid, SidLength);
        pbAcePtr += SidLength;
    }

    // Update the ACE size
    pAceHeader->AceSize = (WORD)(pbAcePtr - pbAceStart);
    return true;
}

static bool AppendAceData(PACE_HEADER pAceHeader, LPCBYTE pbCondition, ULONG cbCondition)
{
    LPBYTE pbAceStart = (LPBYTE)(pAceHeader);
    LPBYTE pbAcePtr = pbAceStart + pAceHeader->AceSize;

    // Copy the SID, if any
    if(pbCondition && cbCondition)
    {
        memcpy(pbAcePtr, pbCondition, cbCondition);
        pbAcePtr += cbCondition;
    }

    // Update the ACE size
    pAceHeader->AceSize = (WORD)(pbAcePtr - pbAceStart);
    return true;
}


template <typename ACE_TYPE>
static ACE_TYPE * AddAce0(PACL pAcl, BYTE AceType, ACCESS_MASK AccessMask, PSID pSid = NULL)
{
    ACE_TYPE * pAce = NULL;
    LPBYTE pbNextAce = (LPBYTE)(pAcl + 1);

    // Get the pointer to the next free ACE
    if(pAcl->AceCount > 0)
    {
        PACE_HEADER pLastAce;

        RtlGetAce(pAcl, pAcl->AceCount - 1, (PVOID *)(&pLastAce));
        pbNextAce = (LPBYTE)(pLastAce) + pLastAce->AceSize;
    }

    if((pAce = (ACE_TYPE *)pbNextAce) != NULL)
    {
        // Configure the ACE
        memset(pAce, 0, sizeof(ACE_TYPE));
        pAce->Header.AceType = AceType;
        pAce->Header.AceSize = FIELD_OFFSET(ACE_TYPE, SidStart);
        pAce->Mask = AccessMask;

        // Copy the SID, if any
        AppendAceSid(&pAce->Header, pSid);
        pAcl->AceCount++;
    }
    return pAce;
}

static PCOMPOUND_ACCESS_ALLOWED_ACE AddAce4(PACL pAcl, ACCESS_MASK AccessMask, PSID pSid1, PSID pSid2 = NULL)
{
    PCOMPOUND_ACCESS_ALLOWED_ACE pAce;

    if((pAce = AddAce0<COMPOUND_ACCESS_ALLOWED_ACE>(pAcl, ACCESS_ALLOWED_COMPOUND_ACE_TYPE, AccessMask, pSid1)) != NULL)
    {
        // Append the second SID, if any
        AppendAceSid(&pAce->Header, pSid2);
        pAce->CompoundAceType = COMPOUND_ACE_IMPERSONATION;
    }
    return pAce;
}

static PACCESS_ALLOWED_OBJECT_ACE AddAce5(PACL pAcl, BYTE AceType, ACCESS_MASK AccessMask, LPGUID pGuid1, LPGUID pGuid2, PSID pSid)
{
    PACCESS_ALLOWED_OBJECT_ACE pAce;

    if((pAce = AddAce0<ACCESS_ALLOWED_OBJECT_ACE>(pAcl, AceType, AccessMask)) != NULL)
    {
        // Fixup the ACE size
        pAce->Header.AceSize = FIELD_OFFSET(ACCESS_ALLOWED_OBJECT_ACE, ObjectType);

        // Append both GUIDs and the SID
        AppendAceGuid(pAce, pGuid1, ACE_OBJECT_TYPE_PRESENT);
        AppendAceGuid(pAce, pGuid2, ACE_INHERITED_OBJECT_TYPE_PRESENT);
        AppendAceSid(&pAce->Header, pSid);
    }
    return pAce;
}

static PACCESS_ALLOWED_CALLBACK_ACE AddAce9(PACL pAcl, BYTE AceType, ACCESS_MASK AccessMask, PSID pSid, LPCBYTE pbCondition, ULONG cbCondition)
{
    PACCESS_ALLOWED_CALLBACK_ACE pAce;

    if((pAce = AddAce0<ACCESS_ALLOWED_CALLBACK_ACE>(pAcl, AceType, AccessMask, pSid)) != NULL)
        AppendAceData(&pAce->Header, pbCondition, cbCondition);
    return pAce;
}

/*
static PACCESS_ALLOWED_CALLBACK_OBJECT_ACE AddAce12(
    PACL pAcl,
    BYTE AceType,
    ACCESS_MASK AccessMask,
    LPGUID pGuid1,
    LPGUID pGuid2,
    PSID pSid,
    LPCBYTE pbCondition,
    ULONG cbCondition)
{
    PACCESS_ALLOWED_CALLBACK_OBJECT_ACE pAce;

    if((pAce = AddAce0<ACCESS_ALLOWED_CALLBACK_OBJECT_ACE>(pAcl, AceType, AccessMask)) != NULL)
    {
        // Fixup the ACE size
        pAce->Header.AceSize = FIELD_OFFSET(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, ObjectType);

        // Append both GUIDs, SID and the condition
        AppendAceGuid(pAce, pGuid1, ACE_OBJECT_TYPE_PRESENT);
        AppendAceGuid(pAce, pGuid2, ACE_INHERITED_OBJECT_TYPE_PRESENT);
        AppendAceSid (&pAce->Header, pSid);
        AppendAceData(&pAce->Header, pbCondition, cbCondition);
    }
    return pAce;
}
*/

PACL CreateEmptyDacl()
{
    PACL pAcl;

    if((pAcl = (PACL)LocalAlloc(LPTR, sizeof(ACL))) != NULL)
    {
        if(RtlCreateAcl(pAcl, sizeof(ACL), ACL_REVISION_DS) != STATUS_SUCCESS)
        {
            LocalFree(pAcl);
            pAcl = NULL;
        }
    }
    return pAcl;
}

PACL CreateDacl(PSID pSidEveryone, PSID pSidUser, PSID pSidAdmin)
{
    PACL pAcl;
    ULONG cbAclSize = 0x1000;
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;

    // Allocate space for ACL
    if((pAcl = (PACL)LocalAlloc(LPTR, cbAclSize)) != NULL)
    {
        if((Status = RtlCreateAcl(pAcl, cbAclSize, ACL_REVISION_DS)) == STATUS_SUCCESS)
        {
            PACE_HEADER pAceHeader;
            GUID Guid1 = {0};
            GUID Guid2 = {0};

            pAceHeader = &AddAce0<ACCESS_ALLOWED_ACE>(pAcl, ACCESS_ALLOWED_ACE_TYPE, GENERIC_ALL, pSidEveryone)->Header;
            cbAclSize = sizeof(ACL) + pAceHeader->AceSize;

            pAceHeader = &AddAce0<ACCESS_DENIED_ACE>(pAcl, ACCESS_DENIED_ACE_TYPE, FILE_EXECUTE, pSidAdmin)->Header;
            cbAclSize = cbAclSize + pAceHeader->AceSize;

            pAceHeader = &AddAce4(pAcl, FILE_EXECUTE, pSidAdmin, pSidUser)->Header;
            cbAclSize = cbAclSize + pAceHeader->AceSize;

            pAceHeader = &AddAce5(pAcl, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ADS_RIGHT_DS_READ_PROP, NULL, NULL, pSidEveryone)->Header;
            cbAclSize = cbAclSize + pAceHeader->AceSize;

            pAceHeader = &AddAce5(pAcl, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ADS_RIGHT_DS_READ_PROP, &Guid1, NULL, pSidEveryone)->Header;
            cbAclSize = cbAclSize + pAceHeader->AceSize;

            pAceHeader = &AddAce5(pAcl, ACCESS_DENIED_OBJECT_ACE_TYPE, ADS_RIGHT_DS_WRITE_PROP, &Guid1, &Guid2, pSidEveryone)->Header;
            cbAclSize = cbAclSize + pAceHeader->AceSize;

            pAceHeader = &AddAce5(pAcl, ACCESS_DENIED_OBJECT_ACE_TYPE, ADS_RIGHT_DS_WRITE_PROP, &Guid1, &Guid2, pSidEveryone)->Header;
            cbAclSize = cbAclSize + pAceHeader->AceSize;

            pAceHeader = &AddAce9(pAcl, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, FILE_READ_DATA, pSidUser, Condition1, sizeof(Condition1))->Header;
            cbAclSize = cbAclSize + pAceHeader->AceSize;

            pAceHeader = &AddAce9(pAcl, ACCESS_DENIED_CALLBACK_ACE_TYPE, FILE_EXECUTE, pSidUser, Condition2, sizeof(Condition2))->Header;
            cbAclSize = cbAclSize + pAceHeader->AceSize;

            pAcl->AclSize = (WORD)(cbAclSize);
        }
    }
    return pAcl;
}

static DWORD SetCustomSecurityDescriptor(HANDLE hObject, ULONG AclType)
{
    SECURITY_INFORMATION SecurityInfo = 0;
    SECURITY_DESCRIPTOR sd;
    NTSTATUS Status = STATUS_SUCCESS;
    PSID pSidEveryone = NULL;
    PSID pSidAdmin = NULL;
    PSID pSidUser = NULL;
    PACL pDacl = NULL;
    ULONG ccUserName = 0;
    ULONG cbSidEveryone = 0;
    ULONG cbSidAdmin = 0;
    ULONG cbSidUser = 0;
    TCHAR szUserName[128];

    // Get two sids: Admins and current user
    ccUserName = _countof(szUserName);
    GetUserName(szUserName, &ccUserName);
    pSidAdmin = GetSid(_T("Administrator"), &cbSidAdmin);
    pSidUser = GetSid(szUserName, &cbSidUser);

    // Get the SID of Everyone
    RtlAllocateAndInitializeSid(&SiaWorld, 1, 0, 0, 0, 0, 0, 0, 0, 0, &pSidEveryone);
    cbSidEveryone = RtlLengthSid(pSidEveryone);

    // Initialize the blank security descriptor
    if(NT_SUCCESS(Status))
    {
        Status = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    }

    // Set the appropriate DACL
    if(NT_SUCCESS(Status))
    {
        switch(AclType)
        {
            case 0:
                if((Status = RtlSetDaclSecurityDescriptor(&sd, TRUE, NULL, FALSE)) == STATUS_SUCCESS)
                {
                    SecurityInfo |= DACL_SECURITY_INFORMATION;
                }
                break;

            case 1:
                if((pDacl = CreateEmptyDacl()) != NULL)
                {
                    if((Status = RtlSetDaclSecurityDescriptor(&sd, TRUE, pDacl, FALSE)) == STATUS_SUCCESS)
                    {
                        SecurityInfo |= DACL_SECURITY_INFORMATION;
                    }
                }
                break;

            case 2:
                if((pDacl = CreateDacl(pSidEveryone, pSidUser, pSidAdmin)) != NULL)
                {
                    if((Status = RtlSetDaclSecurityDescriptor(&sd, TRUE, pDacl, FALSE)) == STATUS_SUCCESS)
                    {
                        SecurityInfo |= DACL_SECURITY_INFORMATION;
                    }
                }
                break;
        }
    }

    // Apply the security information to the handle
    if(NT_SUCCESS(Status))
    {
        Status = NtSetSecurityObject(hObject, SecurityInfo, &sd);
    }

    // Free buffers
    if(pDacl != NULL)
        LocalFree(pDacl);
    if(pSidUser != NULL)
        LocalFree(pSidUser);
    if(pSidAdmin != NULL)
        LocalFree(pSidAdmin);
    return Status;
}

void SetCustomSecurityDescriptor(LPCTSTR szPath, ULONG AclType)
{
    HANDLE hFolder;

    // Make sure that the folder exists
    CreateDirectory(szPath, NULL);

    // Open the folder and set security descriptor
    hFolder = CreateFile(szPath, GENERIC_ALL | READ_CONTROL | WRITE_DAC | WRITE_OWNER, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if(hFolder != INVALID_HANDLE_VALUE)
    {
        SetCustomSecurityDescriptor(hFolder, AclType);
        CloseHandle(hFolder);
    }
}

void DebugCode_SecurityDescriptor(LPCTSTR /* szPath */)
{
    SetCustomSecurityDescriptor(_T("c:\\VMWARE\\Test-001-NULL_ACL"), 0);
    SetCustomSecurityDescriptor(_T("c:\\VMWARE\\Test-002-EMPTY_ACL"), 1);
    SetCustomSecurityDescriptor(_T("c:\\VMWARE\\Test-003-VALID_ACL"), 2);
}
#endif
