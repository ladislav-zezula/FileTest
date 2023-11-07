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

#define PVOID_TRUE                  (PVOID)(UINT_PTR)(TRUE)

typedef enum _TREE_ITEM_TYPE
{
    ItemTypeUnknown,
    ItemTypeOwner,                                  // The item contains "OWNER_SECURITY_INFORMATION"
    ItemTypeGroup,                                  // The item contains "GROUP_SECURITY_INFORMATION"
    ItemTypeDacl,                                   // The item contains "DACL_SECURITY_INFORMATION"
    ItemTypeSacl,                                   // The item contains "SACL_SECURITY_INFORMATION"
    ItemTypeSid,                                    // The item contains Security Identifier (SID)
    ItemTypeAce,                                    // The item contains Access Control Entry (ACE) from DACL
    ItemTypeUint08,                                 // The item contains 8-bit integer
    ItemTypeUint16,                                 // The item contains 16-bit integer
    ItemTypeUint32,                                 // The item contains 32-bit integer
    ItemTypeUint64,                                 // The item contains 64-bit integer
    ItemTypeGuid,                                   // The item is a GUID
    ItemTypeMandSid,                                // The item is a mandatory label SID
    ItemTypeCondition,                              // The item is an ACE condition
} TREE_ITEM_TYPE, *PTREE_ITEM_TYPE;

typedef struct _TREE_ITEM_INFO
{
    TREE_ITEM_TYPE ItemType;
    UINT nIDFormat1;                                // Format string when no data
    UINT nIDFormat2;                                // Format string when there are data
    UINT ccMaxChars;
    bool (*ToString)(LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy);
    bool (*CreateNew)(LPBYTE pbDataBuffer, size_t * pcbDataBuffer);
    bool (*BeginEdit)(LPCTSTR szText, LPTSTR szBuffer, size_t ccBuffer);
    bool (*FinalEdit)(LPTSTR szBuffer, size_t ccBuffer);
    bool (*FromString)(LPBYTE & RefPtr, LPBYTE pbEnd, LPCTSTR szBuffer);
    PVOID lpData;                                   // Set to nonzero when the item has data
} TREE_ITEM_INFO, *PTREE_ITEM_INFO;
typedef const TREE_ITEM_INFO * PCTREE_ITEM_INFO;

typedef struct _ACE_FIELD_INFO
{
    ULONG AceLayoutFlag;
    TFlagInfo * pFlagInfos;
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

static SID_IDENTIFIER_AUTHORITY SiaNull  = SECURITY_NULL_SID_AUTHORITY;
static SID_IDENTIFIER_AUTHORITY SiaWorld = SECURITY_WORLD_SID_AUTHORITY;
static SID_IDENTIFIER_AUTHORITY SiaLabel = SECURITY_MANDATORY_LABEL_AUTHORITY;

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

static TFlagInfo IntegrityLevels[] =
{
    FLAGINFO_NUMV(SECURITY_MANDATORY_UNTRUSTED_RID),
    FLAGINFO_NUMV(SECURITY_MANDATORY_LOW_RID),
    FLAGINFO_NUMV(SECURITY_MANDATORY_MEDIUM_RID),
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


static PSID Sid_AllocateAndInitialize(
    IN PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
    IN BYTE nSubAuthorityCount,
    IN PDWORD pnSubAuthorities)
{
    PSID pSid;

    // Prepare a buffer of a sufficient size
    pSid = Sid_Allocate(GetSidLengthRequired(nSubAuthorityCount));
    if(pSid == NULL)
        return NULL;

    // Fill in the identifier authority and sub-authority count
    if(InitializeSid(pSid, pIdentifierAuthority, nSubAuthorityCount))
    {
        // Fill in the sub-authorities
        for (BYTE i = 0; i < nSubAuthorityCount; i++)
        {
            *GetSidSubAuthority(pSid, i) = pnSubAuthorities[i];
        }
    }
    else
    {
        // Failed initialization; cleanup
        Sid_Free(pSid);
        pSid = NULL;
    }

    // Return our new SID
    return pSid;
}

// Creates a new SID of "Everyone" depending on the ACE type
// Caller must free the returned SID using Sid_Free
static PSID Sid_CreateNew(DWORD AceType)
{
    // We only create two types of SID - "Everyone" and "Mandatory Medium"
    if(AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
    {
        DWORD nSubAuthorities[] = { SECURITY_MANDATORY_MEDIUM_RID };
        return Sid_AllocateAndInitialize(&SiaLabel, RTL_NUMBER_OF(nSubAuthorities), nSubAuthorities);
    }
    else
    {
        DWORD nSubAuthorities[] = { SECURITY_WORLD_RID };
        return Sid_AllocateAndInitialize(&SiaWorld, RTL_NUMBER_OF(nSubAuthorities), nSubAuthorities);
    }
}

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

PSID Sid_Allocate(DWORD dwLength)
{
#ifdef _DEBUG
    return (PSID)malloc(dwLength);              // Allocate using malloc, so we can track the leaks
#else
    return (PSID)HeapAlloc(g_hHeap, 0, dwLength);
#endif
}

// A public function, also used in ACE_HELPER
void Sid_Free(PSID pSid)
{
#ifdef _DEBUG
    free(pSid);
#else
    HeapFree(g_hHeap, 0, pSid);
#endif
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
            *ppSid = Sid_AllocateAndInitialize(&Sia, (BYTE)dwSubAuthCount, dwSubAuth);
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

//
// The SID in the SYSTEM_MANDATORY_LABEL_ACE has the following format:
//
// - IdentifierAuthority is set to SECURITY_MANDATORY_LABEL_AUTHORITY
// - The last subauthority is set to one of the SECURITY_MANDATORY_XXXX values
//
static DWORD SidToIntegrityLevel(PSID pSid)
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
                return *GetSidSubAuthority(pSid, dwSubAuthCount - 1);
            }
        }
    }

    // Return default integrity level
    assert(false);
    return SECURITY_MANDATORY_MEDIUM_RID;
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

// Creates a new ACL with one ACE, granting full access to Everyone
// Caller must free the returned buffer using HeapFree
static PACL Acl_CreateOneItem(BYTE AceType)
{
    DWORD dwSidLength = 0;
    DWORD dwAclLength = 0;
    PSID pSid = NULL;
    PACL pAcl = NULL;
    BOOL bResult = FALSE;

    // Create SID for "Everyone"
    pSid = Sid_CreateNew(AceType);
    if(pSid != NULL)
    {
        // Calculate the size of the new ACE and initialize it
        dwSidLength = GetLengthSid(pSid);
        dwAclLength = sizeof(ACL) + AceSizes[AceType] - sizeof(DWORD) + dwSidLength;

        // Create new empty ACL
        pAcl = Acl_CreateEmpty(dwAclLength);
        if(pAcl != NULL)
        {
            // Perform the ACE-specific addition
            switch(AceType)
            {
                case ACCESS_ALLOWED_ACE_TYPE:
                    bResult = AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, pSid);
                    break;

                case ACCESS_DENIED_ACE_TYPE:
                    bResult = AddAccessDeniedAce(pAcl, ACL_REVISION, GENERIC_ALL, pSid);
                    break;

                case SYSTEM_AUDIT_ACE_TYPE:
                    bResult = AddAuditAccessAce(pAcl, ACL_REVISION, GENERIC_ALL, pSid, TRUE, TRUE);
                    break;

                case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
                    bResult = MyAddMandatoryAce(pAcl, ACL_REVISION, 0, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, pSid);
                    break;

                default:    // Not supported
                    bResult = FALSE;
                    break;
            }

            // If something went wrong, free the ACL
            if(bResult == FALSE)
            {
                HeapFree(g_hHeap, 0, pAcl);
                pAcl = NULL;
            }
        }

        // Free the allocated SID
        Sid_Free(pSid);
    }

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

static BOOL IsTreeItemAce(LPARAM lParam)
{
    return ((lParam & TREE_ITEM_TYPE_MASK) == TREE_ITEM_ACE) ? TRUE : FALSE;
}

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

static BYTE GetDefaultAceType(HWND hWndTree, HTREEITEM hParent)
{
    BYTE AceType = ACCESS_ALLOWED_ACE_TYPE;

    // Retrieve the parent item
    switch(TreeView_GetItemParam(hWndTree, hParent))
    {
        case TREE_ITEM_DACL:
            AceType = ACCESS_ALLOWED_ACE_TYPE;
            break;

        case TREE_ITEM_SACL:
            AceType = SYSTEM_AUDIT_ACE_TYPE;
            break;

        case TREE_ITEM_LABEL:
            AceType = SYSTEM_MANDATORY_LABEL_ACE_TYPE;
            break;

        default:
            assert(FALSE);
            break;
    }

    return AceType;
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

static ULONG GetIntegerValueFromData(LPBYTE pbPtr, LPBYTE pbEnd, ULONG cbIntegerSize)
{
    // Sanity check
    assert(cbIntegerSize == 1 || cbIntegerSize == 2 || cbIntegerSize == 4);

    // Check if there is enough data
    if((pbPtr + cbIntegerSize) <= pbEnd)
    {
        switch(cbIntegerSize)
        {
            case 1: return *(LPBYTE)(pbPtr);
            case 2: return *(PUSHORT)(pbPtr);
            case 4: return *(PULONG32)(pbPtr);
        }
    }
    return 0;
}

static void TV_MakeItemText(
    PCTREE_ITEM_INFO pItemInfo,
    TFlagInfo * pFlags,
    LPTSTR szBuffer,
    size_t ccBuffer,
    LPBYTE pbPtr,
    LPBYTE pbEnd,
    PULONG pcbMoveBy)
{
    LPTSTR szSuffix = NULL;
    size_t ccSuffix = 0;
    ULONG dwValue32;
    ULONG cbMoveBy = 0;
    TCHAR szDataText[0x400] = {0};
    UINT nIDFormat = pItemInfo->nIDFormat1;

    // Do we have data and format for it?
    if(pItemInfo->nIDFormat2)
    {
        if(pItemInfo->ToString != NULL)
        {
            // Format the numeric or whatever value
            if(pItemInfo->ToString(szDataText, _countof(szDataText), pbPtr, pbEnd, &cbMoveBy) && pFlags)
            {
                if((dwValue32 = GetIntegerValueFromData(pbPtr, pbEnd, cbMoveBy)) != 0)
                {
                    StringCchCatEx(szDataText, _countof(szDataText), _T("  "), &szSuffix, &ccSuffix, 0);
                    FlagsToString(pFlags, szSuffix, ccSuffix, dwValue32, false);
                }
            }
        }
        nIDFormat = pItemInfo->nIDFormat2;
    }

    // Finally, format the data to the item
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    rsprintf(szBuffer, ccBuffer, nIDFormat, szDataText);
}

//-----------------------------------------------------------------------------
// Conversion of binary data to string

static bool ToString_HexXX(LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, ULONG cbIntegerSize, PULONG pcbMoveBy = NULL)
{
    ULONG cbMoveBy = 0;

    // If there is a SID, format it to the buffer
    if((pbPtr + cbIntegerSize) <= pbEnd)
    {
        LPCTSTR szFormat = NULL;
        ULONG Value32 = 0;

        switch(cbIntegerSize)
        {
            case 0x1: szFormat = _T("0x%02x"); Value32 = *(LPBYTE)(pbPtr); break;
            case 0x2: szFormat = _T("0x%04x"); Value32 = *(PUSHORT)(pbPtr); break;
            case 0x4: szFormat = _T("0x%08x"); Value32 = *(PULONG)(pbPtr); break;
        }

        // Format the integer value
        StringCchPrintfEx(szBuffer, ccBuffer, &szBuffer, &ccBuffer, 0, szFormat, Value32);
        cbMoveBy = cbIntegerSize;
    }

    // Give the move by
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return (cbMoveBy != 0);
}

static bool ToString_HEX08(LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    return ToString_HexXX(szBuffer, ccBuffer, pbPtr, pbEnd, 1, pcbMoveBy);
}

static bool ToString_HEX16(LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    return ToString_HexXX(szBuffer, ccBuffer, pbPtr, pbEnd, 2, pcbMoveBy);
}

static bool ToString_HEX32(LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    return ToString_HexXX(szBuffer, ccBuffer, pbPtr, pbEnd, 4, pcbMoveBy);
}

// Get GUID from object-based ACEs, like ACCESS_ALLOWED_OBJECT_ACE
// * ACCESS_ALLOWED_OBJECT_ACE::ObjectType is only present if ACE_OBJECT_TYPE_PRESENT
// * ACCESS_ALLOWED_OBJECT_ACE::InheritedObjectType is only present if ACE_INHERITED_OBJECT_TYPE_PRESENT
static bool ToString_ObjectGuid(LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, ULONG FlagToTest, PULONG pcbMoveBy = NULL)
{
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

static bool CreateNew_ObjectGuid(LPBYTE pbDataBuffer, size_t * pcbDataBuffer, ULONG FlagToSet)
{
    size_t cbDataBuffer = pcbDataBuffer[0];
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

// XXX_YYY_OBJECT_ACE::ObjectType is only present if ACE_OBJECT_TYPE_PRESENT is set in XXX_YYY_OBJECT_ACE::Flags
static bool ToString_Guid1(LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    return ToString_ObjectGuid(szBuffer, ccBuffer, pbPtr, pbEnd, ACE_OBJECT_TYPE_PRESENT, pcbMoveBy);
}

// XXX_YYY_OBJECT_ACE::InheritedObjectType is only present if ACE_INHERITED_OBJECT_TYPE_PRESENT is set in XXX_YYY_OBJECT_ACE::Flags
static bool ToString_Guid2(LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    return ToString_ObjectGuid(szBuffer, ccBuffer, pbPtr, pbEnd, ACE_INHERITED_OBJECT_TYPE_PRESENT, pcbMoveBy);
}

// We need to set ACE_OBJECT_TYPE_PRESENT as well
static bool CreateNew_Guid1(LPBYTE pbDataBuffer, size_t * pcbDataBuffer)
{
    return CreateNew_ObjectGuid(pbDataBuffer, pcbDataBuffer, ACE_OBJECT_TYPE_PRESENT);
}

// We need to set ACE_INHERITED_OBJECT_TYPE_PRESENT as well
static bool CreateNew_Guid2(LPBYTE pbDataBuffer, size_t * pcbDataBuffer)
{
    return CreateNew_ObjectGuid(pbDataBuffer, pcbDataBuffer, ACE_INHERITED_OBJECT_TYPE_PRESENT);
}

static bool ToString_Sid(LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    ULONG cbMoveBy = 0;

    // If there is a SID, format it to the buffer
    if(pbPtr && pbEnd > pbPtr)
    {
        // Convert the SID to string
        SidToString((PSID)(pbPtr), szBuffer, ccBuffer, true);
        cbMoveBy = RtlLengthSid((PSID)(pbPtr));
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

static bool ToString_MandSid(LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    PSID pSid = (PSID)(pbPtr);
    ULONG cbMoveBy = 0;

    // If there is a SID, format it to the buffer
    if(pbPtr && pbEnd > pbPtr)
    {
        LPTSTR szSuffix = NULL;
        size_t ccSuffix = 0;
        DWORD dwIntegrityLevel = SidToIntegrityLevel(pSid);

        // Redefine the data to the integrity level
        pbPtr = (LPBYTE)(&dwIntegrityLevel);
        pbEnd = pbPtr + sizeof(DWORD);

        // Reuse the data from the integer
        ToString_HEX32(szBuffer, ccBuffer, pbPtr, pbEnd);
        StringCchCatEx(szBuffer, ccBuffer, _T("  "), &szSuffix, &ccSuffix, 0);
        FlagsToString(IntegrityLevels, szSuffix, ccSuffix, dwIntegrityLevel, false);
        cbMoveBy = RtlLengthSid(pSid);
    }

    // Give the length to move
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return (cbMoveBy != 0);
}

static bool ToString_Condition(LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
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

static bool CreateNew_Sid(LPBYTE pbDataBuffer, size_t * pcbDataBuffer)
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
        Sid_Free(pSid);
    }
    return bResult;
}

static bool ToString_Ace(LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    PACE_HEADER pAceHeader = (PACE_HEADER)(pbPtr);
    ULONG cbMoveBy = 0;

    if((pbPtr + sizeof(ACE_HEADER)) < pbEnd)
    {
        LPCSTR szAceType = GetAceTypeString(pAceHeader->AceType);

        StringCchPrintf(szBuffer, ccBuffer, _T("%hs"), szAceType);
        StringCchCut(szBuffer, ccBuffer, _T("_TYPE"));
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

static bool CreateNew_Ace(LPBYTE pbDataBuffer, size_t * pcbDataBuffer)
{
    PACCESS_ALLOWED_ACE pAce;
    PSID pSid;
    size_t cbDataBuffer = pcbDataBuffer[0];
    bool bResult = false;

    // Create new SID for everyone
    if((pSid = Sid_CreateNew(ACCESS_ALLOWED_ACE_TYPE)) != NULL)
    {
        ULONG SidLength = RtlLengthSid(pSid);
        ULONG AceLength = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + SidLength;

        if(AceLength <= cbDataBuffer)
        {
            // Do not allocate new ACE, just reuse the buffer
            if((pAce = (PACCESS_ALLOWED_ACE)(pbDataBuffer)) != NULL)
            {
                // Setup the buffer as ACCESS_ALLOWED_ACE
                memset(pbDataBuffer, 0, cbDataBuffer);
                pAce->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
                pAce->Header.AceSize = (WORD)(AceLength);
                pAce->Mask = GENERIC_ALL;
                memcpy(&pAce->SidStart, pSid, SidLength);
                bResult = true;
            }
        }

        // Give the ACE length and free SID
        pcbDataBuffer[0] = AceLength;
        Sid_Free(pSid);
    }
    return bResult;
}

static TREE_ITEM_INFO TreeItem_Owner   = {ItemTypeOwner,   IDS_OWNER_SECURITY_INFORMATION};
static TREE_ITEM_INFO TreeItem_Group   = {ItemTypeGroup,   IDS_GROUP_SECURITY_INFORMATION};
static TREE_ITEM_INFO TreeItem_Dacl    = {ItemTypeDacl,    IDS_DACL_SECURITY_INFORMATION};
static TREE_ITEM_INFO TreeItem_Sacl    = {ItemTypeSacl,    IDS_SACL_SECURITY_INFORMATION};

static TREE_ITEM_INFO TreeItem_UserSid = {ItemTypeSid,     IDS_NOT_PRESENT, IDS_FORMAT_SID,  0x00, ToString_Sid, CreateNew_Sid, NULL, NULL, NULL};
static TREE_ITEM_INFO TreeItem_SrvrSid = {ItemTypeSid,     IDS_NOT_PRESENT, IDS_FORMAT_SSID, 0x00, ToString_Sid, CreateNew_Sid, NULL, NULL, NULL};
static TREE_ITEM_INFO TreeItem_ClntSid = {ItemTypeSid,     IDS_NOT_PRESENT, IDS_FORMAT_CSID, 0x00, ToString_Sid, CreateNew_Sid, NULL, NULL, NULL};
static TREE_ITEM_INFO TreeItem_Ace     = {ItemTypeAce,     IDS_NULL_ACL,    IDS_FORMAT_STR,  0x00, ToString_Ace, CreateNew_Ace, NULL, NULL, NULL};

static ACE_FIELD_INFO AceFieldInfos[] =
{
    {ACE_FIELD_HTYPE,           NULL,        {ItemTypeUint08,    0, IDS_FORMAT_ACE_HTYPE,  0x08, ToString_HEX08}},
    {ACE_FIELD_HFLAGS,          AceHdrFlags, {ItemTypeUint08,    0, IDS_FORMAT_ACE_HFLAGS, 0x08, ToString_HEX08}},
    {ACE_FIELD_HSIZE,           NULL,        {ItemTypeUint16,    0, IDS_FORMAT_ACE_HSIZE,  0x10, ToString_HEX16}},
    {ACE_FIELD_ACCESS_MASK,     AceMasks,    {ItemTypeUint32,    0, IDS_FORMAT_ACE_MASK,   0x20, ToString_HEX32}},
    {ACE_FIELD_ADS_ACCESS_MASK, AdsAceMasks, {ItemTypeUint32,    0, IDS_FORMAT_ACE_MASK,   0x20, ToString_HEX32}},
    {ACE_FIELD_MANDATORY_MASK,  LabelMasks,  {ItemTypeUint32,    0, IDS_FORMAT_ACE_MASK,   0x20, ToString_HEX32}},
    {ACE_FIELD_FLAGS,           ObjAceFlags, {ItemTypeUint32,    0, IDS_FORMAT_ACE_FLAGS,  0x20, ToString_HEX32}},
    {ACE_FIELD_CTYPE,           CAceTypes,   {ItemTypeUint16,    0, IDS_FORMAT_ACE_CTYPE,  0x10, ToString_HEX16}},
    {ACE_FIELD_CRESERVED,       NULL,        {ItemTypeUint16,    0, IDS_FORMAT_RESERVED,   0x10, ToString_HEX16}},
    {ACE_FIELD_OBJECT_TYPE1,    NULL,        {ItemTypeGuid,      0, IDS_FORMAT_OBJ_TYPE,   0x10, ToString_Guid1, CreateNew_Guid1}},
    {ACE_FIELD_OBJECT_TYPE2,    NULL,        {ItemTypeGuid,      0, IDS_FORMAT_OBJ_TYPEI,  0x10, ToString_Guid2, CreateNew_Guid2}},
    {ACE_FIELD_ACCESS_SID,      NULL,        {ItemTypeSid,       0, IDS_FORMAT_SID,        0x00, ToString_Sid}},
    {ACE_FIELD_SERVER_SID,      NULL,        {ItemTypeSid,       0, IDS_FORMAT_SSID,       0x00, ToString_Sid}},
    {ACE_FIELD_CLIENT_SID,      NULL,        {ItemTypeSid,       0, IDS_FORMAT_CSID,       0x00, ToString_Sid}},
    {ACE_FIELD_MANDATORY_SID,   NULL,        {ItemTypeMandSid,   0, IDS_FORMAT_INT_LEVEL,  0x00, ToString_MandSid}},
    {ACE_FIELD_CONDITION,       NULL,        {ItemTypeCondition, 0, IDS_FORMAT_CONDITION,  0x00, ToString_Condition}}
};

//-----------------------------------------------------------------------------
// Inserting items

static HTREEITEM TV_InsertNewItem(
    HWND hWndTree,
    HTREEITEM hParent,
    HTREEITEM hInsertAfter,
    PCTREE_ITEM_INFO pItemInfo,
    TFlagInfo * pFlags = NULL,
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
        TV_MakeItemText(pNewInfo, pFlags, szItemText, _countof(szItemText), pbPtr, pbEnd, &cbMoveBy);

        // Does the item have data?
        pNewInfo->lpData = (pbPtr && pbEnd > pbPtr && cbMoveBy) ? PVOID_TRUE : NULL;

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
    return TV_InsertNewItem(hWndTree, hParent, hInsertAfter, pItemInfo, NULL, pbSid, pbEnd);
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
    hAceItem = TV_InsertNewItem(hWndTree, hParent, hInsertAfter, &TreeItem_Ace, NULL, pbPtr, pbEnd);
    if(hAceItem != NULL)
    {
        // Set the ACE to the ACE helper, we can parse the ACE fields easier
        AceHelper.SetAce(pAceHeader);
        hInsertAfter = TVI_FIRST;

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
                                                hAceItem,
                                                hInsertAfter,
                                               &AceFieldInfos[i].TreeItem,
                                                AceFieldInfos[i].pFlagInfos,
                                                pbPtr, pbEnd, &cbMoveBy);
                if(hInsertAfter == NULL)
                    break;
                pbPtr += cbMoveBy;
            }
        }
    }
    
    // Reset the XXX_YYY_OBJECT_ACE::Flags
    OBJECT_ACE_Flags = 0;
    return hAceItem;
}


static void TV_InsertNewItemAcl(
    HWND hWndTree,
    HTREEITEM hParent,
    HTREEITEM hInsertAfter,
    PACL pAcl)
{
    // Remove all children, if any
    TreeView_DeleteChildren(hWndTree, hParent);

    // If the ACL is non-NULL, insert the ACEs
    if(pAcl && pAcl->AclSize)
    {
        LPBYTE pbPtr = (LPBYTE)(pAcl) + sizeof(ACL);
        LPBYTE pbEnd = (LPBYTE)(pAcl) + pAcl->AclSize;

        // Insert all ACEs that are not filtered out
        while((pbPtr + sizeof(ACE_HEADER)) < pbEnd)
        {
            PACE_HEADER pAceHeader = (PACE_HEADER)(pbPtr);
            HTREEITEM hItem;

            // Insert the ACE to the list
            if((hItem = TV_InsertNewItemAce(hWndTree, hParent, hInsertAfter, pAceHeader)) == NULL)
                break;
            hInsertAfter = hItem;

            // Move the data pointer by the size of the ACE
            pbPtr += pAceHeader->AceSize;
        }
    }
    else
    {
        TV_InsertNewItem(hWndTree, hParent, hInsertAfter, &TreeItem_Ace);
    }
}

static HTREEITEM TreeView_SidToItem(HWND hWndTree, HTREEITEM hItem, PSID pSid, LPARAM lParam, UINT nIDFormat, LPCTSTR szDefaultText)
{
    TCHAR szItemText[256];
    TCHAR szSidText[128];

    // If the SID is present, convert the SID to the tree item
    if(pSid != NULL)
    {
        // Convert the SID to text
        SidToString(pSid, szSidText, _countof(szSidText), true);
        rsprintf(szItemText, _countof(szItemText), nIDFormat, szSidText);
        szDefaultText = szItemText;
    }

    // Insert the SID to the tree view
    return TreeView_SetTreeItem(hWndTree, hItem, szDefaultText, lParam);
}

static HTREEITEM TreeView_InsertSidItem(HWND hWndTree, HTREEITEM hParent, PSID pSid, LPARAM lParamNULL, UINT nIDFormat, LPCTSTR szDefaultText)
{
    HTREEITEM hItem;

    // Insert a new item
    hItem = InsertTreeItem(hWndTree, hParent, szDefaultText, lParamNULL);
    if(hItem != NULL)
    {
        // Apply the SID to the item and expand the parent
        TreeView_SidToItem(hWndTree, hItem, pSid, lParamNULL + 1, nIDFormat, szDefaultText);
        TreeView_Expand(hWndTree, hParent, TVE_EXPAND);
    }
    return hItem;
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
            StringToSid(szItemText, ppSid);
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

static HTREEITEM TreeView_MandatorySidToItem(HWND hWndTree, HTREEITEM hParent, PSID pSid)
{
    TCHAR szItemText[256];

    // Format the integrity level
    StringCchPrintf(szItemText, _countof(szItemText), szIntLevelFmt, SidToIntegrityLevel(pSid));
    return TreeView_SetTreeItem(hWndTree, hParent, szItemText, TREE_ITEM_MANDATORY_LABEL);
}

static HTREEITEM TreeView_InsertMandatorySidItem(HWND hWndTree, HTREEITEM hParent, PSID pSid, LPCTSTR szDefaultText)
{
    HTREEITEM hItem;

    // Insert a new item
    hItem = InsertTreeItem(hWndTree, hParent, szDefaultText, TREE_ITEM_MANDATORY_LABEL);
    if(hItem != NULL)
    {
        // Apply the SID to the item and expand the parent
        TreeView_MandatorySidToItem(hWndTree, hItem, pSid);
        TreeView_Expand(hWndTree, hParent, TVE_EXPAND);
    }
    return hItem;
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
        DWORD nSubAuthorities[] = { dwIntLevel };
        pSid = Sid_AllocateAndInitialize(&SiaLabel, RTL_NUMBER_OF(nSubAuthorities), nSubAuthorities);
        if(pSid != NULL)
        {
            // Store the SID to the ACE_HELPER structure
            AceHelper.SetAllocatedSid(pSid, 0);
            bResult = true;
        }
    }

    return bResult;
}

static HTREEITEM TreeView_InsertAceCondition(HWND hWndTree, HTREEITEM hParentItem, LPBYTE Condition, ULONG ConditionLength)
{
    HTREEITEM hItem = NULL;
    LPTSTR szCondition = NULL;
    DWORD dwErrCode;
    TCHAR szItemText[256];
    TCHAR szBuffer[128];

    dwErrCode = LocalGetStringForCondition(Condition, ConditionLength, &szCondition, NULL, NULL, NULL, NULL, false);
    if(dwErrCode != ERROR_SUCCESS)
    {
        LoadString(g_hInst, IDS_INVALID_ACE_CONDITION, szBuffer, _countof(szBuffer));
        szCondition = szBuffer;
    }

    // Make the item text
//    rsprintf(szItemText, _countof(szItemText), IDS_FORMAT_ACE_CONDITION, szCondition);
    hItem = InsertTreeItem(hWndTree, hParentItem, szItemText, TREE_ITEM_ACE_CONDITION);

    // Free the condition, if needed
    if(szCondition && szCondition != szBuffer)
        LocalFree(szCondition);
    return hItem;

}

static HTREEITEM TreeView_AceToItem(
    HWND hWndTree,
    HTREEITEM hItem,
    ACE_HELPER & AceHelper)
{
    TCHAR szItemText[256];

    // Check if the layout is supported and the parent is valid
    if(AceHelper.AceLayout == ACE_LAYOUT_UNKNOWN || hItem == NULL)
        return NULL;

    // Delete all children
    TreeView_DeleteChildren(hWndTree, hItem);

    // Insert the subitem with ACE type
    rsprintf(szItemText, _countof(szItemText), IDS_FORMAT_ACE_HTYPE, AceHelper.AceType);
    InsertTreeItem(hWndTree, hItem, szItemText, TREE_ITEM_ACE_HEADER_TYPE);

    // Insert the subitem with ACE flags
    NamedValueToString(AceHdrFlags, szItemText, _countof(szItemText), szAceHdrFlagsFmt, AceHelper.AceFlags);
    InsertTreeItem(hWndTree, hItem, szItemText, TREE_ITEM_ACE_HEADER_FLAGS);

    // Insert the subitem with ACE size
    rsprintf(szItemText, _countof(szItemText), IDS_FORMAT_ACE_HSIZE, AceHelper.AceSize);
    InsertTreeItem(hWndTree, hItem, szItemText, TREE_ITEM_ACE_HEADER_SIZE);

    // Insert the ACE:Mask (ACCESS_MASK), if present
    if(AceHelper.AceLayout & ACE_FIELD_ACCESS_MASK)
    {
        NamedValueToString(AceMasks, szItemText, _countof(szItemText), szAceMaskFmt, AceHelper.Mask);
        InsertTreeItem(hWndTree, hItem, szItemText, TREE_ITEM_ACE_MASK);
    }

    // Insert the ACE:Mask (Object ACEs), if present
    if(AceHelper.AceLayout & ACE_FIELD_ADS_ACCESS_MASK)
    {
        NamedValueToString(AdsAceMasks, szItemText, _countof(szItemText), szAceMaskFmt, AceHelper.Mask);
        InsertTreeItem(hWndTree, hItem, szItemText, TREE_ITEM_ADS_ACE_MASK);
    }

    // Insert the ACE:Mask (MANDATORY_LABEL_MASK), if present
    if(AceHelper.AceLayout & ACE_FIELD_MANDATORY_MASK)
    {
        NamedValueToString(LabelMasks, szItemText, _countof(szItemText), szAceMaskFmt, AceHelper.Mask);
        InsertTreeItem(hWndTree, hItem, szItemText, TREE_ITEM_MANDATORY_MASK);
    }

    // Insert the ACE::Flags, if present
    if(AceHelper.AceLayout & ACE_FIELD_FLAGS)
    {
        NamedValueToString(ObjAceFlags, szItemText, _countof(szItemText), szAceFlagsFmt, AceHelper.Flags);
        InsertTreeItem(hWndTree, hItem, szItemText, TREE_ITEM_ACE_FLAGS);
    }

    // Insert values from the COMPOUND ACE type
    if(AceHelper.AceLayout & (ACE_FIELD_CTYPE | ACE_FIELD_CRESERVED))
    {
        NamedValueToString(CompoundAceTypes, szItemText, _countof(szItemText), _T("CompoundAceType: %u  "), AceHelper.CompoundAceType);
        InsertTreeItem(hWndTree, hItem, szItemText, TREE_ITEM_COMPOUND_TYPE);
        rsprintf(szItemText, _countof(szItemText), IDS_FORMAT_RESERVED, AceHelper.CompoundReserved);
        InsertTreeItem(hWndTree, hItem, szItemText, TREE_ITEM_COMPOUND_RESERVED);
    }

    // Insert the ACE:ObjectType, if present
    // Info about object GUIDs, see https://msdn.microsoft.com/en-us/library/cc223512.aspx
    if(AceHelper.AceLayout & ACE_FIELD_OBJECT_TYPE1)
    {
        GuidValueToString(szItemText, _countof(szItemText), szAceObjTypeFmt, &AceHelper.ObjectType);
        InsertTreeItem(hWndTree, hItem, szItemText, TREE_ITEM_ACE_OBJ_GUID);
    }

    // Insert the ACE:InheritedObjectType, if present
    if(AceHelper.AceLayout & ACE_FIELD_OBJECT_TYPE2)
    {
        GuidValueToString(szItemText, _countof(szItemText), szAceObjTypeFmt2, &AceHelper.InheritedObjectType);
        InsertTreeItem(hWndTree, hItem, szItemText, TREE_ITEM_ACE_OBJ_GUID2);
    }

    // Insert the access SID, if present
    if(AceHelper.AceLayout & ACE_FIELD_ACCESS_SID)
        TreeView_InsertSidItem(hWndTree, hItem, AceHelper.Sid[0], TREE_ITEM_SID1_NONE, IDS_FORMAT_SID, szUnknownSid);

    // Insert the server SID, if present
    //if(AceHelper.AceLayout & ACE_FIELD_SERVER_SID)
    //    TreeView_InsertSidItem(hWndTree, hItem, AceHelper.Sid[0], TREE_ITEM_SID1_NONE, IDS_FORMAT_SERVER_SID, szUnknownSid);

    // Insert the integrity level, if present
    if(AceHelper.AceLayout & ACE_FIELD_MANDATORY_SID)
        TreeView_InsertMandatorySidItem(hWndTree, hItem, AceHelper.Sid[0], szUnknownSid);

    // Insert the client SID, if present
    //if(AceHelper.AceLayout & ACE_FIELD_CLIENT_SID)
    //    TreeView_InsertSidItem(hWndTree, hItem, AceHelper.Sid[1], TREE_ITEM_SID2_NONE, IDS_FORMAT_CLIENT_SID, szUnknownSid);

    // Insert the ACE condition, if any
    if(AceHelper.AceLayout & ACE_FIELD_CONDITION)
        TreeView_InsertAceCondition(hWndTree, hItem, AceHelper.Condition, AceHelper.ConditionLength);

    // Return the handle to the expanded item
    TreeView_Expand(hWndTree, hItem, TVE_EXPAND);
    return hItem;
}

static HTREEITEM TreeView_AceToItem(
    HWND hWndTree,
    HTREEITEM hParent,
    PACE_HEADER pAceHeader)
{
    ACE_HELPER AceHelper;

    if(!AceHelper.SetAce(pAceHeader))
        return NULL;
    return TreeView_AceToItem(hWndTree, hParent, AceHelper);
}

static HTREEITEM TreeView_InsertAceItem(
    HWND hWndTree,
    HTREEITEM hParent,
    HTREEITEM hInsertAfter,
    PACE_HEADER pAceHeader)
{
    HTREEITEM hItem;
    LPCSTR szAceTypeString = GetAceTypeString(pAceHeader->AceType);

    // Insert the "root" item with ACE type
    hItem = InsertTreeItem(hWndTree, hParent, hInsertAfter, TWideString(szAceTypeString), (PVOID)(ULONG_PTR)(TREE_ITEM_ACE | pAceHeader->AceType));
    if(hItem != NULL)
    {
        // Fill the ACE structure
        TreeView_AceToItem(hWndTree, hItem, pAceHeader);
        TreeView_Expand(hWndTree, hParent, TVE_EXPAND);
    }

    // Return the newly created tree item
    return hItem;
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
    BOOL bTemp;

    // Turn off redrawing for faster response
    SendMessage(hWndTree, WM_SETREDRAW, FALSE, 0);

    // Clear all current tree view items
    TreeView_DeleteAllItems(hWndTree);
    LoadString(g_hInst, IDS_NOT_PRESENT, szNotPresent, _countof(szNotPresent));

    //
    // Insert tree item for owner security information
    //

    hItem = TV_InsertNewItem(hWndTree, NULL, NULL, &TreeItem_Owner);
    if(!GetSecurityDescriptorOwner(pSD, &pOwner, &bTemp))
        pOwner = NULL;
    TV_InsertNewItemSid(hWndTree, hItem, NULL, &TreeItem_UserSid, pOwner);

    //
    // Insert tree item for group security information
    //

    hItem = TV_InsertNewItem(hWndTree, NULL, NULL, &TreeItem_Group);
    if(!GetSecurityDescriptorGroup(pSD, &pGroup, &bTemp))
        pGroup = NULL;
    TV_InsertNewItemSid(hWndTree, hItem, NULL, &TreeItem_UserSid, pGroup);

    //
    // Insert tree item for DACL security information
    //

    hItem = TV_InsertNewItem(hWndTree, NULL, NULL, &TreeItem_Dacl);
    pAcl = NULL;
    GetSecurityDescriptorDacl(pSD, &bTemp, &pAcl, &bTemp);
    TV_InsertNewItemAcl(hWndTree, hItem, NULL, pAcl);

    //
    // Insert tree item for SACL security information
    //

    hItem = TV_InsertNewItem(hWndTree, NULL, NULL, &TreeItem_Sacl);
    pAcl = NULL;
    GetSecurityDescriptorSacl(pSD, &bTemp, &pAcl, &bTemp);
    TV_InsertNewItemAcl(hWndTree, hItem, NULL, pAcl);

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
    HTREEITEM hNextItem;
    HMENU hSubMenu = GetSubMenu(hMainMenu, 0);
    UINT uEnable = MF_GRAYED;

    // Move ACE up is only allowed when the ACE is not the first one
    if(TreeView_GetPrevSibling(hWndTree, hItem) == NULL)
        EnableMenuItem(hSubMenu, IDC_MOVE_ACE_UP, MF_GRAYED);

    // Move ACE down is only allowed when the ACE is not the last one
    hNextItem = TreeView_GetNextSibling(hWndTree, hItem);
    if(hNextItem != NULL)
    {
        if(TreeView_GetItemParam(hWndTree, hNextItem) != TREE_ITEM_NULL_ACL)
            uEnable = MF_ENABLED;
    }
    EnableMenuItem(hSubMenu, IDC_MOVE_ACE_DOWN, uEnable);
}

static HTREEITEM TreeView_GetPreviousItem(HWND hWndTree, HTREEITEM hItem)
{
    hItem = TreeView_GetPrevSibling(hWndTree, hItem);
    if(hItem == NULL)
        hItem = TVI_FIRST;

    return hItem;
}

static BOOL DeferSetItemNumericValue(HWND hDlg, LPNMTVDISPINFO pTVDispInfo, TFlagInfo * pFlags, LPCTSTR szFormat)
{
    LPTSTR szItemText;
    size_t cchItemText = 0x400;
    DWORD dwValue32 = 0;
    BOOL bAcceptChanges = FALSE;

    // The item must be valid
    if(pTVDispInfo->item.pszText != NULL && pTVDispInfo->item.pszText[0] != 0)
    {
        // Attempt to convert the hexa value to DWORD
        if(Text2Hex32(pTVDispInfo->item.pszText, &dwValue32) == ERROR_SUCCESS)
        {
            // Allocate the item text
            szItemText = new TCHAR[cchItemText];
            if(szItemText != NULL)
            {
                // Either format the text as value with flags, or just a value
                if(pFlags != NULL)
                    NamedValueToString(pFlags, szItemText, cchItemText, szFormat, dwValue32);
                else
                    StringCchPrintf(szItemText, cchItemText, szFormat, dwValue32);

                // Yes, accept changes
                PostMessage(hDlg, WM_DEFER_ITEM_TEXT, (WPARAM)pTVDispInfo->item.hItem, (LPARAM)szItemText);
                bAcceptChanges = TRUE;
            }
        }
    }

    return bAcceptChanges;
}

static BOOL DeferSetItemGuidValue(HWND hDlg, LPNMTVDISPINFO pTVDispInfo, LPCTSTR szFormat)
{
    LPTSTR szItemText;
    size_t cchItemText = 0x400;
    GUID guid;
    BOOL bAcceptChanges = FALSE;

    // The item must be valid
    if(pTVDispInfo->item.pszText != NULL && pTVDispInfo->item.pszText[0] != 0)
    {
        // Attempt to convert the text value to GUID
        if(StringToGuid(pTVDispInfo->item.pszText, &guid))
        {
            // Allocate the item text
            szItemText = new TCHAR[cchItemText];
            if(szItemText != NULL)
            {
                // Format the guid
                GuidValueToString(szItemText, cchItemText, szFormat, &guid);

                // Yes, accept changes
                PostMessage(hDlg, WM_DEFER_ITEM_TEXT, (WPARAM)pTVDispInfo->item.hItem, (LPARAM)szItemText);
                bAcceptChanges = TRUE;
            }
        }
    }

    return bAcceptChanges;
}

static BOOL DeferSetItemSidValue(HWND hDlg, LPNMTVDISPINFO pTVDispInfo)
{
    LPTSTR szItemText;
    size_t cchItemText = 0x400;
    PSID pSid = NULL;
    BOOL bAcceptChanges = FALSE;

    // The item must be valid
    if(pTVDispInfo->item.pszText != NULL && pTVDispInfo->item.pszText[0] != 0)
    {
        // Convert the SID to string
        if(StringToSid(pTVDispInfo->item.pszText, &pSid))
        {
            // Allocate the item text
            szItemText = new TCHAR[cchItemText];
            if(szItemText != NULL)
            {
                // Convert the SID to string and post it to the dialog
                SidToString(pSid, szItemText, cchItemText, true);
                PostMessage(hDlg, WM_DEFER_ITEM_TEXT, (WPARAM)pTVDispInfo->item.hItem, (LPARAM)szItemText);
                bAcceptChanges = TRUE;
            }

            // Free the SID
            Sid_Free(pSid);
        }
    }

    return bAcceptChanges;
}

static NTSTATUS QueryObjectSecurity(HANDLE hObject, SECURITY_INFORMATION SecInfo, PSECURITY_DESCRIPTOR * ppSD, PDWORD pcbSD)
{
    PSECURITY_DESCRIPTOR lpSD = ppSD[0];
    NTSTATUS Status;
    DWORD dwTryCount = 0;
    DWORD cbSD = pcbSD[0];

    for(;;)
    {
        // Try to query the object security into the current buffer
        Status = NtQuerySecurityObject(hObject, SecInfo, lpSD, cbSD, &cbSD);
        if(NT_SUCCESS(Status))
        {
            pcbSD[0] = cbSD;
            ppSD[0] = lpSD;
            return Status;
        }

        // If we are trying more than 2 times, quit
        if(dwTryCount++ >= 2)
        {
            pcbSD[0] = 0;
            ppSD[0] = NULL;
            return Status;
        }

        // Allocate new buffer
        if((lpSD = (PSECURITY_DESCRIPTOR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, cbSD)) == NULL)
        {
            pcbSD[0] = 0;
            ppSD[0] = NULL;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
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

    // Set the default security information to query
    pData->SecurityInformation = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    SetDialogSecurityInfo(hDlg);

    // Set blank security descriptor
    PostMessage(hDlg, WM_COMMAND, MAKEWPARAM(IDC_SET_BLANK, BN_CLICKED), 0);
    return TRUE;
}

static int OnSetAclType(HWND hDlg, LPCTSTR szItemText, UINT AclType)
{
    HTREEITEM hItem;
    TVITEM tvi;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);

    // Get the selected item
    hItem = TreeView_GetSelection(hWndTree);
    if(hItem != NULL)
    {
        tvi.mask    = TVIF_PARAM | TVIF_TEXT;
        tvi.pszText = (LPTSTR)szItemText;
        tvi.lParam  = AclType;
        tvi.hItem   = hItem;
        TreeView_SetItem(hWndTree, &tvi);
    }

    return TRUE;
}

static int OnInsertAceBefore(HWND hDlg, BOOL bBeforeSelected, BOOL bDeleteSelected = FALSE)
{
    PACE_HEADER pAceHeader;
    HTREEITEM hItemToDelete = NULL;
    HTREEITEM hInsertAfter;
    HTREEITEM hParent;
    HTREEITEM hItem = NULL;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    PACL pAcl;

    // Retrieve the item where to insert it
    hInsertAfter = TreeView_GetSelection(hWndTree);
    hParent = TreeView_GetParent(hWndTree, hInsertAfter);

    // Shall we deleted the item?
    if(bDeleteSelected)
        hItemToDelete = hInsertAfter;

    // If we shall insert the item BEFORE the current one, move back
    if(bBeforeSelected)
        hInsertAfter = TreeView_GetPreviousItem(hWndTree, hInsertAfter);

    // Create ACE with one entry and set it to the new item
    pAcl = Acl_CreateOneItem(GetDefaultAceType(hWndTree, hParent));
    if(pAcl != NULL)
    {
        // Insert the ACE
        if(GetAce(pAcl, 0, (LPVOID *)(&pAceHeader)))
            hItem = TreeView_InsertAceItem(hWndTree, hParent, hInsertAfter, pAceHeader);

        // Shall we delete the previous item?
        if(hItemToDelete != NULL)
            TreeView_DeleteItem(hWndTree, hItemToDelete);

        // Select the item
        TreeView_Select(hWndTree, hItem, TVGN_CARET);
        HeapFree(g_hHeap, 0, pAcl);
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
    hSwapWith = (bWithPrevious) ? TreeView_GetPrevSibling(hWndTree, hItem)
                                : TreeView_GetNextSibling(hWndTree, hItem);
    if(hItem != NULL && hSwapWith != NULL)
    {
        // Retrieve both ACEsPerform the swap operation
        TreeView_ItemToAce(hWndTree, hItem, AceHelper1);
        TreeView_ItemToAce(hWndTree, hSwapWith, AceHelper2);

        // Change both items
        TreeView_AceToItem(hWndTree, hSwapWith, AceHelper1);
        TreeView_AceToItem(hWndTree, hItem, AceHelper2);

        // Select the previous item
        TreeView_Select(hWndTree, hSwapWith, TVGN_CARET);
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
    TFileTestData * pData = GetDialogData(hDlg);
    PSECURITY_DESCRIPTOR lpSD = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    DWORD cbSD;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    BYTE Buffer[0x400];

    // Get the mask about which security information we want
    GetDialogSecurityInfo(hDlg);
    lpSD = (PSECURITY_DESCRIPTOR)(Buffer);
    cbSD = sizeof(Buffer);

    // Query the security information
    Status = QueryObjectSecurity(pData->hFile, pData->SecurityInformation, &lpSD, &cbSD);

    // If succeeded, load our tree view with security information
    if(NT_SUCCESS(Status))
        TreeView_SecurityDescriptorToTreeView(hWndTree, lpSD);
    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_INFO_INT32, Status, cbSD);

    // Free buffers and return
    if((lpSD != NULL) && (LPBYTE)lpSD != Buffer)
        HeapFree(g_hHeap, 0, lpSD);
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
        Sid_Free(pGroup);
    if(pOwner != NULL)
        Sid_Free(pOwner);
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

static BOOL OnEditNumericItemInPlace(
    HWND /* hDlg */,
    HWND hWndTree,
    HTREEITEM hItem,
    LPCTSTR szFormat)
{
    TVITEM tvi;
    LPTSTR szValue;
    TCHAR szItemText[0x400];
    HWND hEdit;
    DWORD dwValue32 = 0;
    DWORD dwErrCode;

    // Retrieve the item text
    tvi.mask    = TVIF_TEXT;
    tvi.hItem   = hItem;
    tvi.pszText = szItemText;
    tvi.cchTextMax = _countof(szItemText);
    if(!TreeView_GetItem(hWndTree, &tvi))
        return FALSE;

    // Retrieve the value
    szValue = GetItemTextValue(szItemText);
    if(szValue == NULL)
        return FALSE;

    // Convert the value to 32-bit integer
    dwErrCode = Text2Hex32(szValue, &dwValue32);
    if(dwErrCode != ERROR_SUCCESS)
        return FALSE;

    // Format the item to the edit field
    StringCchPrintf(szItemText, _countof(szItemText), szFormat, dwValue32);

    // Apply the value to the edit field
    hEdit = TreeView_GetEditControl(hWndTree);
    if(hEdit == NULL)
        return FALSE;

    // Apply the value to the edit item
    Edit_LimitText(hEdit, 0x10);
    SetWindowText(hEdit, szItemText);
    return TRUE;
}

static BOOL OnEditGuidItemInPlace(
    HWND /* hDlg */,
    HWND hWndTree,
    HTREEITEM hItem)
{
    TVITEM tvi;
    LPTSTR szGuidValue;
    TCHAR szItemText[0x400];
    HWND hEdit;

    // Retrieve the item text
    tvi.mask    = TVIF_TEXT;
    tvi.hItem   = hItem;
    tvi.pszText = szItemText;
    tvi.cchTextMax = _countof(szItemText);
    if(!TreeView_GetItem(hWndTree, &tvi))
        return FALSE;

    // Retrieve the value
    szGuidValue = GetItemTextValue(szItemText);
    if(szGuidValue == NULL)
        return FALSE;

    // Apply the value to the edit field
    hEdit = TreeView_GetEditControl(hWndTree);
    if(hEdit == NULL)
        return FALSE;

    // Apply the value to the edit item
    Edit_LimitText(hEdit, 0x30);
    SetWindowText(hEdit, szGuidValue);
    return TRUE;
}

static BOOL OnEditSidItemInPlace(HWND /* hDlg */, HWND hWndTree, HTREEITEM hItem)
{
    TCHAR szItemText[128];
    HWND hEdit = TreeView_GetEditControl(hWndTree);
    PSID pSid = NULL;

    if(hEdit != NULL)
    {
        if(TreeView_ItemToSid(hWndTree, hItem, &pSid, true))
        {
            Edit_LimitText(hEdit, 128);
            SidToString(pSid, szItemText, _countof(szItemText), false);
            SetWindowText(hEdit, szItemText);
            Sid_Free(pSid);
            return TRUE;
        }
    }

    return FALSE;
}

static void OnEditAceTypeModal(HWND hDlg, HWND hWndTree, HTREEITEM hItem)
{
    ACE_HELPER AceHelper;
    LPCSTR szAceTypeString;
    bool bResult = false;

    // Get the current ACE type from the item
    if(TreeView_ItemToAce(hWndTree, hItem, AceHelper))
    {
        DWORD dwAceType = AceHelper.AceType;

        // Run the dialog
        if(FlagsDialog(hDlg, IDS_ACE_TYPE, AceHdrTypes, dwAceType) == IDOK && dwAceType != AceHelper.AceType)
        {
            // Put the ACE type
            if(AceHelper.SetAceType(dwAceType))
            {
                // Create new SID1
                if(AceHelper.AceLayout & (ACE_FIELD_ACCESS_SID | ACE_FIELD_SERVER_SID))
                    AceHelper.SetAllocatedSid(Sid_CreateNew(AceHelper.AceType), 0);

                // Create new SID2
                if(AceHelper.AceLayout & ACE_FIELD_CLIENT_SID)
                    AceHelper.SetAllocatedSid(Sid_CreateNew(AceHelper.AceType), 1);

                // Set the item text
                szAceTypeString = GetAceTypeString(AceHelper.AceType);
                TreeView_SetTreeItem(hWndTree, hItem, TWideString(szAceTypeString), (TREE_ITEM_ACE | AceHelper.AceType));

                // Fill the sub-item
                bResult = (TreeView_AceToItem(hWndTree, hItem, AceHelper) != NULL);
            }

            // Show an error if failed
            if(bResult == false)
            {
                MessageBoxRc(hDlg, IDS_ERROR, IDS_ACE_TYPE_NOT_SUPPORTED, dwAceType);
            }
        }
    }
}

static void OnEditNumericItemModal(
    HWND hDlg,
    HWND hWndTree,
    HTREEITEM hItem,                // Item to be edited
    TFlagInfo * pFlags,         // Flags array
    LPCTSTR szFormat,               // Format of the flags to be inserted back
    UINT nIDTitle)                  // Title for the flags dialog
{
    TVITEM tvi;
    LPTSTR szValue;
    TCHAR szItemText[0x400];
    DWORD dwFlags32 = 0;
    DWORD dwErrCode;

    // Retrieve the item text
    tvi.mask    = TVIF_TEXT;
    tvi.hItem   = hItem;
    tvi.pszText = szItemText;
    tvi.cchTextMax = _countof(szItemText);
    if(!TreeView_GetItem(hWndTree, &tvi))
        return;

    // Retrieve the value
    szValue = GetItemTextValue(szItemText);
    if(szValue == NULL)
        return;

    // Convert the value to 32-bit integer
    dwErrCode = Text2Hex32(szValue, &dwFlags32);
    if(dwErrCode != ERROR_SUCCESS)
        return;

    // Either invoke the values dialog or the flags dialog
    if(FlagsDialog(hDlg, nIDTitle, pFlags, dwFlags32) == IDOK)
    {
        NamedValueToString(pFlags, szItemText, _countof(szItemText), szFormat, dwFlags32);
        TreeView_SetItem(hWndTree, &tvi);
    }
}

static int OnBeginLabelEdit(HWND hDlg, LPNMTVDISPINFO pTVDispInfo)
{
    PTREE_ITEM_INFO pItemInfo = (PTREE_ITEM_INFO)(pTVDispInfo->item.lParam);
    HWND hWndTree = pTVDispInfo->hdr.hwndFrom;
    HWND hWndEdit;
    BOOL bStartEditing = FALSE;
    int ccMaxChars = 256;
    TCHAR szEditText[256];

    // Verify if the selected tree item is editable
    if(pItemInfo && pItemInfo->BeginEdit)
    {
        // Convert the item text to the editable text
        if(pItemInfo->BeginEdit(pTVDispInfo->item.pszText, szEditText, _countof(szEditText)))
        {
            // Retrieve the handle to the edit box
            if((hWndEdit = TreeView_GetEditControl(hWndTree)) != NULL)
            {
                // Apply the text limit to the edit text
                if(pItemInfo->ccMaxChars != 0)
                    ccMaxChars = pItemInfo->ccMaxChars;
                Edit_LimitText(hWndEdit, pItemInfo->ccMaxChars);

                // Apply the editable text to the edit field
                SetWindowText(hWndEdit, szEditText);
                bStartEditing = TRUE;
            }
        }
    }
/*
    switch(pTVDispInfo->item.lParam)
    {
        case TREE_ITEM_ACE_HEADER_FLAGS:
            bStartEditing = OnEditNumericItemInPlace(hDlg, hWndTree, pTVDispInfo->item.hItem, _T("%02lX"));
            break;

        case TREE_ITEM_ACE_MASK:
        case TREE_ITEM_ADS_ACE_MASK:
        case TREE_ITEM_MANDATORY_MASK:
            bStartEditing = OnEditNumericItemInPlace(hDlg, hWndTree, pTVDispInfo->item.hItem, _T("%08lX"));
            break;

        case TREE_ITEM_MANDATORY_LABEL:
            bStartEditing = OnEditNumericItemInPlace(hDlg, hWndTree, pTVDispInfo->item.hItem, _T("%08lX"));
            break;

        case TREE_ITEM_ACE_OBJ_GUID:
        case TREE_ITEM_ACE_OBJ_GUID2:
            bStartEditing = OnEditGuidItemInPlace(hDlg, hWndTree, pTVDispInfo->item.hItem);
            break;

        case TREE_ITEM_SID_NONE:
        case TREE_ITEM_SID:
        case TREE_ITEM_SID1_NONE:
        case TREE_ITEM_SID1:
        case TREE_ITEM_SID2_NONE:
        case TREE_ITEM_SID2:
            bStartEditing = OnEditSidItemInPlace(hDlg, hWndTree, pTVDispInfo->item.hItem);
            break;

        default:
            SetResultInfo(hDlg, RSI_NTSTATUS, STATUS_CANNOT_EDIT_THIS);
            break;
    }
*/

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
    BOOL bAcceptChanges = FALSE;

    // If pszText contains NULL, it means that the user cancelled the editing
    if(pTVDispInfo->item.pszText != NULL)
    {
        // Verify if the selected file info class is editable
        switch(pTVDispInfo->item.lParam)
        {
            case TREE_ITEM_ACE_HEADER_FLAGS:
                bAcceptChanges = DeferSetItemNumericValue(hDlg, pTVDispInfo, AceHdrFlags, szAceHdrFlagsFmt);
                if(bAcceptChanges == FALSE)
                    SetResultInfo(hDlg, RSI_NTSTATUS, STATUS_INVALID_DATA_FORMAT);
                break;

            case TREE_ITEM_ACE_MASK:
                bAcceptChanges = DeferSetItemNumericValue(hDlg, pTVDispInfo, AceMasks, szAceMaskFmt);
                if(bAcceptChanges == FALSE)
                    SetResultInfo(hDlg, RSI_NTSTATUS, STATUS_INVALID_DATA_FORMAT);
                break;

            case TREE_ITEM_ADS_ACE_MASK:
                bAcceptChanges = DeferSetItemNumericValue(hDlg, pTVDispInfo, AdsAceMasks, szAceMaskFmt);
                if(bAcceptChanges == FALSE)
                    SetResultInfo(hDlg, RSI_NTSTATUS, STATUS_INVALID_DATA_FORMAT);
                break;

            case TREE_ITEM_MANDATORY_MASK:
                bAcceptChanges = DeferSetItemNumericValue(hDlg, pTVDispInfo, LabelMasks, szAceMaskFmt);
                if(bAcceptChanges == FALSE)
                    SetResultInfo(hDlg, RSI_NTSTATUS, STATUS_INVALID_DATA_FORMAT);
                break;

            case TREE_ITEM_MANDATORY_LABEL:
                bAcceptChanges = DeferSetItemNumericValue(hDlg, pTVDispInfo, NULL, szIntLevelFmt);
                if(bAcceptChanges == FALSE)
                    SetResultInfo(hDlg, RSI_NTSTATUS, STATUS_INVALID_DATA_FORMAT);
                break;

            case TREE_ITEM_ACE_OBJ_GUID:
                bAcceptChanges = DeferSetItemGuidValue(hDlg, pTVDispInfo, szAceObjTypeFmt);
                if(bAcceptChanges == FALSE)
                    SetResultInfo(hDlg, RSI_NTSTATUS, STATUS_INVALID_DATA_FORMAT);
                break;

            case TREE_ITEM_ACE_OBJ_GUID2:
                bAcceptChanges = DeferSetItemGuidValue(hDlg, pTVDispInfo, szAceObjTypeFmt2);
                if(bAcceptChanges == FALSE)
                    SetResultInfo(hDlg, RSI_NTSTATUS, STATUS_INVALID_DATA_FORMAT);
                break;

            case TREE_ITEM_SID_NONE:
            case TREE_ITEM_SID:
            case TREE_ITEM_SID1_NONE:
            case TREE_ITEM_SID1:
            case TREE_ITEM_SID2_NONE:
            case TREE_ITEM_SID2:
                bAcceptChanges = DeferSetItemSidValue(hDlg, pTVDispInfo);
                if(bAcceptChanges == FALSE)
                    SetResultInfo(hDlg, RSI_NTSTATUS, STATUS_INVALID_DATA_FORMAT);
                break;

            default:
                SetResultInfo(hDlg, RSI_NTSTATUS, STATUS_CANNOT_EDIT_THIS);
                break;
        }
    }

    // Enable the exit button
    DisableCloseDialog(hDlg, FALSE);
    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, bAcceptChanges);
    return TRUE;
}

static int OnDeleteItem(HWND /* hDlg */, LPNMTREEVIEW /* pNMTreeView */)
{
    // TODO: Uncomment when ready
    //if(pNMTreeView->itemOld.lParam != NULL)
    //    HeapFree(g_hHeap, 0, (LPVOID)(pNMTreeView->itemOld.lParam));
    return TRUE;
}

static int OnTVContextMenu(HWND hDlg, LPARAM lParam)
{
    HTREEITEM hItem;
    POINT pt;
    LPARAM ItemParam;
    HMENU hMainMenu = NULL;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    RECT rect;

    // Get the selected item
    hItem = TreeView_GetSelection(hWndTree);
    if(hItem != NULL)
    {
        // Get the LPARAM of the tree item.
        ItemParam = TreeView_GetItemParam(hWndTree, hItem);

        // NULL DACL or Empty DACL -> Exec context menu of that item type
        if(ItemParam == TREE_ITEM_NULL_ACL || ItemParam == TREE_ITEM_EMPTY_ACL)
        {
            hMainMenu = FindContextMenu(IDR_ACL_TYPE_MENU);
        }

        if(IsTreeItemAce(ItemParam))
        {
            hMainMenu = FindContextMenu(IDR_ACE_MENU);
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
    //LPARAM lParam;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    //bool bGoToParent = true;
    BYTE DataBuffer[0x200];

    // Reset the XXX_YYY_OBJECT_ACE::Flags
    OBJECT_ACE_Flags = 0;

    // Get the handle to the selected item
    if((hItem = TreeView_GetSelection(hWndTree)) != NULL)
    {
        // Retrieve the parent of the item
        hParent = TreeView_GetParent(hWndTree, hItem);

        // Retrieve the tree item info of the selected item
        if((pItemInfo = (PTREE_ITEM_INFO)TreeView_GetItemParam(hWndTree, hItem)) != NULL)
        {
            // Save the item info to the stack
            memcpy(&SaveItemInfo, pItemInfo, sizeof(TREE_ITEM_INFO));
            pItemInfo = &SaveItemInfo;

            // Does the item have handler for double click?
            if(pItemInfo->lpData == NULL && pItemInfo->CreateNew != NULL)
            {
                size_t cbDataBuffer = sizeof(DataBuffer);

                if(pItemInfo->CreateNew(DataBuffer, &cbDataBuffer))
                {
                    // Get the previous item
                    hInsertAfter = TreeView_GetPreviousItem(hWndTree, hItem);

                    // Delete the subitems of the item
                    TreeView_DeleteItem(hWndTree, hItem);

                    // Insert the new item with the created data
                    TV_InsertNewItem(hWndTree, hParent, hInsertAfter, &SaveItemInfo, NULL, DataBuffer, &DataBuffer[cbDataBuffer]);
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

        case TREE_ITEM_NULL_ACL:    // Insert a new ACE to the tree
        case TREE_ITEM_EMPTY_ACL:
            OnInsertAceBefore(hDlg, TRUE, TRUE);
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
            OnEditNumericItemModal(hDlg, hWndTree, hSelItem, IntegrityLevels, szIntLevelFmt, IDS_INTEGRITY_LEVEL);
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
                return OnSetAclType(hDlg, szNullAcl, TREE_ITEM_NULL_ACL);

            case IDC_SET_EMPTY_ACL:
                return OnSetAclType(hDlg, szEmptyAcl, TREE_ITEM_EMPTY_ACL);

            case IDC_NEW_ACE_BEFORE:
                return OnInsertAceBefore(hDlg, TRUE);

            case IDC_NEW_ACE_AFTER:
                return OnInsertAceBefore(hDlg, FALSE);

            case IDC_MOVE_ACE_UP:
                return OnSwapAceWith(hDlg, TRUE);

            case IDC_MOVE_ACE_DOWN:
                return OnSwapAceWith(hDlg, FALSE);

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

static PACL CreateDacl(PSID pSidEveryone, PSID pSidUser, PSID pSidAdmin)
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

static DWORD SetExoticSecurityDescriptor(HANDLE hObject)
{
    SID_IDENTIFIER_AUTHORITY SiaEveryone = SECURITY_WORLD_SID_AUTHORITY;
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
    RtlAllocateAndInitializeSid(&SiaEveryone, 1, 0, 0, 0, 0, 0, 0, 0, 0, &pSidEveryone);
    cbSidEveryone = RtlLengthSid(pSidEveryone);

    // Initialize the blank security descriptor
    if(NT_SUCCESS(Status))
    {
        Status = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    }

    // Set the DACL to the security descriptor
    if(NT_SUCCESS(Status))
    {
        if((pDacl = CreateDacl(pSidEveryone, pSidUser, pSidAdmin)) != NULL)
        {
            if((Status = RtlSetDaclSecurityDescriptor(&sd, TRUE, pDacl, FALSE)) == STATUS_SUCCESS)
            {
                SecurityInfo |= DACL_SECURITY_INFORMATION;
            }
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

void DebugCode_SecurityDescriptor(LPCTSTR szPath)
{
    HANDLE hFolder;

    // Cut the NT prefix
    if(!_tcsnicmp(szPath, _T("\\??\\"), 4))
        szPath += 4;

    // Open the folder and set security descriptor
    hFolder = CreateFile(szPath, GENERIC_ALL | READ_CONTROL | WRITE_DAC | WRITE_OWNER, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if(hFolder != INVALID_HANDLE_VALUE)
    {
        SetExoticSecurityDescriptor(hFolder);
        CloseHandle(hFolder);
    }
}
#endif
