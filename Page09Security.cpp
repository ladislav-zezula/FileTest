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
#define TREE_ITEM_NO_SID            0x10000000      // Under OWNER/GROUP, No SID present
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
#define TREE_ITEM_ACE_OBJ_GUID      0x3000000D      // ACE:ObjectType
#define TREE_ITEM_ACE_OBJ_GUID2     0x3000000E      // ACE:InheritedObjectType
#define TREE_ITEM_TYPE_MASK         0xF0000000
#define TREE_ITEM_VALUE_MASK        0x0FFFFFFF

#define MAXIMUM_ACL_SIZE         0xFFF8             // The biggest ACL that can possibly exist

typedef bool (*ACE_FILTER_PROC)(PACE_HEADER pAceHeader);

// Masks for each tre item
static LPCTSTR szUnknownSid     = _T("<UNKNOWN-SID>");
static LPCTSTR szNullAcl        = _T("<NULL ACL. Double-click to create new...>");
static LPCTSTR szEmptyAcl       = _T("<Empty ACL. Double-click to create new...>");
static LPCTSTR szAceHdrTypeFmt  = _T("AceType: 0x%02lX");
static LPCTSTR szAceHdrFlagsFmt = _T("AceFlags: 0x%02lX  ");
static LPCTSTR szAceHdrSizeFmt  = _T("AceSize: 0x%04lX");
static LPCTSTR szAceMaskFmt     = _T("Mask: 0x%08lX  ");
static LPCTSTR szIntLevelFmt    = _T("IntLevel: 0x%08lX");
static LPCTSTR szAceFlagsFmt    = _T("Flags: 0x%08lX ");
static LPCTSTR szAceObjTypeFmt  = _T("ObjectType: %s");
static LPCTSTR szAceObjTypeFmt2 = _T("InheritedObjectType: %s");

static SID_IDENTIFIER_AUTHORITY SiaNull  = SECURITY_NULL_SID_AUTHORITY;
static SID_IDENTIFIER_AUTHORITY SiaWorld = SECURITY_WORLD_SID_AUTHORITY;
static SID_IDENTIFIER_AUTHORITY SiaLabel = SECURITY_MANDATORY_LABEL_AUTHORITY;

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

static TFlagInfo MandatoryMasks[] =
{
    FLAGINFO_BITV(SYSTEM_MANDATORY_LABEL_NO_WRITE_UP),
    FLAGINFO_BITV(SYSTEM_MANDATORY_LABEL_NO_READ_UP),
    FLAGINFO_BITV(SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP),
    FLAGINFO_END()
};

static TFlagInfo AceFlags[] =
{
    FLAGINFO_BITV(ACE_OBJECT_TYPE_PRESENT),
    FLAGINFO_BITV(ACE_INHERITED_OBJECT_TYPE_PRESENT),
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
    0,                                          // ACCESS_ALLOWED_COMPOUND_ACE_TYPE (?)
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

static DWORD AceSidOffsets[] =
{
    FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart),
    FIELD_OFFSET(ACCESS_DENIED_ACE, SidStart),
    FIELD_OFFSET(SYSTEM_AUDIT_ACE, SidStart),
    FIELD_OFFSET(SYSTEM_ALARM_ACE, SidStart),
    0,                                          // ACCESS_ALLOWED_COMPOUND_ACE(?)
    FIELD_OFFSET(ACCESS_ALLOWED_OBJECT_ACE, SidStart),
    FIELD_OFFSET(ACCESS_DENIED_OBJECT_ACE, SidStart),
    FIELD_OFFSET(SYSTEM_AUDIT_OBJECT_ACE, SidStart),
    FIELD_OFFSET(SYSTEM_ALARM_OBJECT_ACE, SidStart),

    FIELD_OFFSET(ACCESS_ALLOWED_CALLBACK_ACE, SidStart),
    FIELD_OFFSET(ACCESS_DENIED_CALLBACK_ACE, SidStart),
    FIELD_OFFSET(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, SidStart),
    FIELD_OFFSET(ACCESS_DENIED_CALLBACK_OBJECT_ACE, SidStart),
    FIELD_OFFSET(SYSTEM_AUDIT_CALLBACK_ACE, SidStart),
    FIELD_OFFSET(SYSTEM_ALARM_CALLBACK_ACE, SidStart),
    FIELD_OFFSET(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE, SidStart),
    FIELD_OFFSET(SYSTEM_ALARM_CALLBACK_OBJECT_ACE, SidStart),
    FIELD_OFFSET(SYSTEM_MANDATORY_LABEL_ACE, SidStart)
};

//-----------------------------------------------------------------------------
// Local functions - SID

static PSID Sid_Allocate(DWORD dwLength)
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

static PSID Sid_AllocateAndInitialize(
    IN PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
    IN BYTE nSubAuthorityCount,
    IN PDWORD pnSubAuthorities)
{
    PSID pSid;

    // Prepare a buffer of a sufficient size
    pSid = Sid_Allocate(GetSidLengthRequired(nSubAuthorityCount));
    if (pSid == NULL)
        return NULL;

    // Fill in the identifier authority and sub-authority count
    if (InitializeSid(pSid, pIdentifierAuthority, nSubAuthorityCount))
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
static PSID Sid_CreateNew(BYTE AceType)
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

static void SidToString(PSID pvSid, LPTSTR szString, size_t cchString, bool bAddUserName)
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

static bool StringToSid(LPTSTR szSid, PSID * ppSid)
{
    SID_IDENTIFIER_AUTHORITY Sia = SiaNull;
    SID_NAME_USE SidNameUse;
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
    if(szSid[0] == _T('S') && szSid[1] == _T('-') && szSid[2] == _T('1') && szSid[3] == _T('-'))
    {
        // Skip revision
        dwRevision = SID_REVISION;
        szSid += 4;

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

    if(pSid != NULL)
    {
        // Retrieve integrity level from SID
        if(!memcmp(GetSidIdentifierAuthority(pSid), &SiaLabel, sizeof(SID_IDENTIFIER_AUTHORITY)))
        {
            dwSubAuthCount = *GetSidSubAuthorityCount(pSid);
            if(dwSubAuthCount > 0)
            {
                return *GetSidSubAuthority(pSid, dwSubAuthCount - 1);
            }
        }
    }

    // Set default integrity level
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

static bool AceFilterIncludeAll(PACE_HEADER)
{
    return true;
}

static bool AceFilterExcludeMandatoryAces(PACE_HEADER pAceHeader)
{
    return (pAceHeader->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE);
}

static bool AceFilterMandatoryAcesOnly(PACE_HEADER pAceHeader)
{
    return (pAceHeader->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE);
}

//-----------------------------------------------------------------------------
// Local functions - tree items

static BOOL IsTreeItemAce(LPARAM lParam)
{
    return ((lParam & TREE_ITEM_TYPE_MASK) == TREE_ITEM_ACE) ? TRUE : FALSE;
}

static LPCSTR GetAceTypeString(DWORD AceType)
{
    BYTE MaxAceType = (BYTE)(_countof(AceHdrTypes) - 1);

    // Insert the "root" item with ACE type
    return (AceType < MaxAceType) ? AceHdrTypes[AceType].szFlagText : "UNKNOWN_ACE";
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

static BYTE GetDefaultAceType(HWND hTreeView, HTREEITEM hParent)
{
    BYTE AceType = ACCESS_ALLOWED_ACE_TYPE;

    // Retrieve the parent item
    switch(TreeView_GetItemParam(hTreeView, hParent))
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

static bool TreeView_ItemToValue32(HWND hTreeView, HTREEITEM hItem, LPDWORD PtrValue)
{
    TVITEM tvi;
    LPTSTR szValue;
    TCHAR szItemText[256];
    int nError;

    // Get the text from the
    tvi.mask = TVIF_TEXT;
    tvi.hItem = hItem;
    tvi.pszText = szItemText;
    tvi.cchTextMax = _countof(szItemText);
    if(TreeView_GetItem(hTreeView, &tvi))
    {
        // Retrieve the value
        szValue = GetItemTextValue(szItemText);
        if(szValue != NULL)
        {
            // Convert the 32-bit value to an integer
            nError = Text2Hex32(szValue, PtrValue);
            return (nError == ERROR_SUCCESS);
        }
    }

    return false;
}

static bool TreeView_ItemToGuid(HWND hTreeView, HTREEITEM hItem, LPGUID PtrGuid)
{
    TVITEM tvi;
    LPTSTR szValue;
    TCHAR szItemText[256];

    // Get the text from the
    tvi.mask = TVIF_TEXT;
    tvi.hItem = hItem;
    tvi.pszText = szItemText;
    tvi.cchTextMax = _countof(szItemText);
    if(TreeView_GetItem(hTreeView, &tvi))
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

static HTREEITEM TreeView_SidToItem(HWND hTreeView, HTREEITEM hItem, PSID pSid, LPCTSTR szDefaultText)
{
    LPARAM lParam = TREE_ITEM_NO_SID;
    TCHAR szTextBuff[256];

    // If the SID is present, convert the SID to the tree item
    if(pSid != NULL)
    {
        // Convert the SID to text
        SidToString(pSid, szTextBuff, _countof(szTextBuff), true);
        szDefaultText = szTextBuff;
        lParam = TREE_ITEM_SID;
    }

    return TreeView_SetTreeItem(hTreeView, hItem, szDefaultText, lParam);
}

static HTREEITEM TreeView_InsertSidItem(HWND hTreeView, HTREEITEM hParent, PSID pSid, LPCTSTR szDefaultText)
{
    HTREEITEM hItem;

    // Insert a new item
    hItem = InsertTreeItem(hTreeView, hParent, szDefaultText, TREE_ITEM_NO_SID);
    if(hItem != NULL)
    {
        // Apply the SID to the item and expand the parent
        TreeView_SidToItem(hTreeView, hItem, pSid, szDefaultText);
        TreeView_Expand(hTreeView, hParent, TVE_EXPAND);
    }
    return hItem;
}

static bool TreeView_ItemToSid(HWND hTreeView, HTREEITEM hItem, PSID * ppSid, bool bCanCreateNewSid)
{
    TVITEM tvi;
    TCHAR szItemText[256];

    // Get the text from the treeview item
    tvi.mask = TVIF_TEXT | TVIF_PARAM;
    tvi.hItem = hItem;
    tvi.pszText = szItemText;
    tvi.cchTextMax = _countof(szItemText);
    TreeView_GetItem(hTreeView, &tvi);

    // Convert the tree item to SID
    switch(tvi.lParam)
    {
        case TREE_ITEM_NO_SID:
            if(bCanCreateNewSid)
                *ppSid = Sid_CreateNew(ACCESS_ALLOWED_ACE_TYPE);
            break;

        case TREE_ITEM_SID:
            StringToSid(szItemText, ppSid);
            break;
    }

    return (*ppSid != NULL);
}

static bool TreeView_ItemToSid(HWND hTreeView, HTREEITEM hItem, ACE_HELPER & AceHelper)
{
    PSID pSid = NULL;
    bool bResult = false;

    if(TreeView_ItemToSid(hTreeView, hItem, &pSid, false))
    {
        AceHelper.SetAllocatedSid(pSid);
        bResult = true;
    }

    return bResult;
}

static HTREEITEM TreeView_MandatorySidToItem(HWND hTreeView, HTREEITEM hParent, PSID pSid)
{
    TCHAR szItemText[256];

    // Format the integrity level
    StringCchPrintf(szItemText, _countof(szItemText), szIntLevelFmt, SidToIntegrityLevel(pSid));
    return TreeView_SetTreeItem(hTreeView, hParent, szItemText, TREE_ITEM_MANDATORY_LABEL);
}

static HTREEITEM TreeView_InsertMandatorySidItem(HWND hTreeView, HTREEITEM hParent, PSID pSid, LPCTSTR szDefaultText)
{
    HTREEITEM hItem;

    // Insert a new item
    hItem = InsertTreeItem(hTreeView, hParent, szDefaultText, TREE_ITEM_MANDATORY_LABEL);
    if(hItem != NULL)
    {
        // Apply the SID to the item and expand the parent
        TreeView_MandatorySidToItem(hTreeView, hItem, pSid);
        TreeView_Expand(hTreeView, hParent, TVE_EXPAND);
    }
    return hItem;
}

static bool TreeView_ItemToMandatorySid(HWND hTreeView, HTREEITEM hItem, ACE_HELPER & AceHelper)
{
    DWORD dwIntLevel = SECURITY_MANDATORY_MEDIUM_RID;
    PSID pSid = NULL;
    bool bResult = false;

    // Convert the item to SID
    if(TreeView_ItemToValue32(hTreeView, hItem, &dwIntLevel))
    {
        // Create new mandatory label SID
        DWORD nSubAuthorities[] = { dwIntLevel };
        pSid = Sid_AllocateAndInitialize(&SiaLabel, RTL_NUMBER_OF(nSubAuthorities), nSubAuthorities);
        if(pSid != NULL)
        {
            // Store the SID to the ACE_HELPER structure
            AceHelper.SetAllocatedSid(pSid);
            bResult = true;
        }
    }

    return bResult;
}

static HTREEITEM TreeView_AceToItem(
    HWND hTreeView,
    HTREEITEM hItem,
    ACE_HELPER & AceHelper)
{
    TCHAR szItemText[256];

    // Check if the layout is supported
    if(AceHelper.AceLayout == ACE_LAYOUT_UNKNOWN)
        return NULL;

    // If the parent is valis
    if(hItem != NULL)
    {
        // Delete all children
        TreeView_DeleteChildren(hTreeView, hItem);

        // Insert the subitem with ACE type
        StringCchPrintf(szItemText, _countof(szItemText), szAceHdrTypeFmt, AceHelper.AceType);
        InsertTreeItem(hTreeView, hItem, szItemText, TREE_ITEM_ACE_HEADER_TYPE);

        // Insert the subitem with ACE flags
        NamedValueToString(AceHdrFlags, szItemText, _countof(szItemText), szAceHdrFlagsFmt, AceHelper.AceFlags);
        InsertTreeItem(hTreeView, hItem, szItemText, TREE_ITEM_ACE_HEADER_FLAGS);

        // Insert the subitem with ACE size
        StringCchPrintf(szItemText, _countof(szItemText), szAceHdrSizeFmt, AceHelper.AceSize);
        InsertTreeItem(hTreeView, hItem, szItemText, TREE_ITEM_ACE_HEADER_SIZE);

        // Insert the ACE:Mask (ACCESS_MASK), if present
        if(AceHelper.AceLayout & ACE_FIELD_ACCESS_MASK)
        {
            NamedValueToString(AceMasks, szItemText, _countof(szItemText), szAceMaskFmt, AceHelper.Mask);
            InsertTreeItem(hTreeView, hItem, szItemText, TREE_ITEM_ACE_MASK);
        }

        // Insert the ACE:Mask (Object ACEs), if present
        if(AceHelper.AceLayout & ACE_FIELD_ADS_ACCESS_MASK)
        {
            NamedValueToString(AdsAceMasks, szItemText, _countof(szItemText), szAceMaskFmt, AceHelper.Mask);
            InsertTreeItem(hTreeView, hItem, szItemText, TREE_ITEM_ADS_ACE_MASK);
        }

        // Insert the ACE:Mask (MANDATORY_LABEL_MASK), if present
        if(AceHelper.AceLayout & ACE_FIELD_MANDATORY_MASK)
        {
            NamedValueToString(MandatoryMasks, szItemText, _countof(szItemText), szAceMaskFmt, AceHelper.Mask);
            InsertTreeItem(hTreeView, hItem, szItemText, TREE_ITEM_MANDATORY_MASK);
        }

        // Insert the ACE::Flags, if present
        if(AceHelper.AceLayout & ACE_FIELD_FLAGS)
        {
            NamedValueToString(AceFlags, szItemText, _countof(szItemText), szAceFlagsFmt, AceHelper.Flags);
            InsertTreeItem(hTreeView, hItem, szItemText, TREE_ITEM_ACE_FLAGS);
        }

        // Insert the ACE:ObjectType, if present
        // Info about object GUIDs, see https://msdn.microsoft.com/en-us/library/cc223512.aspx
        if(AceHelper.AceLayout & ACE_FIELD_OBJECT_TYPE)
        {
            GuidValueToString(szItemText, _countof(szItemText), szAceObjTypeFmt, &AceHelper.ObjectType);
            InsertTreeItem(hTreeView, hItem, szItemText, TREE_ITEM_ACE_OBJ_GUID);
        }

        // Insert the ACE:InheritedObjectType, if present
        if(AceHelper.AceLayout & ACE_FIELD_OBJECT_TYPE2)
        {
            GuidValueToString(szItemText, _countof(szItemText), szAceObjTypeFmt2, &AceHelper.InheritedObjectType);
            InsertTreeItem(hTreeView, hItem, szItemText, TREE_ITEM_ACE_OBJ_GUID2);
        }

        // Insert the integrity level, if present
        if(AceHelper.AceLayout & ACE_FIELD_MANDATORY_SID)
            TreeView_InsertMandatorySidItem(hTreeView, hItem, AceHelper.Sid, szUnknownSid);

        // Insert the access SID, if present
        if(AceHelper.AceLayout & ACE_FIELD_ACCESS_SID)
            TreeView_InsertSidItem(hTreeView, hItem, AceHelper.Sid, szUnknownSid);

        // Expand the item
        TreeView_Expand(hTreeView, hItem, TVE_EXPAND);
    }

    // Return the item handle
    return hItem;
}

static HTREEITEM TreeView_AceToItem(
    HWND hTreeView,
    HTREEITEM hParent,
    PACE_HEADER pAceHeader)
{
    ACE_HELPER AceHelper;

    if(!AceHelper.SetAce(pAceHeader))
        return NULL;
    return TreeView_AceToItem(hTreeView, hParent, AceHelper);
}

static HTREEITEM TreeView_InsertAceItem(
    HWND hTreeView,
    HTREEITEM hParent,
    HTREEITEM hInsertAfter,
    PACE_HEADER pAceHeader)
{
    HTREEITEM hItem;
    LPCSTR szAceTypeString = GetAceTypeString(pAceHeader->AceType);

    // Insert the "root" item with ACE type
    hItem = InsertTreeItem(hTreeView, hParent, hInsertAfter, TWideString(szAceTypeString), (PVOID)(ULONG_PTR)(TREE_ITEM_ACE | pAceHeader->AceType));
    if(hItem != NULL)
    {
        // Fill the ACE structure
        TreeView_AceToItem(hTreeView, hItem, pAceHeader);
        TreeView_Expand(hTreeView, hParent, TVE_EXPAND);
    }

    // Return the newly created tree item
    return hItem;
}

static bool TreeView_ItemToAce(
    HWND hTreeView,
    HTREEITEM hItem,
    ACE_HELPER & AceHelper)
{
    DWORD dwAceType = 0;

    // Fill the entire structure with zeros
    AceHelper.Reset();

    // Retrieve the (first/next) child
    hItem = TreeView_GetChild(hTreeView, hItem);
    while(hItem != NULL)
    {
        bool bResult = false;

        // Get the values of the ACE according the item type
        switch(TreeView_GetItemParam(hTreeView, hItem))
        {
            case TREE_ITEM_ACE_HEADER_TYPE:     // Save the ACE_Header::AceType
                if(TreeView_ItemToValue32(hTreeView, hItem, &dwAceType))
                    bResult = AceHelper.SetAceType(dwAceType);
                break;

            case TREE_ITEM_ACE_HEADER_FLAGS:    // Save the ACE_Header::AceFlags
                bResult = TreeView_ItemToValue32(hTreeView, hItem, &AceHelper.AceFlags);
                break;

            case TREE_ITEM_ACE_HEADER_SIZE:     // Save the ACE_HEADER::AceSize (even if it will not be used)
                bResult = TreeView_ItemToValue32(hTreeView, hItem, &AceHelper.AceSize);
                break;

            case TREE_ITEM_ACE_MASK:
            case TREE_ITEM_ADS_ACE_MASK:
            case TREE_ITEM_MANDATORY_MASK:
                bResult = TreeView_ItemToValue32(hTreeView, hItem, &AceHelper.Mask);
                break;

            case TREE_ITEM_ACE_FLAGS:
                bResult = TreeView_ItemToValue32(hTreeView, hItem, &AceHelper.Flags);
                break;

            case TREE_ITEM_ACE_OBJ_GUID:
                bResult = TreeView_ItemToGuid(hTreeView, hItem, &AceHelper.ObjectType);
                break;

            case TREE_ITEM_ACE_OBJ_GUID2:
                bResult = TreeView_ItemToGuid(hTreeView, hItem, &AceHelper.InheritedObjectType);
                break;

            case TREE_ITEM_MANDATORY_LABEL:
                bResult = TreeView_ItemToMandatorySid(hTreeView, hItem, AceHelper);
                break;

            case TREE_ITEM_SID:
                bResult = TreeView_ItemToSid(hTreeView, hItem, AceHelper);
                break;
        }

        // If an error happened, do nothing
        if(!bResult)
            return false;
        hItem = TreeView_GetNextSibling(hTreeView, hItem);
    }

    return true;
}

static DWORD TreeView_InsertAclItems(
    HWND hTreeView,
    HTREEITEM hParent,
    PACL pAcl,
    ACE_FILTER_PROC PfnAceFilter)
{
    PACE_HEADER pAceHeader;
    HTREEITEM hItem;
    DWORD dwAceCount = 0;

    //
    // Note: parent ACL item already has the proper item text and LPARAM
    //

    // Do nothing if there is no item
    if(hParent != NULL)
    {
        // Remove all children, if any
        TreeView_DeleteChildren(hTreeView, hParent);

        // Insert new children, if needed
        if(pAcl != NULL)
        {
            // Parse all ACEs
            for(WORD AceIndex = 0; AceIndex < pAcl->AceCount; AceIndex++)
            {
                if(GetAce(pAcl, AceIndex, (PVOID *)&pAceHeader))
                {
                    // If the filter approves the ACE, insert it
                    if(PfnAceFilter(pAceHeader))
                    {
                        hItem = TreeView_InsertAceItem(hTreeView, hParent, TVI_LAST, pAceHeader);
                        dwAceCount += (hItem != NULL) ? 1 : 0;
                    }
                }
            }

            // If we didn't insert any ACEs, insert default text
            // Also triggers on empty ACLs
            if(dwAceCount == 0)
            {
                hItem = InsertTreeItem(hTreeView, hParent, szEmptyAcl, TREE_ITEM_EMPTY_ACL);
            }
        }
        else
        {
            // NULL DACL
            hItem = InsertTreeItem(hTreeView, hParent, szNullAcl, TREE_ITEM_NULL_ACL);
        }

        // Always expand the item
        TreeView_Expand(hTreeView, hParent, TVE_EXPAND);
    }

    return dwAceCount;
}

static bool TreeView_ItemToAcl_Add(
    HWND hTreeView,
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
        lParam = TreeView_GetItemParam(hTreeView, hItem);
        if((lParam & TREE_ITEM_TYPE_MASK) != TREE_ITEM_ACE)
            return false;

        // Retrieve the (first/next) child
        bResult = TreeView_ItemToAce(hTreeView, hItem, AceHelper);
        if(bResult == FALSE)
            return false;

        // Create an ACE that reflects the type
        switch(lParam & TREE_ITEM_VALUE_MASK)
        {
            case ACCESS_ALLOWED_ACE_TYPE:
                bResult = AddAccessAllowedAceEx(pAcl, ACL_REVISION, AceHelper.AceFlags, AceHelper.Mask, AceHelper.Sid);
                break;

            case ACCESS_DENIED_ACE_TYPE:
                bResult = AddAccessDeniedAceEx(pAcl, ACL_REVISION, AceHelper.AceFlags, AceHelper.Mask, AceHelper.Sid);
                break;

            case SYSTEM_AUDIT_ACE_TYPE:
                bResult = AddAuditAccessAceEx(pAcl, ACL_REVISION, AceHelper.AceFlags, AceHelper.Mask, AceHelper.Sid, FALSE, FALSE);
                break;

            default:    // Let our helper to add the ACE
                bResult = AceHelper.AddToAcl(pAcl);
                break;
        }

        // Get the next sibling
        hItem = TreeView_GetNextSibling(hTreeView, hItem);
    }

    // We need to free the SID
    return (bool)(bResult != FALSE);
}

static BOOL TreeView_ItemToAcl(
    HWND hTreeView,
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
        lParam1 = TreeView_GetItemParam(hTreeView, hAclItem1);

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
        TreeView_ItemToAcl_Add(hTreeView, hAclItem1, pAcl);

    // If the secondary item is an ACL item, we insert all ACEs to the ACL
    if(hAclItem2 != NULL)
        TreeView_ItemToAcl_Add(hTreeView, hAclItem2, pAcl);

    // Finalize the ACL
    *ppAcl = Acl_FinishBuild(pAcl);
    return TRUE;
}

static void TreeView_SdToTreeView(
    HWND hTreeView,
    PSECURITY_DESCRIPTOR pSD)
{
    HTREEITEM hItem;
    TCHAR szNotPresent[128];
    PSID pOwner = NULL;
    PSID pGroup = NULL;
    PACL pDacl = NULL;
    PACL pSacl = NULL;
    BOOL bTemp;

    // Clear all current tree view items
    TreeView_DeleteAllItems(hTreeView);
    LoadString(g_hInst, IDS_NOT_PRESENT, szNotPresent, _countof(szNotPresent));

    //
    // Insert tree item for owner security information
    //

    hItem = InsertTreeItem(hTreeView, TVI_ROOT, _T("OWNER_SECURITY_INFORMATION"), TREE_ITEM_OWNER);
    if(GetSecurityDescriptorOwner(pSD, &pOwner, &bTemp))
        TreeView_InsertSidItem(hTreeView, hItem, pOwner, szNotPresent);

    //
    // Insert tree item for group security information
    //

    hItem = InsertTreeItem(hTreeView, TVI_ROOT, _T("GROUP_SECURITY_INFORMATION"), TREE_ITEM_GROUP);
    if(GetSecurityDescriptorGroup(pSD, &pGroup, &bTemp))
        TreeView_InsertSidItem(hTreeView, hItem, pGroup, szNotPresent);

    //
    // Insert tree item for DACL security information
    //

    hItem = InsertTreeItem(hTreeView, TVI_ROOT, _T("DACL_SECURITY_INFORMATION"), TREE_ITEM_DACL);
    if(GetSecurityDescriptorDacl(pSD, &bTemp, &pDacl, &bTemp))
        TreeView_InsertAclItems(hTreeView, hItem, pDacl, AceFilterIncludeAll);

    //
    // Insert tree item for SACL security information
    //

    hItem = InsertTreeItem(hTreeView, TVI_ROOT, _T("SACL_SECURITY_INFORMATION"), TREE_ITEM_SACL);
    if(GetSecurityDescriptorSacl(pSD, &bTemp, &pSacl, &bTemp))
        TreeView_InsertAclItems(hTreeView, hItem, pSacl, AceFilterExcludeMandatoryAces);

    //
    // Insert tree item for LABEL security information
    //

    hItem = InsertTreeItem(hTreeView, TVI_ROOT, _T("LABEL_SECURITY_INFORMATION"), TREE_ITEM_LABEL);
    if(GetSecurityDescriptorSacl(pSD, &bTemp, &pSacl, &bTemp))
        TreeView_InsertAclItems(hTreeView, hItem, pSacl, AceFilterMandatoryAcesOnly);
}

void TreeView_DeferItemText(HWND hDlg, WPARAM wParam, LPARAM lParam)
{
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);
    TVITEM tvi;

    // Apply the text to the tree item
    tvi.mask    = TVIF_TEXT;
    tvi.hItem   = (HTREEITEM)wParam;
    tvi.pszText = (LPTSTR)lParam;
    TreeView_SetItem(hTreeView, &tvi);

    // Free the text
    delete [] tvi.pszText;
}

static SECURITY_INFORMATION GetWantedSecurityInfo(HWND hDlg)
{
    SECURITY_INFORMATION SecInfo = 0;

    if(IsDlgButtonChecked(hDlg, IDC_OWNER_INFORMATION) == BST_CHECKED)
        SecInfo |= OWNER_SECURITY_INFORMATION;
    if(IsDlgButtonChecked(hDlg, IDC_GROUP_INFORMATION) == BST_CHECKED)
        SecInfo |= GROUP_SECURITY_INFORMATION;
    if(IsDlgButtonChecked(hDlg, IDC_DACL_INFORMATION) == BST_CHECKED)
        SecInfo |= DACL_SECURITY_INFORMATION;
    if(IsDlgButtonChecked(hDlg, IDC_SACL_INFORMATION) == BST_CHECKED)
        SecInfo |= SACL_SECURITY_INFORMATION;
    if(IsDlgButtonChecked(hDlg, IDC_LABEL_INFORMATION) == BST_CHECKED)
        SecInfo |= LABEL_SECURITY_INFORMATION;

    return SecInfo;
}

static void UpdateContextMenu(HWND hTreeView, HTREEITEM hItem, HMENU hMainMenu)
{
    HTREEITEM hNextItem;
    HMENU hSubMenu = GetSubMenu(hMainMenu, 0);
    UINT uEnable = MF_GRAYED;

    // Move ACE up is only allowed when the ACE is not the first one
    if(TreeView_GetPrevSibling(hTreeView, hItem) == NULL)
        EnableMenuItem(hSubMenu, IDC_MOVE_ACE_UP, MF_GRAYED);

    // Move ACE down is only allowed when the ACE is not the last one
    hNextItem = TreeView_GetNextSibling(hTreeView, hItem);
    if(hNextItem != NULL)
    {
        if(TreeView_GetItemParam(hTreeView, hNextItem) != TREE_ITEM_NULL_ACL)
            uEnable = MF_ENABLED;
    }
    EnableMenuItem(hSubMenu, IDC_MOVE_ACE_DOWN, uEnable);
}

static HTREEITEM TreeView_GetPreviousItem(HWND hTreeView, HTREEITEM hItem)
{
    hItem = TreeView_GetPrevSibling(hTreeView, hItem);
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
    CheckDlgButton(hDlg, IDC_OWNER_INFORMATION, BST_CHECKED);
    CheckDlgButton(hDlg, IDC_GROUP_INFORMATION, BST_CHECKED);
    CheckDlgButton(hDlg, IDC_DACL_INFORMATION, BST_CHECKED);
//  CheckDlgButton(hDlg, IDC_SACL_INFORMATION, BST_CHECKED);

    // Set blank security descriptor
    PostMessage(hDlg, WM_COMMAND, MAKEWPARAM(IDC_SET_BLANK, BN_CLICKED), 0);
    return TRUE;
}

static int OnSetAclType(HWND hDlg, LPCTSTR szItemText, UINT AclType)
{
    HTREEITEM hItem;
    TVITEM tvi;
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);

    // Get the selected item
    hItem = TreeView_GetSelection(hTreeView);
    if(hItem != NULL)
    {
        tvi.mask    = TVIF_PARAM | TVIF_TEXT;
        tvi.pszText = (LPTSTR)szItemText;
        tvi.lParam  = AclType;
        tvi.hItem   = hItem;
        TreeView_SetItem(hTreeView, &tvi);
    }

    return TRUE;
}

static int OnCreateNewSid(HWND /* hDlg */, HWND hTreeView, HTREEITEM hItem)
{
    PSID pSid;

    pSid = Sid_CreateNew(ACCESS_ALLOWED_ACE_TYPE);
    if(pSid != NULL)
    {
        TreeView_SidToItem(hTreeView, hItem, pSid, szUnknownSid);
        Sid_Free(pSid);
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
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);
    PACL pAcl;

    // Retrieve the item where to insert it
    hInsertAfter = TreeView_GetSelection(hTreeView);
    hParent = TreeView_GetParent(hTreeView, hInsertAfter);

    // Shall we deleted the item?
    if(bDeleteSelected)
        hItemToDelete = hInsertAfter;

    // If we shall insert the item BEFORE the current one, move back
    if(bBeforeSelected)
        hInsertAfter = TreeView_GetPreviousItem(hTreeView, hInsertAfter);

    // Create ACE with one entry and set it to the new item
    pAcl = Acl_CreateOneItem(GetDefaultAceType(hTreeView, hParent));
    if(pAcl != NULL)
    {
        // Insert the ACE
        if(GetAce(pAcl, 0, (LPVOID *)(&pAceHeader)))
            hItem = TreeView_InsertAceItem(hTreeView, hParent, hInsertAfter, pAceHeader);

        // Shall we delete the previous item?
        if(hItemToDelete != NULL)
            TreeView_DeleteItem(hTreeView, hItemToDelete);

        // Select the item
        TreeView_Select(hTreeView, hItem, TVGN_CARET);
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
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);

    // Retrieve the item where to insert it
    hItem = TreeView_GetSelection(hTreeView);
    hParent = TreeView_GetParent(hTreeView, hItem);

    // Get the previous or next item to swap with
    hSwapWith = (bWithPrevious) ? TreeView_GetPrevSibling(hTreeView, hItem)
                                : TreeView_GetNextSibling(hTreeView, hItem);
    if(hItem != NULL && hSwapWith != NULL)
    {
        // Retrieve both ACEsPerform the swap operation
        TreeView_ItemToAce(hTreeView, hItem, AceHelper1);
        TreeView_ItemToAce(hTreeView, hSwapWith, AceHelper2);

        // Change both items
        TreeView_AceToItem(hTreeView, hSwapWith, AceHelper1);
        TreeView_AceToItem(hTreeView, hItem, AceHelper2);

        // Select the previous item
        TreeView_Select(hTreeView, hSwapWith, TVGN_CARET);
    }

    return TRUE;
}


static int OnDeleteAce(HWND hDlg)
{
    HTREEITEM hParent;
    HTREEITEM hItem;
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);
    DWORD dwChildCount;

    hItem = TreeView_GetSelection(hTreeView);
    hParent = TreeView_GetParent(hTreeView, hItem);
    if(hParent != NULL && hItem != NULL)
    {
        // Delete the tree item
        if(TreeView_DeleteItem(hTreeView, hItem))
        {
            // Retrieve the child count
            dwChildCount = TreeView_GetChildCount(hTreeView, hParent);
            if(dwChildCount == 0)
            {
                // Insert the ACL as empty
                hItem = InsertTreeItem(hTreeView, hParent, szEmptyAcl, TREE_ITEM_EMPTY_ACL);
                TreeView_Select(hTreeView, hItem, TVGN_CARET);
            }
        }
    }

    return TRUE;
}

static int OnSetBlankSecurityDescriptor(HWND hDlg)
{
    SECURITY_DESCRIPTOR sd;
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);

    // Initialize the tree view with blank security descriptor
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    TreeView_SdToTreeView(hTreeView, &sd);
    return TRUE;
}

static int OnQuerySecurity(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    PSECURITY_DESCRIPTOR pSD = NULL;
    SECURITY_INFORMATION SecInfo;
    NTSTATUS Status = STATUS_SUCCESS;
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);
    BYTE SecDescBuff[0x400];
    DWORD cbSD = 0;

    // Get the mask about which security information we want
    SecInfo = GetWantedSecurityInfo(hDlg);

    // Query the security information
    if(IsHandleValid(pData->hFile))
    {
        pSD = (PSECURITY_DESCRIPTOR)SecDescBuff;
        cbSD = sizeof(SecDescBuff);
        Status = NtQuerySecurityObject(pData->hFile, SecInfo, pSD, cbSD, &cbSD);
        if(Status == STATUS_BUFFER_TOO_SMALL && cbSD != 0)
        {
            pSD = (PSECURITY_DESCRIPTOR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, cbSD);
            Status = NtQuerySecurityObject(pData->hFile, SecInfo, pSD, cbSD, &cbSD);
        }
    }

    // Set the result to the dialog controls
    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_INFO_INT32, Status, cbSD);

    // If succeeded, load our tree view with security information
    if(NT_SUCCESS(Status))
        TreeView_SdToTreeView(hTreeView, pSD);

    // Free buffers and return
    if(pSD != NULL && (PBYTE)pSD != SecDescBuff)
        HeapFree(g_hHeap, 0, pSD);
    return TRUE;
}

static int OnSetSecurity(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    SECURITY_DESCRIPTOR sd;
    SECURITY_INFORMATION AppliedSecInfo = 0;
    SECURITY_INFORMATION WantedSecInfo;
    HTREEITEM hChildItem[5];
    HTREEITEM hAclItem1 = NULL;
    HTREEITEM hAclItem2 = NULL;
    HTREEITEM hItem;
    NTSTATUS Status = STATUS_SUCCESS;
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);
    PSID pOwner = NULL;
    PSID pGroup = NULL;
    PACL pDacl = NULL;
    PACL pSacl = NULL;

    // Get the mask about which security information we want
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    WantedSecInfo = GetWantedSecurityInfo(hDlg);

    // Get handles of all child items
    hChildItem[0] = TreeView_GetChild(hTreeView, TVI_ROOT);
    hChildItem[1] = TreeView_GetNextSibling(hTreeView, hChildItem[0]);
    hChildItem[2] = TreeView_GetNextSibling(hTreeView, hChildItem[1]);
    hChildItem[3] = TreeView_GetNextSibling(hTreeView, hChildItem[2]);
    hChildItem[4] = TreeView_GetNextSibling(hTreeView, hChildItem[3]);

    //
    // Put owner into the security descriptor
    //

    if(WantedSecInfo & OWNER_SECURITY_INFORMATION)
    {
        hItem = TreeView_GetChild(hTreeView, hChildItem[0]);
        if(hItem != NULL)
        {
            if(TreeView_ItemToSid(hTreeView, hItem, &pOwner, false) && pOwner != NULL)
            {
                SetSecurityDescriptorOwner(&sd, pOwner, FALSE);
                AppliedSecInfo |= OWNER_SECURITY_INFORMATION;
            }
        }
    }

    //
    // Put group into the security descriptor
    //

    if(WantedSecInfo & GROUP_SECURITY_INFORMATION)
    {
        hItem = TreeView_GetChild(hTreeView, hChildItem[1]);
        if(hItem != NULL)
        {
            if(TreeView_ItemToSid(hTreeView, hItem, &pGroup, false) && pGroup != NULL)
            {
                SetSecurityDescriptorGroup(&sd, pGroup, FALSE);
                AppliedSecInfo |= GROUP_SECURITY_INFORMATION;
            }
        }
    }

    //
    // Put DACL into the security descriptor
    //

    if(WantedSecInfo & DACL_SECURITY_INFORMATION)
    {
        hItem = TreeView_GetChild(hTreeView, hChildItem[2]);
        if(hItem != NULL)
        {
            if(TreeView_ItemToAcl(hTreeView, hItem, NULL, &pDacl))
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

    if(WantedSecInfo & (SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION))
    {
        // Get handles to wanted tree items
        if(WantedSecInfo & SACL_SECURITY_INFORMATION)
            hAclItem1 = TreeView_GetChild(hTreeView, hChildItem[3]);
        if(WantedSecInfo & LABEL_SECURITY_INFORMATION)
            hAclItem2 = TreeView_GetChild(hTreeView, hChildItem[4]);

        if(TreeView_ItemToAcl(hTreeView, hAclItem1, hAclItem2, &pSacl))
        {
            SetSecurityDescriptorSacl(&sd, TRUE, pSacl, FALSE);
            AppliedSecInfo |= (WantedSecInfo & (SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION));
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
    HWND hTreeView,
    HTREEITEM hItem,
    LPCTSTR szFormat)
{
    TVITEM tvi;
    LPTSTR szValue;
    TCHAR szItemText[0x400];
    HWND hEdit;
    DWORD dwValue32 = 0;
    int nError;

    // Retrieve the item text
    tvi.mask    = TVIF_TEXT;
    tvi.hItem   = hItem;
    tvi.pszText = szItemText;
    tvi.cchTextMax = _countof(szItemText);
    if(!TreeView_GetItem(hTreeView, &tvi))
        return FALSE;

    // Retrieve the value
    szValue = GetItemTextValue(szItemText);
    if(szValue == NULL)
        return FALSE;

    // Convert the value to 32-bit integer
    nError = Text2Hex32(szValue, &dwValue32);
    if(nError != ERROR_SUCCESS)
        return FALSE;

    // Format the item to the edit field
    StringCchPrintf(szItemText, _countof(szItemText), szFormat, dwValue32);

    // Apply the value to the edit field
    hEdit = TreeView_GetEditControl(hTreeView);
    if(hEdit == NULL)
        return FALSE;

    // Apply the value to the edit item
    Edit_LimitText(hEdit, 0x10);
    SetWindowText(hEdit, szItemText);
    return TRUE;
}

static BOOL OnEditGuidItemInPlace(
    HWND /* hDlg */,
    HWND hTreeView,
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
    if(!TreeView_GetItem(hTreeView, &tvi))
        return FALSE;

    // Retrieve the value
    szGuidValue = GetItemTextValue(szItemText);
    if(szGuidValue == NULL)
        return FALSE;

    // Apply the value to the edit field
    hEdit = TreeView_GetEditControl(hTreeView);
    if(hEdit == NULL)
        return FALSE;

    // Apply the value to the edit item
    Edit_LimitText(hEdit, 0x30);
    SetWindowText(hEdit, szGuidValue);
    return TRUE;
}

static BOOL OnEditSidItemInPlace(HWND /* hDlg */, HWND hTreeView, HTREEITEM hItem)
{
    TCHAR szItemText[128];
    HWND hEdit = TreeView_GetEditControl(hTreeView);
    PSID pSid = NULL;

    if(hEdit != NULL)
    {
        if(TreeView_ItemToSid(hTreeView, hItem, &pSid, true))
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

static void OnEditAceTypeModal(HWND hDlg, HWND hTreeView, HTREEITEM hItem)
{
    ACE_HELPER AceHelper;
    LPCSTR szAceTypeString;
    bool bResult = false;

    // Get the current ACE type from the item
    if(TreeView_ItemToAce(hTreeView, hItem, AceHelper))
    {
        DWORD dwAceType = AceHelper.AceType;

        // Run the dialog
        if(FlagsDialog(hDlg, IDS_ACE_TYPE, AceHdrTypes, dwAceType) == IDOK && dwAceType != AceHelper.AceType)
        {
            // Put the ACE type
            if(AceHelper.SetAceType(dwAceType))
            {
                // Create new SID
                AceHelper.SetAllocatedSid(Sid_CreateNew((BYTE)AceHelper.AceType));

                // Set the item text
                szAceTypeString = GetAceTypeString(AceHelper.AceType);
                TreeView_SetTreeItem(hTreeView, hItem, TWideString(szAceTypeString), (TREE_ITEM_ACE | AceHelper.AceType));

                // Fill the sub-item
                bResult = (TreeView_AceToItem(hTreeView, hItem, AceHelper) != NULL);
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
    HWND hTreeView,
    HTREEITEM hItem,                // Item to be edited
    TFlagInfo * pFlags,         // Flags array
    LPCTSTR szFormat,               // Format of the flags to be inserted back
    UINT nIDTitle)                  // Title for the flags dialog
{
    TVITEM tvi;
    LPTSTR szValue;
    TCHAR szItemText[0x400];
    DWORD dwFlags32 = 0;
    int nError;

    // Retrieve the item text
    tvi.mask    = TVIF_TEXT;
    tvi.hItem   = hItem;
    tvi.pszText = szItemText;
    tvi.cchTextMax = _countof(szItemText);
    if(!TreeView_GetItem(hTreeView, &tvi))
        return;

    // Retrieve the value
    szValue = GetItemTextValue(szItemText);
    if(szValue == NULL)
        return;

    // Convert the value to 32-bit integer
    nError = Text2Hex32(szValue, &dwFlags32);
    if(nError != ERROR_SUCCESS)
        return;

    // Either invoke the values dialog or the flags dialog
    if(FlagsDialog(hDlg, nIDTitle, pFlags, dwFlags32) == IDOK)
    {
        NamedValueToString(pFlags, szItemText, _countof(szItemText), szFormat, dwFlags32);
        TreeView_SetItem(hTreeView, &tvi);
    }
}

static int OnBeginLabelEdit(HWND hDlg, LPNMTVDISPINFO pTVDispInfo)
{
    HWND hTreeView = pTVDispInfo->hdr.hwndFrom;
    BOOL bStartEditing = FALSE;

    // Verify if the selected tree item is editable
    switch(pTVDispInfo->item.lParam)
    {
        case TREE_ITEM_ACE_HEADER_FLAGS:
            bStartEditing = OnEditNumericItemInPlace(hDlg, hTreeView, pTVDispInfo->item.hItem, _T("%02lX"));
            break;

        case TREE_ITEM_ACE_MASK:
        case TREE_ITEM_ADS_ACE_MASK:
        case TREE_ITEM_MANDATORY_MASK:
            bStartEditing = OnEditNumericItemInPlace(hDlg, hTreeView, pTVDispInfo->item.hItem, _T("%08lX"));
            break;

        case TREE_ITEM_MANDATORY_LABEL:
            bStartEditing = OnEditNumericItemInPlace(hDlg, hTreeView, pTVDispInfo->item.hItem, _T("%08lX"));
            break;

        case TREE_ITEM_ACE_OBJ_GUID:
        case TREE_ITEM_ACE_OBJ_GUID2:
            bStartEditing = OnEditGuidItemInPlace(hDlg, hTreeView, pTVDispInfo->item.hItem);
            break;

        case TREE_ITEM_SID:
        case TREE_ITEM_NO_SID:
            bStartEditing = OnEditSidItemInPlace(hDlg, hTreeView, pTVDispInfo->item.hItem);
            break;

        default:
            SetResultInfo(hDlg, RSI_NTSTATUS, STATUS_CANNOT_EDIT_THIS);
            break;
    }

    // If we start editing something, make sure that Esc key will not
    // cancel the entire FileTest
    DisableCloseDialog(hDlg, bStartEditing);

    // Store the result info the dialog's private variables
    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, bStartEditing ? FALSE : TRUE);
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
                bAcceptChanges = DeferSetItemNumericValue(hDlg, pTVDispInfo, MandatoryMasks, szAceMaskFmt);
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

            case TREE_ITEM_SID:
            case TREE_ITEM_NO_SID:
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

static int OnTVContextMenu(HWND hDlg, LPARAM lParam)
{
    HTREEITEM hItem;
    POINT pt;
    LPARAM ItemParam;
    HMENU hMainMenu = NULL;
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);
    RECT rect;

    // Get the selected item
    hItem = TreeView_GetSelection(hTreeView);
    if(hItem != NULL)
    {
        // Get the LPARAM of the tree item.
        ItemParam = TreeView_GetItemParam(hTreeView, hItem);

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
            UpdateContextMenu(hTreeView, hItem, hMainMenu);

            // If we don't have the coords, make them from the tree item
            if(lParam == 0xFFFFFFFF)
            {
                TreeView_GetItemRect(hTreeView, hItem, &rect, TRUE);
                pt.x = rect.left;
                pt.y = rect.bottom;
                ClientToScreen(hTreeView, &pt);
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
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);

    // Select the right-clicked tree view item
    GetCursorPos(&pt);
    ScreenToClient(hTreeView, &pt);
    hti.pt = pt;
    hti.flags = TVHT_ONITEMLABEL;
    hItem = TreeView_HitTest(hTreeView, &hti);

    // If there is an item clicked, select it
    if(hItem != NULL)
        TreeView_Select(hTreeView, hItem, TVGN_CARET);

    return FALSE;
}

static int OnTVDoubleClick(HWND hDlg)
{
    HTREEITEM hSelItem;
    LPARAM lParam;
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);
    bool bGoToParent = true;

    // Get the lParam of the clicked item
    hSelItem = TreeView_GetSelection(hTreeView);
    lParam = TreeView_GetItemParam(hTreeView, hSelItem);

    // The ACE type item is the same like the ACE type subitem
    if(IsTreeItemAce(lParam))
    {
        lParam = TREE_ITEM_ACE_HEADER_TYPE;
        bGoToParent = false;
    }

    // Edit the item
    switch(lParam)
    {
        case TREE_ITEM_NO_SID:
            OnCreateNewSid(hDlg, hTreeView, hSelItem);
            break;

        case TREE_ITEM_NULL_ACL:    // Insert a new ACE to the tree
        case TREE_ITEM_EMPTY_ACL:
            OnInsertAceBefore(hDlg, TRUE, TRUE);
            break;

        case TREE_ITEM_ACE_HEADER_TYPE:
            if(bGoToParent)
                hSelItem = TreeView_GetParent(hTreeView, hSelItem);
            OnEditAceTypeModal(hDlg, hTreeView, hSelItem);
            break;

        case TREE_ITEM_ACE_HEADER_FLAGS:
            OnEditNumericItemModal(hDlg, hTreeView, hSelItem, AceHdrFlags, szAceHdrFlagsFmt, IDS_ACE_FLAGS);
            break;

        case TREE_ITEM_ACE_MASK:
            OnEditNumericItemModal(hDlg, hTreeView, hSelItem, AceMasks, szAceMaskFmt, IDS_ACE_MASK);
            break;

        case TREE_ITEM_ADS_ACE_MASK:
            OnEditNumericItemModal(hDlg, hTreeView, hSelItem, AdsAceMasks, szAceMaskFmt, IDS_ADS_ACE_MASK);
            break;

        case TREE_ITEM_MANDATORY_MASK:
            OnEditNumericItemModal(hDlg, hTreeView, hSelItem, MandatoryMasks, szAceMaskFmt, IDS_MANDATORY_MASK);
            break;

        case TREE_ITEM_ACE_OBJ_GUID:
        case TREE_ITEM_ACE_OBJ_GUID2:
            ObjectGuidHelpDialog(hDlg);
            break;

        case TREE_ITEM_MANDATORY_LABEL:
            OnEditNumericItemModal(hDlg, hTreeView, hSelItem, IntegrityLevels, szIntLevelFmt, IDS_INTEGRITY_LEVEL);
            break;
    }

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

