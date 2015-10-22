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

#define TREE_ITEM_OWNER           OWNER_SECURITY_INFORMATION
#define TREE_ITEM_GROUP           GROUP_SECURITY_INFORMATION
#define TREE_ITEM_DACL            DACL_SECURITY_INFORMATION
#define TREE_ITEM_SACL            SACL_SECURITY_INFORMATION
#define TREE_ITEM_LABEL           LABEL_SECURITY_INFORMATION
#define TREE_ITEM_NO_SID          0x10000000        // Under OWNER/GROUP, No SID present
#define TREE_ITEM_SID             0x10000001        // Under OWNER/GROUP: Present SID
#define TREE_ITEM_SID_MAND_LABEL  0x10000002        // SID for integrity level (SECURITY_MANDATORY_LABEL_AUTHORITY)
#define TREE_ITEM_NEW_ACE         0x10000003        // Under DACL/SACL/LABEL: No ACEs ("click to create new")
#define TREE_ITEM_ACE             0x20000000        // An ACE. Lower 8 bits indicate the ACE type
#define TREE_ITEM_ACE_TYPE        0x30000005        // ACE_HEADER::AceType
#define TREE_ITEM_ACE_FLAGS       0x30000006        // ACE_HEADER::AceFlags
#define TREE_ITEM_ACE_SIZE        0x30000007        // ACE_HEADER::AceFlags
#define TREE_ITEM_ACE_MASK        0x30000008        // ACE::Mask
#define TREE_ITEM_MANDATORY_MASK  0x30000009        // ACE::Mask for SYSTEM_MANDATORY_LABEL_ACE
#define TREE_ITEM_TYPE_MASK       0xF0000000

#define WM_EXPAND_ITEM           (WM_USER + 0x1000) // wParam = hItem, lParam = expand code
#define WM_ACE_FLAGS_TO_ITEM     (WM_USER + 0x1001) // wParam = hItem, lParam = new ACE flags
#define WM_ACE_MASK_TO_ITEM      (WM_USER + 0x1002) // wParam = hItem, lParam = new ACE mask
#define WM_MAND_MASK_TO_ITEM     (WM_USER + 0x1003) // wParam = hItem, lParam = new ACE mask
#define WM_SID_TO_ITEM           (WM_USER + 0x1004) // wParam = hItem, lParam = pSid (needs to be freed by HeapFree)

// Masks for each tre item
static LPCTSTR szAceTypeFmt   = _T("AceType: 0x%02lX");
static LPCTSTR szAceFlagsFmt  = _T("AceFlags: 0x%02lX  ");
static LPCTSTR szAceSizeFmt   = _T("AceSize: 0x%04lX");
static LPCTSTR szAceMaskFmt   = _T("Mask: 0x%08lX  ");
static LPCTSTR szIntLevelFmt  = _T("IntLevel: 0x%08lX");

static TFlagInfo AceTypes[] =
{
    FLAG_INFO_ENTRY(ACCESS_ALLOWED_ACE_TYPE),
    FLAG_INFO_ENTRY(ACCESS_DENIED_ACE_TYPE),
    FLAG_INFO_ENTRY(SYSTEM_AUDIT_ACE_TYPE),
    FLAG_INFO_ENTRY(SYSTEM_ALARM_ACE_TYPE),
    FLAG_INFO_ENTRY(ACCESS_ALLOWED_COMPOUND_ACE_TYPE),
    FLAG_INFO_ENTRY(ACCESS_ALLOWED_OBJECT_ACE_TYPE),
    FLAG_INFO_ENTRY(ACCESS_DENIED_OBJECT_ACE_TYPE),
    FLAG_INFO_ENTRY(SYSTEM_AUDIT_OBJECT_ACE_TYPE),
    FLAG_INFO_ENTRY(SYSTEM_ALARM_OBJECT_ACE_TYPE),
    FLAG_INFO_ENTRY(ACCESS_ALLOWED_CALLBACK_ACE_TYPE),
    FLAG_INFO_ENTRY(ACCESS_DENIED_CALLBACK_ACE_TYPE),
    FLAG_INFO_ENTRY(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE),
    FLAG_INFO_ENTRY(ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE),
    FLAG_INFO_ENTRY(SYSTEM_AUDIT_CALLBACK_ACE_TYPE),
    FLAG_INFO_ENTRY(SYSTEM_ALARM_CALLBACK_ACE_TYPE),
    FLAG_INFO_ENTRY(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE),
    FLAG_INFO_ENTRY(SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE),
    FLAG_INFO_ENTRY(SYSTEM_MANDATORY_LABEL_ACE_TYPE),
    FLAG_INFO_END
};  

static TFlagInfo AceFlags[] =
{
    FLAG_INFO_ENTRY(OBJECT_INHERIT_ACE),
    FLAG_INFO_ENTRY(CONTAINER_INHERIT_ACE),
    FLAG_INFO_ENTRY(NO_PROPAGATE_INHERIT_ACE),
    FLAG_INFO_ENTRY(INHERIT_ONLY_ACE),
    FLAG_INFO_ENTRY(INHERITED_ACE),
    FLAG_INFO_ENTRY(SUCCESSFUL_ACCESS_ACE_FLAG),
    FLAG_INFO_ENTRY(FAILED_ACCESS_ACE_FLAG),
    FLAG_INFO_END
};

static TFlagInfo AceMasks[] =
{
    FLAG_INFO_ENTRY(FILE_READ_DATA),       
    FLAG_INFO_ENTRY(FILE_WRITE_DATA),      
    FLAG_INFO_ENTRY(FILE_APPEND_DATA),     
    FLAG_INFO_ENTRY(FILE_READ_EA),         
    FLAG_INFO_ENTRY(FILE_WRITE_EA),        
    FLAG_INFO_ENTRY(FILE_EXECUTE),         
    FLAG_INFO_ENTRY(FILE_DELETE_CHILD),    
    FLAG_INFO_ENTRY(FILE_READ_ATTRIBUTES), 
    FLAG_INFO_ENTRY(FILE_WRITE_ATTRIBUTES),
    FLAG_INFO_ENTRY(DELETE),                
    FLAG_INFO_ENTRY(READ_CONTROL),          
    FLAG_INFO_ENTRY(WRITE_DAC),             
    FLAG_INFO_ENTRY(WRITE_OWNER),           
    FLAG_INFO_ENTRY(SYNCHRONIZE),           
    FLAG_INFO_ENTRY(GENERIC_WRITE),         
    FLAG_INFO_ENTRY(GENERIC_READ),          
    FLAG_INFO_ENTRY(GENERIC_WRITE),         
    FLAG_INFO_ENTRY(GENERIC_EXECUTE),       
    FLAG_INFO_ENTRY(GENERIC_ALL),           
    FLAG_INFO_END
};

static TFlagInfo MandatoryMasks[] =
{
    FLAG_INFO_ENTRY(SYSTEM_MANDATORY_LABEL_NO_WRITE_UP),       
    FLAG_INFO_ENTRY(SYSTEM_MANDATORY_LABEL_NO_READ_UP),      
    FLAG_INFO_ENTRY(SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP),     
    FLAG_INFO_END
};

static DWORD AceSizes[] =
{
    sizeof(ACCESS_ALLOWED_ACE),                   // ACCESS_ALLOWED_ACE_TYPE          
    sizeof(ACCESS_DENIED_ACE),                    // ACCESS_DENIED_ACE_TYPE           
    sizeof(SYSTEM_AUDIT_ACE),                     // SYSTEM_AUDIT_ACE_TYPE            
    sizeof(SYSTEM_ALARM_ACE),                     // SYSTEM_ALARM_ACE_TYPE            
    0,                                            // ACCESS_ALLOWED_COMPOUND_ACE_TYPE (?)
    sizeof(ACCESS_ALLOWED_OBJECT_ACE),            // ACCESS_ALLOWED_OBJECT_ACE_TYPE   
    sizeof(ACCESS_DENIED_OBJECT_ACE),             // ACCESS_DENIED_OBJECT_ACE_TYPE    
    sizeof(SYSTEM_AUDIT_OBJECT_ACE),              // SYSTEM_AUDIT_OBJECT_ACE_TYPE     
    sizeof(SYSTEM_ALARM_OBJECT_ACE),              // SYSTEM_ALARM_OBJECT_ACE_TYPE     
    sizeof(ACCESS_ALLOWED_CALLBACK_ACE),          // ACCESS_ALLOWED_CALLBACK_ACE_TYPE 
    sizeof(ACCESS_DENIED_CALLBACK_ACE),           // ACCESS_DENIED_CALLBACK_ACE_TYPE  
    sizeof(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE),   // ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
    sizeof(ACCESS_DENIED_CALLBACK_OBJECT_ACE),    // ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
    sizeof(SYSTEM_AUDIT_CALLBACK_ACE),            // SYSTEM_AUDIT_CALLBACK_ACE_TYPE   
    sizeof(SYSTEM_ALARM_CALLBACK_ACE),            // SYSTEM_ALARM_CALLBACK_ACE_TYPE       
    sizeof(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE),     // SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
    sizeof(SYSTEM_ALARM_CALLBACK_OBJECT_ACE),     // SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
    sizeof(SYSTEM_MANDATORY_LABEL_ACE),           // SYSTEM_MANDATORY_LABEL_ACE_TYPE      
};

//-----------------------------------------------------------------------------
// Local functions

static bool CheckForServiceAccount(LPTSTR szUserName)
{
    TCHAR szSaveUserName[MAX_PATH];
    TCHAR szKeyName[MAX_PATH];
    HKEY hSubKey;

    // Save the user name
    _tcscpy(szSaveUserName, szUserName);

    // If the name resembles a service, give it the NT_SERVICE prefix. This only applies in Vista or newer
    if(g_dwWinVer >= 0x0600 && _tcschr(szUserName, _T('\\')) == NULL)
    {
        _stprintf(szKeyName, _T("SYSTEM\\CurrentControlSet\\Services\\%s"), szUserName);
        if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKeyName, 0, KEY_QUERY_VALUE, &hSubKey) == ERROR_SUCCESS)
        {
            _stprintf(szUserName, _T("NT SERVICE\\%s"), szSaveUserName);
            RegCloseKey(hSubKey);
            return true;
        }
    }

    return false;
}

static PSID CreateCopyOfSid(PSID pSidToFree)
{
    PSID pNewSid = NULL;

    // If the new SID is valid, create its copy on the heap
    if(pSidToFree != NULL)
    {
        DWORD dwSidLength = GetLengthSid(pSidToFree);

        // Allocate the new SID
        pNewSid = (PSID)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwSidLength);
        if(pNewSid != NULL)
            CopySid(dwSidLength, pNewSid, pSidToFree);

        // Free the old SID and return the new one
        FreeSid(pSidToFree);
    }
    return pNewSid;
}

// Creates a new SID of "Everyone" user
// Caller must free the returned SID using HeapFree
static PSID CreateNewSid(BYTE AceType)
{
    SID_IDENTIFIER_AUTHORITY SiaLabel = SECURITY_MANDATORY_LABEL_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SiaWorld = SECURITY_WORLD_SID_AUTHORITY;
    PSID pSidToFree = NULL;

    // We only create two types of SID - "Everyone" and "Mandatory Medium"
    if(AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
    {
        AllocateAndInitializeSid(&SiaLabel, 1, SECURITY_MANDATORY_MEDIUM_RID,
                                               0,
                                               0,
                                               0,
                                               0,
                                               0,
                                               0,
                                               0,
                                              &pSidToFree);
    }
    else
    {
        AllocateAndInitializeSid(&SiaWorld, 1, SECURITY_WORLD_RID,
                                               0,
                                               0,
                                               0,
                                               0,
                                               0,
                                               0,
                                               0,
                                              &pSidToFree);
    }

    // Reallocate the SID so that it is on the heap
    return CreateCopyOfSid(pSidToFree);
}

static BOOL IsTreeItemAce(LPARAM lParam)
{
    return ((lParam & TREE_ITEM_TYPE_MASK) == TREE_ITEM_ACE) ? TRUE : FALSE;
}

static BOOL IsTreeItemAcl(HWND hTreeView, HTREEITEM hItem)
{
    TVITEM tvi;

    // Only perform test on valid items
    if(hItem != NULL)
    {
        // Get the lparam from the tree item
        tvi.mask = TVIF_PARAM;
        tvi.hItem = TreeView_GetChild(hTreeView, hItem);
        TreeView_GetItem(hTreeView, &tvi);

        // Is it a valid ACE ?
        if(IsTreeItemAce(tvi.lParam))
            return TRUE;

        // Is it an empty ACL ?
        if(tvi.lParam == TREE_ITEM_NEW_ACE)
            return TRUE;
    }

    return FALSE;
}

static BOOL WINAPI MyAddMandatoryAce(
    PACL pAcl,
    DWORD dwAceRevision,
    DWORD dwAceFlags,
    DWORD MandatoryPolicy,
    PSID pLabelSid)
{
    PACCESS_ALLOWED_ACE pAce = NULL;
    DWORD SidLength;
    DWORD AceSize;

    // Check if the SID is valid
    if(!IsValidSid(pLabelSid))
    {
        SetLastError(ERROR_INVALID_SID);
        return FALSE;
    }
    
    // Find first free ACE
    if(!FindFirstFreeAce(pAcl, (LPVOID *)&pAce))
    {
        SetLastError(ERROR_INVALID_ACL);
        return FALSE;
    }

    // Check if there is enough space in the ACL
    SidLength = GetLengthSid(pLabelSid);
    AceSize = sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) + SidLength;
    if(pAce == NULL || ((PUCHAR)pAce + AceSize) > ((PUCHAR)pAcl + pAcl->AclSize))
    {
        SetLastError(ERROR_ALLOTTED_SPACE_EXCEEDED);
        return FALSE;
    }

    // Fill the ACE
    pAce->Header.AceType  = SYSTEM_MANDATORY_LABEL_ACE_TYPE;
    pAce->Header.AceFlags = (BYTE)dwAceFlags;
    pAce->Header.AceSize  = (WORD)AceSize;
    pAce->Mask = MandatoryPolicy;
    CopySid(SidLength, (PSID)(&pAce->SidStart), pLabelSid);

    // Increment the ACE count in ACL
    pAcl->AceCount += 1;

    // Adjust revision, if necessary
    pAcl->AclRevision = (BYTE)dwAceRevision;

    return TRUE;
}

// Creates a new ACL with one ACE, granting full access to Everyone 
// Caller must free the returned buffer using HeapFree
PACL CreateNewAcl(BYTE AceType)
{
    DWORD dwSidLength = 0;
    DWORD dwAclLength = 0;
    PSID pSid = NULL;
    PACL pAcl = NULL;

    // Check whether the ACE type is valid at all
    if(AceType < _countof(AceSizes) && AceSizes[AceType] != 0)
    {
        // Create SID for "Everyone"
        pSid = CreateNewSid(AceType);
        if(pSid != NULL)
        {
            // Calculate the size of the new ACE and initialize it
            dwSidLength = GetLengthSid(pSid);
            dwAclLength = sizeof(ACL) + AceSizes[AceType] - sizeof(DWORD) + dwSidLength;
            
            // Create a new ACL
            pAcl = (PACL)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwAclLength);
            if(pAcl != NULL)
            {
                if(InitializeAcl(pAcl, dwAclLength, ACL_REVISION))
                {
                    switch(AceType)
                    {
                        case ACCESS_ALLOWED_ACE_TYPE:
                            AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, pSid);
                            break;

                        case ACCESS_DENIED_ACE_TYPE:
                            AddAccessDeniedAce(pAcl, ACL_REVISION, GENERIC_ALL, pSid);
                            break;

                        case SYSTEM_AUDIT_ACE_TYPE:
                            AddAuditAccessAce(pAcl, ACL_REVISION, GENERIC_ALL, pSid, TRUE, TRUE);
                            break;

                        case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
                            MyAddMandatoryAce(pAcl, ACL_REVISION, 0, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, pSid);
                            break;

                        default:    // Not supported
                            HeapFree(g_hHeap, 0, pAcl);
                            pAcl = NULL;
                            break;
                    }
                }
                else
                {
                    // Free the ACL if we failed to initialize it
                    HeapFree(g_hHeap, 0, pAcl);
                    pAcl = NULL;
                }
            }

            // Free the allocated SID
            HeapFree(g_hHeap, 0, pSid);
            pSid = NULL;
        }
    }

    return pAcl;
}

static LPTSTR FormatBitFlags(
    TFlagInfo * pFlags,
    LPCTSTR szMask,
    LPTSTR szBuffer,
    LPTSTR szEndChar,
    DWORD dwFlags)
{
    int nFlagsAppended = 0;             // Number of already-appended flags

    // If the flags are zero, append zero only
    if(dwFlags == 0 && szMask == NULL)
    {
        if(szEndChar > szBuffer)
            *szBuffer++ = _T('0');
        *szBuffer = 0;
        return szBuffer;
    }

    // Append the byte value
    if(szMask != NULL)
    {
        szBuffer += _stprintf(szBuffer, szMask, dwFlags);
    }

    // If the caller requires full output, give the flag values as named values
    for(; pFlags->szFlagText != NULL; pFlags++)
    {
        if(IS_FLAG_SET(pFlags, dwFlags))
        {
            LPCTSTR szFlagName = pFlags->szFlagText;

            // If there are flags already, append the OR sign first
            if(szBuffer < szEndChar)
            {
                if(nFlagsAppended > 0)
                {
                    *szBuffer++ = _T(' ');
                    *szBuffer++ = _T('|');
                    *szBuffer++ = _T(' ');
                }

                // Append the flag value now
                while(szBuffer < szEndChar && *szFlagName != 0)
                    *szBuffer++ = *szFlagName++;
            }

            // Clear this flag from the values
            dwFlags &= ~pFlags->dwValue;
            nFlagsAppended++;
        }
    }

    // If there are some flags remaining, insert them as hexa value
    if(dwFlags != 0 && (szEndChar - szBuffer) >= 8)
    {
        if(nFlagsAppended > 0)
            *szBuffer++ = _T('|');
        szBuffer += _stprintf(szBuffer, _T("%08lX"), dwFlags);
    }

    // Terminate the string and exit
    *szBuffer = 0;
    return szBuffer;
}

static void SidToString(PSID pvSid, LPTSTR szString, bool bAddUserName)
{
    PSID_IDENTIFIER_AUTHORITY pSia;
    SID * pSid = (SID *)pvSid;
    UCHAR SubAuthCount;

    // Add the "S-" begin
    *szString++ = _T('S');
    *szString++ = _T('-');

    // Add the revision
    szString += _stprintf(szString, _T("%u-"), pSid->Revision);

    // Add the last value of the authority
    // TODO: Is this correct ?
    pSia = GetSidIdentifierAuthority(pSid);
    szString += _stprintf(szString, _T("%u"), pSia->Value[5]);

    // Add the subauthorities
    SubAuthCount = *GetSidSubAuthorityCount(pSid);
    for(DWORD i = 0; i < SubAuthCount; i++)
    {
        DWORD dwSubAuth = *GetSidSubAuthority(pSid, i);

        szString += swprintf(szString, L"-%u", dwSubAuth);
    }

    // If we are required to add user name, do it.
    if(bAddUserName)                                  
    {
        SID_NAME_USE SidNameUse;
        TCHAR szDomainName[128] = _T("");
        TCHAR szUserName[128] = _T("");
        DWORD cchDomainName = _maxchars(szDomainName);
        DWORD cchUserName = _maxchars(szUserName);

        if(LookupAccountSid(NULL, pSid, szUserName, &cchUserName, szDomainName, &cchDomainName, &SidNameUse))
        {
            if(szDomainName[0] != 0)
                _stprintf(szString, _T(" (%s\\%s)"), szDomainName, szUserName);
            else
                _stprintf(szString, _T(" (%s)"), szUserName);
        }
        else
        {
            _tcscpy(szString, _T(" (Unknown SID)"));
        }
    }
}

static BOOL StringToSid(LPTSTR szSid, PSID * ppSid)
{
    SID_IDENTIFIER_AUTHORITY Sia = SECURITY_NULL_SID_AUTHORITY;
    SID_NAME_USE SidNameUse;
    PSID  pSidToFree = NULL;
    PSID  pNewSid = NULL;
    TCHAR szDomainName[128] = _T("");
    DWORD dwSubAuthCount = 0;
    DWORD dwSubAuth[8];
    DWORD dwDomainName = _maxchars(szDomainName);
    DWORD dwRevision = SID_REVISION;
    DWORD dwLength = 0;
    BOOL bResult;

    // Verify the string sid value
    if(szSid == NULL || szSid[0] == 0)
        return FALSE;

    // Case 1: Sid is entered as text form ("S-1-....")
    if(szSid[0] == _T('S') && szSid[1] == _T('-'))
    {
        // Skip the begin of the SID
        szSid += 2;

        // Get revision
        if(szSid[0] == _T('1') && szSid[1] == _T('-'))
        {
            // Skip revision
            dwRevision = SID_REVISION;
            szSid += 2;

            // Get the identifier authority
            if(isdigit(szSid[0]) && szSid[1] == _T('-'))
            {
                Sia.Value[5] = (BYTE)StrToInt(szSid, &szSid, 10);
                szSid++;

                // Get the subauthorities
                memset(dwSubAuth, 0, sizeof(dwSubAuth));
                while(isdigit(szSid[0]) && dwSubAuthCount < 8)
                {
                    dwSubAuth[dwSubAuthCount++] = StrToInt(szSid, &szSid, 10);
                    if(szSid[0] == _T('-'))
                        szSid++;
                }

                // If an unknown character found, do nothing
                if(szSid[0] == 0 || szSid[0] == _T(' '))
                {
                    // Create the SID
                    if(AllocateAndInitializeSid(&Sia, (BYTE)dwSubAuthCount,
                                                            dwSubAuth[0],
                                                            dwSubAuth[1],
                                                            dwSubAuth[2], 
                                                            dwSubAuth[3], 
                                                            dwSubAuth[4], 
                                                            dwSubAuth[5], 
                                                            dwSubAuth[6], 
                                                            dwSubAuth[7],
                                                           &pSidToFree))
                    {
                        *ppSid = CreateCopyOfSid(pSidToFree);
                        return TRUE;
                    }
                }
            }
        }

        return FALSE;
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
        pNewSid = (PSID)HeapAlloc(g_hHeap, 0, dwLength);
        bResult = LookupAccountName(NULL, szSid, pNewSid, &dwLength, szDomainName, &dwDomainName, &SidNameUse);
    }

    // If succeeded, give the SID
    if(bResult)
        *ppSid = pNewSid;
    return bResult;
}

static DWORD SidToIntegrityLevel(PSID pSid)
{
    SID_IDENTIFIER_AUTHORITY Sia = SECURITY_MANDATORY_LABEL_AUTHORITY;
    DWORD dwSubAuthCount;
    
    // Retrieve integrity level from SID
    if(!memcmp(GetSidIdentifierAuthority(pSid), &Sia, sizeof(SID_IDENTIFIER_AUTHORITY)))
    {
        dwSubAuthCount = *GetSidSubAuthorityCount(pSid);
        if(dwSubAuthCount > 0)
        {
            return *GetSidSubAuthority(pSid, dwSubAuthCount - 1);
        }
    }

    // Set default integrity level
    return SECURITY_MANDATORY_MEDIUM_RID;
}

static BOOL IntegrityLevelToSid(DWORD dwIntLevel, PSID * ppSid)
{
    SID_IDENTIFIER_AUTHORITY Sia = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID pSidToFree = NULL;
    PSID pNewSid = NULL;

    if(AllocateAndInitializeSid(&Sia, 1, dwIntLevel, 0, 0, 0, 0, 0, 0, 0, &pSidToFree))
        pNewSid = CreateCopyOfSid(pSidToFree);

    *ppSid = pNewSid;
    return (pNewSid != NULL) ? TRUE : FALSE;
}

static BOOL ItemTextToNumber(LPCTSTR szText, DWORD & dwValue)
{
    // Find the "0x" value
    while(*szText != 0)
    {
        if(szText[0] == _T('0') && szText[1] == _T('x'))
            break;
        szText++;
    }

    // If it's a recognized hexa number, convert it
    if(szText[0] == _T('0') && szText[1] == _T('x'))
    {
        dwValue = StrToInt(szText + 2, NULL, 16);
        return TRUE;
    }

    return FALSE;
}

static void ValueToTreeItem(
    HWND hTreeView,
    HTREEITEM hItem,
    TFlagInfo * pFlags,
    LPCTSTR szFlagsFmt,
    LPARAM lParam,
    DWORD dwValue)
{
    TVITEM tvi;
    LPTSTR szEndChar;
    TCHAR szItemText[256];

    // Format the item text
    szEndChar = szItemText + _maxchars(szItemText) - 1;
    FormatBitFlags(pFlags, szFlagsFmt, szItemText, szEndChar, dwValue);

    // Set the text and item param
    tvi.mask = TVIF_TEXT | TVIF_PARAM;
    tvi.hItem = hItem;
    tvi.lParam = lParam;
    tvi.pszText = szItemText;
    TreeView_SetItem(hTreeView, &tvi);
}

static BOOL TreeItemToValue(HWND hTreeView, HTREEITEM hItem, LPARAM lParam, DWORD & dwValue)
{
    TVITEM tvi;
    TCHAR szItemText[256];

    // Get the text from the 
    tvi.mask = TVIF_TEXT | TVIF_PARAM;
    tvi.hItem = hItem;
    tvi.pszText = szItemText;
    tvi.cchTextMax = _maxchars(szItemText);
    TreeView_GetItem(hTreeView, &tvi);

    // Verify the proper type
    if(tvi.lParam != lParam)
        return FALSE;

    return ItemTextToNumber(szItemText, dwValue);
}

static void TextToTreeItem(
    HWND hTreeView,
    HTREEITEM hItem,
    LPARAM lParam,
    LPCTSTR szItemText)
{
    TVITEM tvi;

    // Set the text and item param
    tvi.mask = TVIF_TEXT | TVIF_PARAM;
    tvi.hItem = hItem;
    tvi.lParam = lParam;
    tvi.pszText = (LPTSTR)szItemText;
    TreeView_SetItem(hTreeView, &tvi);
}

static void AceFlagsToTreeItem(HWND hTreeView, HTREEITEM hItem, DWORD dwAceFlags)
{
    return ValueToTreeItem(hTreeView, hItem, AceFlags, szAceFlagsFmt, TREE_ITEM_ACE_FLAGS, dwAceFlags);
}                               

static BOOL TreeItemToAceFlags(HWND hTreeView, HTREEITEM hItem, DWORD & dwAceFlags)
{
    return TreeItemToValue(hTreeView, hItem, TREE_ITEM_ACE_FLAGS, dwAceFlags);
}

static void AceMaskToTreeItem(HWND hTreeView, HTREEITEM hItem, DWORD dwAceMask)
{
    return ValueToTreeItem(hTreeView, hItem, AceMasks, szAceMaskFmt, TREE_ITEM_ACE_MASK, dwAceMask);
}                               

static BOOL TreeItemToAceMask(HWND hTreeView, HTREEITEM hItem, DWORD & dwAceMask)
{
    return TreeItemToValue(hTreeView, hItem, TREE_ITEM_ACE_MASK, dwAceMask);
}

static void MandatoryMaskToTreeItem(HWND hTreeView, HTREEITEM hItem, DWORD dwAceMask)
{
    return ValueToTreeItem(hTreeView, hItem, MandatoryMasks, szAceMaskFmt, TREE_ITEM_MANDATORY_MASK, dwAceMask);
}                               

static BOOL TreeItemToMandatoryMask(HWND hTreeView, HTREEITEM hItem, DWORD & dwAceMask)
{
    return TreeItemToValue(hTreeView, hItem, TREE_ITEM_MANDATORY_MASK, dwAceMask);
}

static void SidToTreeItem(HWND hTreeView, HTREEITEM hItem, PSID pSid)
{
    TVITEM tvi;
    TCHAR szItemText[256];

    // Convert the SID to text
    SidToString(pSid, szItemText, true);

    // Put the SID text to the tree view item
    tvi.mask = TVIF_TEXT | TVIF_PARAM;
    tvi.hItem = hItem;
    tvi.lParam = TREE_ITEM_SID;
    tvi.pszText = szItemText;
    TreeView_SetItem(hTreeView, &tvi);
}

static BOOL TreeItemToSid(HWND hTreeView, HTREEITEM hItem, PSID * ppSid, BOOL bCreateNewSidAllowed)
{
    TVITEM tvi;
    TCHAR szItemText[256];

    // Get the text from the treeview item
    tvi.mask = TVIF_TEXT | TVIF_PARAM;
    tvi.hItem = hItem;
    tvi.pszText = szItemText;
    tvi.cchTextMax = _maxchars(szItemText);
    TreeView_GetItem(hTreeView, &tvi);

    // If there is "not present", we just create new SID for "Everyone"
    if(tvi.lParam == TREE_ITEM_NO_SID && bCreateNewSidAllowed)
    {
        *ppSid = CreateNewSid(ACCESS_ALLOWED_ACE_TYPE);
        return TRUE;
    }

    // Convert the tree item to SID
    return StringToSid(szItemText, ppSid);
}

static void MandLabelSidToTreeItem(HWND hTreeView, HTREEITEM hItem, PSID pSid)
{
    TVITEM tvi;
    TCHAR szItemText[256];
    DWORD dwIntLevel = SidToIntegrityLevel(pSid);

    // Convert the integrity level to number
    _stprintf(szItemText, szIntLevelFmt, dwIntLevel);

    // Put the SID text to the tree view item
    tvi.mask = TVIF_TEXT | TVIF_PARAM;
    tvi.hItem = hItem;
    tvi.lParam = TREE_ITEM_SID_MAND_LABEL;
    tvi.pszText = szItemText;
    TreeView_SetItem(hTreeView, &tvi);
}

static BOOL TreeItemToMandLabelSid(HWND hTreeView, HTREEITEM hItem, PSID * ppSid)
{
    DWORD dwIntLevel;

    // Convert the item text value to number
    if(!TreeItemToValue(hTreeView, hItem, TREE_ITEM_SID_MAND_LABEL, dwIntLevel))
        return FALSE;

    return IntegrityLevelToSid(dwIntLevel, ppSid);
}

static void AceToTreeItem(
    HWND hTreeView,
    HTREEITEM hAceItem,
    PACCESS_ALLOWED_ACE pAce)
{
    HTREEITEM hItem;
    LPCTSTR szAceType;
    TCHAR szItemText[256];
    PSID pSid;
    BYTE MaxAceType = (BYTE)(sizeof(AceTypes) / sizeof(TFlagInfo)) - 1;

    // Remove all children, if any
    while((hItem = TreeView_GetChild(hTreeView, hAceItem)) != NULL)
        TreeView_DeleteItem(hTreeView, hItem);

    // Insert the "root" item with ACE type
    szAceType = _T("UNKNOWN_ACE");
    if(pAce->Header.AceType < MaxAceType)
        szAceType = AceTypes[pAce->Header.AceType].szFlagText;
    TextToTreeItem(hTreeView, hAceItem, (TREE_ITEM_ACE | pAce->Header.AceType), szAceType);

    // Insert the subitem with ACE type
    hItem = InsertTreeItem(hTreeView, hAceItem, TVI_FIRST, _T(""), NULL);
    _stprintf(szItemText, szAceTypeFmt, pAce->Header.AceType);
    TextToTreeItem(hTreeView, hItem, TREE_ITEM_ACE_TYPE, szItemText);

    // Insert the subitem with ACE flags
    hItem = InsertTreeItem(hTreeView, hAceItem, hItem, _T(""), NULL);
    AceFlagsToTreeItem(hTreeView, hItem, pAce->Header.AceFlags);

    // Insert the subitem with ACE size
    hItem = InsertTreeItem(hTreeView, hAceItem, hItem, _T(""), NULL);
    _stprintf(szItemText, szAceSizeFmt, pAce->Header.AceSize);
    TextToTreeItem(hTreeView, hItem, TREE_ITEM_ACE_SIZE, szItemText);

    // If the ACE is one of four supported ACE types, insetr access mask and SID
    switch(pAce->Header.AceType)
    {
        case ACCESS_ALLOWED_ACE_TYPE:
        case ACCESS_DENIED_ACE_TYPE:
        case SYSTEM_AUDIT_ACE_TYPE:
        case SYSTEM_ALARM_ACE_TYPE:

            // Insert the subitem with access mask
            hItem = InsertTreeItem(hTreeView, hAceItem, hItem, _T(""), NULL);
            AceMaskToTreeItem(hTreeView, hItem, pAce->Mask);

            // Insert the subitem with SID
            pSid = (PSID)(&pAce->SidStart);
            hItem = InsertTreeItem(hTreeView, hAceItem, hItem, _T(""), NULL);
            SidToTreeItem(hTreeView, hItem, pSid);
            break;

        case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
            
            // Insert the subitem with access mask
            hItem = InsertTreeItem(hTreeView, hAceItem, hItem, _T(""), NULL);
            MandatoryMaskToTreeItem(hTreeView, hItem, pAce->Mask);

            // Insert the subitem with SID
            pSid = (PSID)(&pAce->SidStart);
            hItem = InsertTreeItem(hTreeView, hAceItem, hItem, _T(""), NULL);
            MandLabelSidToTreeItem(hTreeView, hItem, pSid);
            break;

        default:
            // TODO: !!!
            break;
    }

    // Expand the tree item. Sometimes doesn't work directly, need to postpone it
    PostMessage(GetParent(hTreeView), WM_EXPAND_ITEM, (WPARAM)hAceItem, TVE_EXPAND);
}

static BOOL TreeItemToAce(HWND hTreeView, HTREEITEM hItem, PACCESS_ALLOWED_ACE * ppAce)
{
    PACCESS_ALLOWED_ACE pAce = NULL;
    TVITEM tvi;                               
    TCHAR szItemText[256];
    DWORD dwSidLength = 0;
    DWORD dwAceType = 0;
    DWORD dwAceFlags = 0;
    DWORD dwAceSize = 0;
    DWORD dwAceMask = 0;
    PSID pSid = NULL;

    // Get ACE type
    tvi.mask = TVIF_TEXT | TVIF_PARAM;
    tvi.hItem = hItem;
    tvi.pszText = szItemText;
    tvi.cchTextMax = _maxchars(szItemText);
    TreeView_GetItem(hTreeView, &tvi);
    if(!IsTreeItemAce(tvi.lParam))
        return FALSE;

    // Get the ACE type
    hItem = TreeView_GetChild(hTreeView, hItem);            // ACE_HEADER::AceType
    dwAceType = (BYTE)(tvi.lParam & 0xFF);

    // Get the ACE flags
    hItem = TreeView_GetNextSibling(hTreeView, hItem);      // ACE_HEADER::AceFlags
    if(!TreeItemToAceFlags(hTreeView, hItem, dwAceFlags))
        return FALSE;

    // Get the ACE size
    hItem = TreeView_GetNextSibling(hTreeView, hItem);      // ACE_HEADER::AceSize
    if(hItem == NULL)
        return FALSE;

    // Perform ACE-specific parsing
    switch(tvi.lParam & 0x000000FF)
    {
        case ACCESS_ALLOWED_ACE_TYPE:       // These four ACE types have the same layout
        case ACCESS_DENIED_ACE_TYPE:
        case SYSTEM_AUDIT_ACE_TYPE:
        case SYSTEM_ALARM_ACE_TYPE:

            // Parse the data as one of the four ACE types
            hItem = TreeView_GetNextSibling(hTreeView, hItem);      // ACE::Mask
            if(!TreeItemToAceMask(hTreeView, hItem, dwAceMask))
                return FALSE;

            // Get the start of the SID
            hItem = TreeView_GetNextSibling(hTreeView, hItem);      // ACE_HEADER::SidStart
            if(!TreeItemToSid(hTreeView, hItem, &pSid, false))
                return FALSE;
            break;

        case SYSTEM_MANDATORY_LABEL_ACE_TYPE:

            // Parse the data as the SYSTEM_MANDATORY_LABEL_ACE
            hItem = TreeView_GetNextSibling(hTreeView, hItem);      // ACE::Mask
            if(!TreeItemToMandatoryMask(hTreeView, hItem, dwAceMask))
                return FALSE;

            hItem = TreeView_GetNextSibling(hTreeView, hItem);      // ACE_HEADER::SidStart
            if(!TreeItemToMandLabelSid(hTreeView, hItem, &pSid))
                return FALSE;
            break;
    }

    // Calculate the length of the ACE
    if(pSid != NULL)
        dwSidLength = GetLengthSid(pSid);
    dwAceSize = sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + dwSidLength;
    
    // Allocate the ACE
    pAce = (PACCESS_ALLOWED_ACE)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwAceSize);
    if(pAce != NULL)
    {
        // Construct the ACE
        pAce->Header.AceType  = (BYTE)dwAceType;
        pAce->Header.AceFlags = (BYTE)dwAceFlags;
        pAce->Header.AceSize  = (WORD)dwAceSize;
        pAce->Mask = dwAceMask;
        
        // Copy the SID, if any
        if(pSid != NULL && dwSidLength != 0)
            CopySid(dwSidLength, (PSID)(&pAce->SidStart), pSid);

        // Give the ACE to the caller
        *ppAce = pAce;
    }

    // Free the returned SID and give the ACE to the caller
    if(pSid != NULL)
        HeapFree(g_hHeap, 0, pSid);
    return (pAce != NULL) ? TRUE : FALSE;
}

static void AclToTreeItem(
    HWND hTreeView,
    HTREEITEM hAclItem,
    PACL pAcl)
{
    PACCESS_ALLOWED_ACE pAce;
    HTREEITEM hItem;

    //
    // Note: parent ACL item already has the proper item text and LPARAM
    //

    // Do nothing if the ACL is NULL
    if(hAclItem == NULL || pAcl == NULL)
        return;

    // Remove all children, if any
    while((hItem = TreeView_GetChild(hTreeView, hAclItem)) != NULL)
        TreeView_DeleteItem(hTreeView, hItem);

    // Parse all ACEs
    hItem = TVI_FIRST;
    for(WORD AceIndex = 0; AceIndex < pAcl->AceCount; AceIndex++)
    {
        if(GetAce(pAcl, AceIndex, (PVOID *)&pAce))
        {
            // Insert the (next) ACE into the chain
            hItem = InsertTreeItem(hTreeView, hAclItem, hItem, NULL, NULL);
            AceToTreeItem(hTreeView, hItem, pAce);
        }
    }

    // Insert an entry which serves as new item inserter
    InsertTreeItem(hTreeView, hAclItem, _T("<Double-click to insert new ACE here ...>"), (PVOID)TREE_ITEM_NEW_ACE);
    TreeView_Expand(hTreeView, hAclItem, TVE_EXPAND);
}

static BOOL TreeItemToAcl(
    HWND hTreeView,
    HTREEITEM hAclItem1,
    HTREEITEM hAclItem2,
    PACL * ppAcl)
{
    PACCESS_ALLOWED_ACE * pAceArray = NULL;
    PACCESS_ALLOWED_ACE pAce = NULL;
    HTREEITEM hItem;
    LPBYTE pbAce;
    DWORD dwArraySize = 0;
    DWORD dwMaxAceCount = 0;
    DWORD dwAceCount = 0;
    DWORD dwAclSize = 0;
    DWORD dwIndex;
    PACL pNewAcl = NULL;

    // If none of the tree item is a valid ACL or an empty ACL, do nothing
    if(!IsTreeItemAcl(hTreeView, hAclItem1) && !IsTreeItemAcl(hTreeView, hAclItem2))
        return FALSE;
    dwMaxAceCount += TreeView_GetChildCount(hTreeView, hAclItem1);
    dwMaxAceCount += TreeView_GetChildCount(hTreeView, hAclItem2);

    // Allocate array of ACEs
    if(dwMaxAceCount > 0)
    {
        dwArraySize = sizeof(ACCESS_ALLOWED_ACE *) * dwMaxAceCount;
        pAceArray = (PACCESS_ALLOWED_ACE *)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwArraySize);
        if(pAceArray != NULL)
        {
            // Collect ACEs from the first ACL item
            if(IsTreeItemAcl(hTreeView, hAclItem1))
            {
                hItem = TreeView_GetChild(hTreeView, hAclItem1);
                while(hItem != NULL)
                {
                    if(TreeItemToAce(hTreeView, hItem, &pAceArray[dwAceCount]))
                        dwAceCount++;
                    hItem = TreeView_GetNextSibling(hTreeView, hItem);
                }
            }

            // Collect ACEs from the second ACL item
            if(IsTreeItemAcl(hTreeView, hAclItem2))
            {
                hItem = TreeView_GetChild(hTreeView, hAclItem2);
                while(hItem != NULL)
                {
                    if(TreeItemToAce(hTreeView, hItem, &pAceArray[dwAceCount]))
                        dwAceCount++;
                    hItem = TreeView_GetNextSibling(hTreeView, hItem);
                }
            }
        }
    }

    // Calculate size of the entire ACL
    dwAclSize = sizeof(ACL);
    for(dwIndex = 0; dwIndex < dwAceCount; dwIndex++)
    {
        if(pAceArray[dwIndex] != NULL)
        {
            dwAclSize += pAceArray[dwIndex]->Header.AceSize;
        }
    }

    // Allocate ACL
    pNewAcl = (PACL)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwAclSize);
    if(pNewAcl != NULL)
    {
        // Initialize the ACL
        InitializeAcl(pNewAcl, dwAclSize, ACL_REVISION);
        pbAce = (LPBYTE)pNewAcl + sizeof(ACL);

        // Add all ACEs
        for(dwIndex = 0; dwIndex < dwAceCount; dwIndex++)
        {
            pAce = pAceArray[dwIndex];
            if(pAce != NULL)
            {
                memcpy(pbAce, pAce, pAce->Header.AceSize);
                pNewAcl->AclSize = pNewAcl->AclSize + (WORD)pAce->Header.AceSize;
                pNewAcl->AceCount++;

                pbAce += pAce->Header.AceSize;
            }
        }

        // Give the ACL to the caller
        *ppAcl = pNewAcl;
    }

    // Free the ACE array, if any
    if(pAceArray != NULL)
    {
        for(dwIndex = 0; dwIndex < dwAceCount; dwIndex++)
        {
            if(pAceArray[dwIndex] != NULL)
            {
                HeapFree(g_hHeap, 0, pAceArray[dwIndex]);
                pAceArray[dwIndex] = NULL;
            }
        }
        HeapFree(g_hHeap, 0, pAceArray);
    }
    return TRUE;
}

static void SecurityDescriptorToTreeView(
    HWND hTreeView,
    PSECURITY_DESCRIPTOR pSD)
{
    HTREEITEM hParentItem;
    HTREEITEM hItem;
    TCHAR szNotPresent[128];
    PSID pOwner = NULL;
    PSID pGroup = NULL;
    PACL pDacl = NULL;
    PACL pSacl = NULL;
    BOOL bTemp;

    // Clear all current tree view items
    TreeView_DeleteAllItems(hTreeView);
    LoadString(g_hInst, IDS_NOT_PRESENT, szNotPresent, _maxchars(szNotPresent));

    //
    // Insert tree item for owner security information
    //

    hParentItem = InsertTreeItem(hTreeView, TVI_ROOT, _T("OWNER_SECURITY_INFORMATION"), (PVOID)TREE_ITEM_OWNER);
    GetSecurityDescriptorOwner(pSD, &pOwner, &bTemp);
    if(pOwner != NULL)    
    {
        hItem = InsertTreeItem(hTreeView, hParentItem, NULL, NULL); 
        SidToTreeItem(hTreeView, hItem, pOwner);
    }
    else
    {
        InsertTreeItem(hTreeView, hParentItem, szNotPresent, (PVOID)TREE_ITEM_NO_SID); 
    }
    TreeView_Expand(hTreeView, hParentItem, TVE_EXPAND);

    //
    // Insert tree item for group security information
    //

    hParentItem = InsertTreeItem(hTreeView, TVI_ROOT, _T("GROUP_SECURITY_INFORMATION"), (PVOID)TREE_ITEM_GROUP);
    GetSecurityDescriptorGroup(pSD, &pGroup, &bTemp);
    if(pGroup != NULL)
    {
        hItem = InsertTreeItem(hTreeView, hParentItem, NULL, NULL); 
        SidToTreeItem(hTreeView, hItem, pGroup);
    }
    else
    {
        InsertTreeItem(hTreeView, hParentItem, szNotPresent, (PVOID)TREE_ITEM_NO_SID); 
    }
    TreeView_Expand(hTreeView, hParentItem, TVE_EXPAND);

    //
    // Insert tree item for DACL security information
    //

    hParentItem = InsertTreeItem(hTreeView, TVI_ROOT, _T("DACL_SECURITY_INFORMATION"), (PVOID)TREE_ITEM_DACL);
    GetSecurityDescriptorDacl(pSD, &bTemp, &pDacl, &bTemp);
    if(pDacl != NULL)
    {
        AclToTreeItem(hTreeView, hParentItem, pDacl);
    }
    else
    {
        InsertTreeItem(hTreeView, hParentItem, szNotPresent, (PVOID)TREE_ITEM_NEW_ACE); 
    }
    TreeView_Expand(hTreeView, hParentItem, TVE_EXPAND);

    //
    // Insert tree item for SACL security information
    //

    hParentItem = InsertTreeItem(hTreeView, TVI_ROOT, _T("SACL_SECURITY_INFORMATION"), (PVOID)TREE_ITEM_SACL);
    GetSecurityDescriptorSacl(pSD, &bTemp, &pSacl, &bTemp);
    if(pSacl != NULL)
    {
        AclToTreeItem(hTreeView, hParentItem, pSacl);
    }
    else
    {
        InsertTreeItem(hTreeView, hParentItem, NULL, szNotPresent, (PVOID)TREE_ITEM_NEW_ACE); 
    }
    TreeView_Expand(hTreeView, hParentItem, TVE_EXPAND);

    //
    // Insert tree item for LABEL security information
    //

    hParentItem = InsertTreeItem(hTreeView, TVI_ROOT, _T("LABEL_SECURITY_INFORMATION"), (PVOID)TREE_ITEM_LABEL);
    GetSecurityDescriptorSacl(pSD, &bTemp, &pSacl, &bTemp);
    if(pSacl != NULL)
    {
        AclToTreeItem(hTreeView, hParentItem, pSacl);
    }
    else
    {
        InsertTreeItem(hTreeView, hParentItem, NULL, szNotPresent, (PVOID)TREE_ITEM_NEW_ACE); 
    }
    TreeView_Expand(hTreeView, hParentItem, TVE_EXPAND);
}

static HTREEITEM CreateNewSidAtItem(HWND hTreeView, HTREEITEM hItem)
{
    PSID pSid = CreateNewSid(ACCESS_ALLOWED_ACE_TYPE);

    if(pSid != NULL)
    {
        SidToTreeItem(hTreeView, hItem, pSid);
        HeapFree(g_hHeap, 0, pSid);
    }
    return hItem;
}

static HTREEITEM InsertNewAceToTree(HWND hTreeView, HTREEITEM hInsertBefore, HTREEITEM hInsertAfter)
{
    PACCESS_ALLOWED_ACE pAce = NULL;
    HTREEITEM hParentItem = NULL;
    HTREEITEM hItem = NULL;
    TVITEM tvi;
    PACL pAcl;
    BYTE AceType;

    // Only one item must be non-NULL
    assert(hInsertBefore != NULL || hInsertAfter != NULL);
    assert(hInsertBefore == NULL || hInsertAfter == NULL);

    // Get the parent item
    if(hInsertBefore != NULL)
        hParentItem = TreeView_GetParent(hTreeView, hInsertBefore);
    if(hInsertAfter != NULL)
        hParentItem = TreeView_GetParent(hTreeView, hInsertAfter);

    // Determine the item where we shall insert the new ACE
    if(hInsertBefore != NULL)
        hInsertAfter = TreeView_GetPrevSibling(hTreeView, hInsertBefore);
    if(hInsertAfter == NULL)
        hInsertAfter = TVI_FIRST;
    
    // Get the type of ACE to create
    tvi.mask = TVIF_PARAM;
    tvi.hItem = hParentItem;
    TreeView_GetItem(hTreeView, &tvi);
    switch(tvi.lParam)
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
            return NULL;
    }

    // Create ACE with one entry and set it to the new item
    pAcl = CreateNewAcl(AceType);
    if(pAcl != NULL)
    {
        if(GetAce(pAcl, 0, (LPVOID *)(&pAce)))
        {
            hItem = InsertTreeItem(hTreeView, hParentItem, hInsertAfter, NULL, NULL);
            AceToTreeItem(hTreeView, hItem, pAce);
        }
        HeapFree(g_hHeap, 0, pAcl);
    }

    return hItem;
}

static void EditAceType(HWND hDlg, HWND hTreeView, HTREEITEM hItem)
{
    PACCESS_ALLOWED_ACE pFirstAce = NULL;
    PACCESS_ALLOWED_ACE pAce = NULL;
    PACL pAcl;

    // Get the current ACE type from the item
    if(TreeItemToAce(hTreeView, hItem, &pAce))
    {
        DWORD dwSaveValue = pAce->Header.AceType;
        DWORD dwValue = dwSaveValue;

        // Run the dialog
        if(ValuesDialog(hDlg, &dwValue, IDS_ACE_TYPE, AceTypes) == IDOK && dwValue != dwSaveValue)
        {
            // Create new ACL with single ACE of the new type
            pAcl = CreateNewAcl((BYTE)dwValue);
            if(pAcl == NULL)
            {
                MessageBoxRc(hDlg, IDS_ERROR, IDS_ACE_TYPE_NOT_SUPPORTED, (dwValue & 0xFF));
                return;
            }

            // Retrieve the very first ACE and insert it to the tree item
            if(GetAce(pAcl, 0, (LPVOID *)(&pFirstAce)))
                AceToTreeItem(hTreeView, hItem, pFirstAce);
            HeapFree(g_hHeap, 0, pAcl);
        }

        HeapFree(g_hHeap, 0, pAce);
    }
}

static void EditAceType2(HWND hDlg, HWND hTreeView, HTREEITEM hItem)
{
    HTREEITEM hParentItem = TreeView_GetParent(hTreeView, hItem);

    EditAceType(hDlg, hTreeView, hParentItem);
}

static void EditAceFlags(HWND hDlg, HWND hTreeView, HTREEITEM hItem)
{
    DWORD dwAceFlags = 0;

    // Get the ACE flags from the tree view item
    if(TreeItemToAceFlags(hTreeView, hItem, dwAceFlags))
    {
        if(FlagsDialog(hDlg, &dwAceFlags, IDS_ACE_FLAGS, AceFlags) == IDOK)
        {
            AceFlagsToTreeItem(hTreeView, hItem, dwAceFlags);
        }
    }
}

static void EditAceMask(HWND hDlg, HWND hTreeView, HTREEITEM hItem)
{
    DWORD dwAceMask = 0;

    // Get the ACE mask from the tere item
    if(TreeItemToAceMask(hTreeView, hItem, dwAceMask))
    {
        if(FlagsDialog(hDlg, &dwAceMask, IDS_ACE_MASK, AceMasks) == IDOK)
        {
            AceMaskToTreeItem(hTreeView, hItem, dwAceMask);
        }
    }
}

static void EditMandatoryMask(HWND hDlg, HWND hTreeView, HTREEITEM hItem)
{
    DWORD dwMandatoryMask = 0;

    // Get the ACE mask from the tere item
    if(TreeItemToMandatoryMask(hTreeView, hItem, dwMandatoryMask))
    {
        if(FlagsDialog(hDlg, &dwMandatoryMask, IDS_MANDATORY_MASK, MandatoryMasks) == IDOK)
        {
            MandatoryMaskToTreeItem(hTreeView, hItem, dwMandatoryMask);
        }
    }
}

static BOOL StartEditingAceFlags(HWND /* hDlg */, HWND hTreeView, HTREEITEM hItem)
{
    TCHAR szItemText[128];
    HWND hEdit = TreeView_GetEditControl(hTreeView);
    DWORD dwAceFlags = 0;
    
    if(hEdit != NULL)
    {
        if(TreeItemToAceFlags(hTreeView, hItem, dwAceFlags))
        {
            Edit_LimitText(hEdit, 0x08);
            _stprintf(szItemText, _T("%02lX"), dwAceFlags);
            SetWindowText(hEdit, szItemText);
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL StartEditingAceMask(HWND /* hDlg */, HWND hTreeView, HTREEITEM hItem)
{
    TCHAR szItemText[128];
    HWND hEdit = TreeView_GetEditControl(hTreeView);
    DWORD dwAceMask = 0;
    
    if(hEdit != NULL)
    {
        if(TreeItemToAceMask(hTreeView, hItem, dwAceMask))
        {
            Edit_LimitText(hEdit, 0x20);
            _stprintf(szItemText, _T("%08lX"), dwAceMask);
            SetWindowText(hEdit, szItemText);
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL StartEditingMandAceMask(HWND /* hDlg */, HWND hTreeView, HTREEITEM hItem)
{
    TCHAR szItemText[128];
    HWND hEdit = TreeView_GetEditControl(hTreeView);
    DWORD dwAceMask = 0;
    
    if(hEdit != NULL)
    {
        if(TreeItemToMandatoryMask(hTreeView, hItem, dwAceMask))
        {
            Edit_LimitText(hEdit, 0x20);
            _stprintf(szItemText, _T("%08lX"), dwAceMask);
            SetWindowText(hEdit, szItemText);
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL StartEditingSid(HWND /* hDlg */, HWND hTreeView, HTREEITEM hItem)
{
    TCHAR szItemText[128];
    HWND hEdit = TreeView_GetEditControl(hTreeView);
    PSID pSid = NULL;
    
    if(hEdit != NULL)
    {
        if(TreeItemToSid(hTreeView, hItem, &pSid, true))
        {
            Edit_LimitText(hEdit, 128);
            SidToString(pSid, szItemText, false);
            SetWindowText(hEdit, szItemText);
            HeapFree(g_hHeap, 0, pSid);
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL StartEditingMandLabelSid(HWND /* hDlg */, HWND hTreeView, HTREEITEM hItem)
{
    TCHAR szItemText[0x40];
    DWORD dwIntLevel = SECURITY_MANDATORY_MEDIUM_RID;
    HWND hEdit = TreeView_GetEditControl(hTreeView);
    PSID pSid = NULL;
    
    if(hEdit != NULL)
    {
        if(TreeItemToMandLabelSid(hTreeView, hItem, &pSid))
        {
            // Format the integrity level
            dwIntLevel = SidToIntegrityLevel(pSid);
            _stprintf(szItemText, _T("%08lX"), dwIntLevel);

            // Apply the integrity level to the editbox
            Edit_LimitText(hEdit, 0x20);
            SetWindowText(hEdit, szItemText);
            HeapFree(g_hHeap, 0, pSid);
            return TRUE;
        }
    }

    return FALSE;
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

static void UpdateContextMenu(HWND hTreeView, HTREEITEM hItem, HMENU hSubMenu)
{
    HTREEITEM hNextItem;
    TVITEM tvi;
    UINT uEnable = MF_GRAYED;

    // Move ACE up is only allowed when the ACE is not the first one
    if(TreeView_GetPrevSibling(hTreeView, hItem) == NULL)
        EnableMenuItem(hSubMenu, IDC_MOVE_ACE_UP, MF_GRAYED);

    // Move ACE down is only allowed when the ACE is not the last one
    hNextItem = TreeView_GetNextSibling(hTreeView, hItem);
    if(hNextItem != NULL)
    {
        tvi.mask = TVIF_PARAM;
        tvi.hItem = hNextItem;
        TreeView_GetItem(hTreeView, &tvi);
        if(tvi.lParam != TREE_ITEM_NEW_ACE)
            uEnable = MF_ENABLED;
    }
    EnableMenuItem(hSubMenu, IDC_MOVE_ACE_DOWN, uEnable);
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
        pAnchors->AddAnchor(hDlg, IDC_RESULT_STATUS_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_STATUS, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_IOSTATUS_INFO_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_IOSTATUS_INFO, akLeft | akRight | akBottom);
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

static void OnExpandItem(HWND hDlg, WPARAM wParam, LPARAM lParam)
{
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);

    // Apply the ACE flags to the tree item
    TreeView_Expand(hTreeView, (HTREEITEM)wParam, (UINT)lParam);
}

static void OnAceFlagsToItem(HWND hDlg, WPARAM wParam, LPARAM lParam)
{
    HTREEITEM hItem = (HTREEITEM)wParam;
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);
    DWORD dwAceFlags = (DWORD)lParam;

    // Apply the ACE flags to the tree item
    AceFlagsToTreeItem(hTreeView, hItem, dwAceFlags);
}

static void OnAceMaskToItem(HWND hDlg, WPARAM wParam, LPARAM lParam)
{
    HTREEITEM hItem = (HTREEITEM)wParam;
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);
    DWORD dwAceMask = (DWORD)lParam;

    // Apply the ACE flags to the tree item
    AceMaskToTreeItem(hTreeView, hItem, dwAceMask);
}

static void OnMandatoryMaskToItem(HWND hDlg, WPARAM wParam, LPARAM lParam)
{
    HTREEITEM hItem = (HTREEITEM)wParam;
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);
    DWORD dwAceMask = (DWORD)lParam;

    // Apply the ACE flags to the tree item
    MandatoryMaskToTreeItem(hTreeView, hItem, dwAceMask);
}

static void OnSidToItem(HWND hDlg, WPARAM wParam, LPARAM lParam)
{
    SID_IDENTIFIER_AUTHORITY Sia = SECURITY_MANDATORY_LABEL_AUTHORITY;
    HTREEITEM hItem = (HTREEITEM)wParam;
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);
    PSID pSid = (PSID)lParam;

    if(pSid != NULL)
    {
        // Apply the SID to the tree item
        if(!memcmp(GetSidIdentifierAuthority(pSid), &Sia, sizeof(SID_IDENTIFIER_AUTHORITY)))
        {
            MandLabelSidToTreeItem(hTreeView, hItem, pSid);
        }
        else
        {
            SidToTreeItem(hTreeView, hItem, pSid);
        }

        // Free the SID
        HeapFree(g_hHeap, 0, pSid);
    }
}

static int OnEditLabel(HWND hDlg)
{
    HTREEITEM hItem;
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);

    // Only start editing if the tree view has focus
    if(GetFocus() == hTreeView)
    {
        hItem = TreeView_GetSelection(hTreeView);
        if(hItem != NULL)
            TreeView_EditLabel(hTreeView, hItem);
    }

    return TRUE;
}

static int OnAceOperation(HWND hDlg, UINT nIDCtrl)
{
    PACCESS_ALLOWED_ACE pAce1 = NULL;
    PACCESS_ALLOWED_ACE pAce2 = NULL;
    HTREEITEM hItemBefore;
    HTREEITEM hItemAfter;
    HTREEITEM hItem;
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);

    // Get the currently selected item
    hItem = TreeView_GetSelection(hTreeView);

    // Call the appropriate insert function
    if(nIDCtrl == IDC_NEW_ACE_BEFORE)
    {
        hItem = InsertNewAceToTree(hTreeView, hItem, NULL);
        TreeView_Select(hTreeView, hItem, TVGN_CARET);
        return TRUE;
    }

    if(nIDCtrl == IDC_NEW_ACE_AFTER)
    {
        hItem = InsertNewAceToTree(hTreeView, NULL, hItem);
        TreeView_Select(hTreeView, hItem, TVGN_CARET);
        return TRUE;
    }

    if(nIDCtrl == IDC_MOVE_ACE_UP)
    {
        hItemBefore = TreeView_GetPrevSibling(hTreeView, hItem);
        if(hItemBefore == NULL)
            return FALSE;

        TreeItemToAce(hTreeView, hItemBefore, &pAce1);
        TreeItemToAce(hTreeView, hItem, &pAce2);
        AceToTreeItem(hTreeView, hItemBefore, pAce2);
        AceToTreeItem(hTreeView, hItem, pAce1);
        TreeView_Select(hTreeView, hItemBefore, TVGN_CARET);
        HeapFree(g_hHeap, 0, pAce2);
        HeapFree(g_hHeap, 0, pAce1);
        return TRUE;
    }

    if(nIDCtrl == IDC_MOVE_ACE_DOWN)
    {
        hItemAfter = TreeView_GetNextSibling(hTreeView, hItem);
        if(hItemAfter == NULL)
            return FALSE;

        TreeItemToAce(hTreeView, hItem, &pAce1);
        TreeItemToAce(hTreeView, hItemAfter, &pAce2);
        AceToTreeItem(hTreeView, hItem, pAce2);
        AceToTreeItem(hTreeView, hItemAfter, pAce1);
        TreeView_Select(hTreeView, hItemAfter, TVGN_CARET);
        HeapFree(g_hHeap, 0, pAce2);
        HeapFree(g_hHeap, 0, pAce1);
        return TRUE;
    }

    if(nIDCtrl == IDC_DELETE_ACE)
    {
        TreeView_DeleteItem(hTreeView, hItem);
        return TRUE;
    }

    return FALSE;
}

static int OnSetBlankSecurityDescriptor(HWND hDlg)
{
    SECURITY_DESCRIPTOR sd;
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);

    // Initialize the tree view with blank security descriptor
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SecurityDescriptorToTreeView(hTreeView, &sd);
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
    SetResultInfo(hDlg, Status, NULL, cbSD);

    // If succeeded, load our tree view with security information
    if(NT_SUCCESS(Status))
        SecurityDescriptorToTreeView(hTreeView, pSD);

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
            if(TreeItemToSid(hTreeView, hItem, &pOwner, false) && pOwner != NULL)
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
            if(TreeItemToSid(hTreeView, hItem, &pOwner, false) && pGroup != NULL)
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
        if(TreeItemToAcl(hTreeView, hChildItem[2], NULL, &pDacl) && pDacl != NULL)
        {
            SetSecurityDescriptorDacl(&sd, TRUE, pDacl, FALSE);
            AppliedSecInfo |= DACL_SECURITY_INFORMATION;
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
            hAclItem1 = hChildItem[3];
        if(WantedSecInfo & LABEL_SECURITY_INFORMATION)
            hAclItem2 = hChildItem[4];

        if(TreeItemToAcl(hTreeView, hAclItem1, hAclItem2, &pSacl) && pSacl != NULL)
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
        SetResultInfo(hDlg, Status);
    }

    // Free all 4 parts of the security information
    if(pSacl != NULL)
        HeapFree(g_hHeap, 0, pSacl);
    if(pDacl != NULL)
        HeapFree(g_hHeap, 0, pDacl);
    if(pGroup != NULL)
        HeapFree(g_hHeap, 0, pGroup);
    if(pOwner != NULL)
        HeapFree(g_hHeap, 0, pOwner);
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

static int OnTreeViewContextMenu(HWND hDlg, LPARAM lParam)
{
    HTREEITEM hItem;
    TVITEM tvi;
    HMENU hMainMenu = LoadMenu(g_hInst, MAKEINTRESOURCE(IDR_ACE_MENU));
    HMENU hSubMenu = GetSubMenu(hMainMenu, 0);
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);
    RECT rect;

    // Get the selected item
    hItem = TreeView_GetSelection(hTreeView);
    if(hItem == NULL)
        return FALSE;

    // Get the LPARAM of the tree item.
    tvi.mask = TVIF_PARAM;
    tvi.hItem = hItem;
    TreeView_GetItem(hTreeView, &tvi);

    // If it's one of the 4 ACE types, we offer context menu
    if(IsTreeItemAce(tvi.lParam))
    {
        // Get the position where the menu item will be
        rect.left = GET_X_LPARAM(lParam);
        rect.top = GET_Y_LPARAM(lParam);
        if(rect.left == -1 && rect.top == -1)
        {
            TreeView_GetItemRect(hTreeView, hItem, &rect, TRUE); 
            ClientToScreen(hTreeView, (LPPOINT)&rect);
        }

        // Set the window to foreground due to capture mouse events
        UpdateContextMenu(hTreeView, hItem, hSubMenu);
        SetForegroundWindow(hDlg);
        TrackPopupMenu(hSubMenu, (TPM_LEFTBUTTON | TPM_RIGHTBUTTON), rect.left, rect.top, 0, hDlg, NULL);
        PostMessage(hDlg, WM_NULL, 0, 0);
        DestroyMenu(hMainMenu);
        return TRUE;
    }

    return FALSE;
}

static int OnTreeViewRightClick(HWND hDlg)
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

static int OnTreeViewDoubleClick(HWND hDlg)
{
    HTREEITEM hSelItem;
    HTREEITEM hItem;
    TVITEM tvi;
    HWND hTreeView = GetDlgItem(hDlg, IDC_SECURITY);

    // Get the lParam of the clicked item
    hSelItem = TreeView_GetSelection(hTreeView);
    tvi.mask = TVIF_PARAM;
    tvi.hItem = hSelItem;
    TreeView_GetItem(hTreeView, &tvi);

    // Edit the ACE item types
    if(IsTreeItemAce(tvi.lParam))
    {
        EditAceType(hDlg, hTreeView, hSelItem);
    }
    else
    {
        // Edit the item
        switch(tvi.lParam)
        {
            case TREE_ITEM_NO_SID:
                hItem = CreateNewSidAtItem(hTreeView, hSelItem);
                TreeView_Select(hTreeView, hItem, TVGN_CARET);
                break;

            case TREE_ITEM_NEW_ACE: // Insert a new ACE to the tree
                hItem = InsertNewAceToTree(hTreeView, hSelItem, NULL);
                TreeView_Select(hTreeView, hItem, TVGN_CARET);
                break;

            case TREE_ITEM_ACE_TYPE:
                EditAceType2(hDlg, hTreeView, hSelItem);
                break;

            case TREE_ITEM_ACE_FLAGS:
                EditAceFlags(hDlg, hTreeView, hSelItem);
                break;

            case TREE_ITEM_ACE_MASK:
                EditAceMask(hDlg, hTreeView, hSelItem);
                break;

            case TREE_ITEM_MANDATORY_MASK:
                EditMandatoryMask(hDlg, hTreeView, hSelItem);
                break;
        }
    }

    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, TRUE);
    return TRUE;
}

static void OnTVKeyDown(HWND hDlg, NMTVKEYDOWN * pNMTVKeyDown)
{
    if(pNMTVKeyDown->wVKey == VK_SPACE)
    {
        OnTreeViewDoubleClick(hDlg);
    }
}

static int OnBeginLabelEdit(HWND hDlg, NMTVDISPINFO * pTVDispInfo)
{
    HWND hTreeView = pTVDispInfo->hdr.hwndFrom;
    BOOL bCancelEdit = TRUE;

    // Verify if the selected tree item is editable
    switch(pTVDispInfo->item.lParam)
    {
        case TREE_ITEM_ACE_FLAGS:
            if(StartEditingAceFlags(hDlg, hTreeView, pTVDispInfo->item.hItem))
            {
                DisableDialogMessages(hDlg, TRUE);
                bCancelEdit = FALSE;
            }
            break;

        case TREE_ITEM_ACE_MASK:
            if(StartEditingAceMask(hDlg, hTreeView, pTVDispInfo->item.hItem))
            {
                DisableDialogMessages(hDlg, TRUE);
                bCancelEdit = FALSE;
            }
            break;

        case TREE_ITEM_MANDATORY_MASK:
            if(StartEditingMandAceMask(hDlg, hTreeView, pTVDispInfo->item.hItem))
            {
                DisableDialogMessages(hDlg, TRUE);
                bCancelEdit = FALSE;
            }
            break;

        case TREE_ITEM_SID:
        case TREE_ITEM_NO_SID:
            if(StartEditingSid(hDlg, hTreeView, pTVDispInfo->item.hItem))
            {
                DisableDialogMessages(hDlg, TRUE);
                bCancelEdit = FALSE;
            }
            break;

        case TREE_ITEM_SID_MAND_LABEL:
            if(StartEditingMandLabelSid(hDlg, hTreeView, pTVDispInfo->item.hItem))
            {
                DisableDialogMessages(hDlg, TRUE);
                bCancelEdit = FALSE;
            }
            break;

        default:
            SetResultInfo(hDlg, STATUS_CANNOT_EDIT_THIS);
            break;
    }

    // Store the result info the dialog's private variables
    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, bCancelEdit);
    return TRUE;
}

static int OnEndLabelEdit(HWND hDlg, NMTVDISPINFO * pTVDispInfo)
{
    LPTSTR szEnd;
    DWORD dwNewValue;
    PSID pSid = NULL;
    BOOL bAcceptChanges = FALSE;

    // If pszText contains NULL, it means that the user cancelled the editing
    if(pTVDispInfo->item.pszText != NULL)
    {
        // Verify if the selected file info class is editable
        switch(pTVDispInfo->item.lParam)
        {
            case TREE_ITEM_ACE_FLAGS:
                dwNewValue = StrToInt(pTVDispInfo->item.pszText, &szEnd, 0x10);
                if(*szEnd != 0)
                {
                    // Warn the user that the text has an invalid format
                    SetResultInfo(hDlg, STATUS_INVALID_DATA_FORMAT);
                    break;
                }

                // If all seems to be OK, we delay-update the tree item
                PostMessage(hDlg, WM_ACE_FLAGS_TO_ITEM, (WPARAM)pTVDispInfo->item.hItem, (LPARAM)dwNewValue);
                bAcceptChanges = TRUE;
                break;

            case TREE_ITEM_ACE_MASK:
                dwNewValue = StrToInt(pTVDispInfo->item.pszText, &szEnd, 0x10);
                if(*szEnd != 0)
                {
                    // Warn the user that the text has an invalid format
                    SetResultInfo(hDlg, STATUS_INVALID_DATA_FORMAT);
                    break;
                }

                // If all seems to be OK, we delay-update the tree item
                PostMessage(hDlg, WM_ACE_MASK_TO_ITEM, (WPARAM)pTVDispInfo->item.hItem, (LPARAM)dwNewValue);
                bAcceptChanges = TRUE;
                break;

            case TREE_ITEM_MANDATORY_MASK:
                dwNewValue = StrToInt(pTVDispInfo->item.pszText, &szEnd, 0x10);
                if(*szEnd != 0)
                {
                    // Warn the user that the text has an invalid format
                    SetResultInfo(hDlg, STATUS_INVALID_DATA_FORMAT);
                    break;
                }

                // If all seems to be OK, we delay-update the tree item
                PostMessage(hDlg, WM_MAND_MASK_TO_ITEM, (WPARAM)pTVDispInfo->item.hItem, (LPARAM)dwNewValue);
                bAcceptChanges = TRUE;
                break;

            case TREE_ITEM_SID:
            case TREE_ITEM_NO_SID:
                
                // Check if the SID has proper format
                if(!StringToSid(pTVDispInfo->item.pszText, &pSid))
                {
                    // Warn the user that the text has an invalid format
                    SetResultInfo(hDlg, STATUS_INVALID_DATA_FORMAT);
                    break;
                }

                // If all seems to be OK, we delay-update the tree item
                PostMessage(hDlg, WM_SID_TO_ITEM, (WPARAM)pTVDispInfo->item.hItem, (LPARAM)pSid);
                bAcceptChanges = TRUE;
                break;

            case TREE_ITEM_SID_MAND_LABEL:
                dwNewValue = StrToInt(pTVDispInfo->item.pszText, &szEnd, 0x10);
                if(*szEnd != 0)
                {
                    // Warn the user that the text has an invalid format
                    SetResultInfo(hDlg, STATUS_INVALID_DATA_FORMAT);
                    break;
                }

                // If all is OK, we delay-update the tree item
                if(IntegrityLevelToSid(dwNewValue, &pSid))
                {
                    PostMessage(hDlg, WM_SID_TO_ITEM, (WPARAM)pTVDispInfo->item.hItem, (LPARAM)pSid);
                    bAcceptChanges = TRUE;
                }
                break;

            default:
                SetResultInfo(hDlg, STATUS_CANNOT_EDIT_THIS);
                break;
        }
    }

    // Enable the exit button
    DisableDialogMessages(hDlg, FALSE);
    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, bAcceptChanges);
    return TRUE;
}

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    // From an accelerator
    if(nNotify == 1)
    {
        switch(nIDCtrl)        
        {
            case ID_DOUBLE_CLICK:
                return OnTreeViewDoubleClick(hDlg);

            case ID_EDIT_LABEL:
                return OnEditLabel(hDlg);
        }
        return FALSE;
    }

    if(nNotify == BN_CLICKED)
    {
        switch(nIDCtrl)
        {
            case IDC_NEW_ACE_BEFORE:
            case IDC_NEW_ACE_AFTER:
            case IDC_MOVE_ACE_UP:
            case IDC_MOVE_ACE_DOWN:
            case IDC_DELETE_ACE:
                return OnAceOperation(hDlg, nIDCtrl);

            case IDC_SET_BLANK:
                return OnSetBlankSecurityDescriptor(hDlg);

            case IDC_QUERY_SECURITY:
                return OnQuerySecurity(hDlg);

            case IDC_SET_SECURITY:
                return OnSetSecurity(hDlg);
        }
        return FALSE;
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
                return OnTreeViewRightClick(hDlg);
            break;
    
        case NM_DBLCLK:
            if(pNMHDR->idFrom == IDC_SECURITY)
                return OnTreeViewDoubleClick(hDlg);
            break;

        case TVN_KEYDOWN:
            OnTVKeyDown(hDlg, (NMTVKEYDOWN *)pNMHDR);
            break;
    
        case TVN_BEGINLABELEDIT:
            return OnBeginLabelEdit(hDlg, (NMTVDISPINFO *)pNMHDR);

        case TVN_ENDLABELEDIT:
            return OnEndLabelEdit(hDlg, (NMTVDISPINFO *)pNMHDR);
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

        case WM_EXPAND_ITEM:
            OnExpandItem(hDlg, wParam, lParam);
            return TRUE;

        case WM_ACE_FLAGS_TO_ITEM:
            OnAceFlagsToItem(hDlg, wParam, lParam);
            return TRUE;

        case WM_ACE_MASK_TO_ITEM:
            OnAceMaskToItem(hDlg, wParam, lParam);
            return TRUE;

        case WM_MAND_MASK_TO_ITEM:
            OnMandatoryMaskToItem(hDlg, wParam, lParam);
            return TRUE;

        case WM_SID_TO_ITEM:
            OnSidToItem(hDlg, wParam, lParam);
            return TRUE;

        case WM_CONTEXTMENU:
            return OnTreeViewContextMenu(hDlg, lParam);

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
