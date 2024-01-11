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

#define ALL_SACL_SECURITY_INFORMATION   0xFFFFFFF8  // Mask for all system-type security infos

#define ITEM_DATA_MAGIC                 0xDEADBABE

#define MAX_ITEM_TEXT                   1024
#define MAX_NEST_LEVEL                  8

#define ItemDataNULL    (PVOID)(INT_PTR)(NULL)
#define ItemDataValid   (PVOID)(INT_PTR)(1)

typedef enum _ITEM_TYPE
{
    ItemTypeUnknown,
    ItemTypeOwner,                                  // The item contains "OWNER_SECURITY_INFORMATION"
    ItemTypeGroup,                                  // The item contains "GROUP_SECURITY_INFORMATION"
    ItemTypeDacl,                                   // The item contains "DACL_SECURITY_INFORMATION"
    ItemTypeSacl,                                   // The item contains "SACL_SECURITY_INFORMATION"
    ItemTypeNoAcl,                                  // The item says that an ACL is not present
    ItemTypeNullAcl,                                // NULL ACL
    ItemTypeSid,                                    // Security Identifier (SID)
    ItemTypeAce,                                    // Access Control Entry (ACE) from DACL
    ItemTypeAceType,                                // ACE_HEADER::AceType
    ItemTypeBool,                                   // A boolean value
    ItemTypeUint08,                                 // 8-bit integer
    ItemTypeUint16,                                 // 16-bit integer
    ItemTypeUint32,                                 // 32-bit integer
    ItemTypeUint64,                                 // 64-bit integer
    ItemTypeLPWSTR,                                 // Pointer to a zero-terminate unicode string (LPWSTR)
    ItemTypeBinN,                                   // An octet string with length at the beginning
    ItemTypeGuid,                                   // An object GUID
    ItemTypeGuid2,                                  // An inherited object GUID
    ItemTypeSid11,                                  // mandatory label SID
    ItemTypeSid17,                                  // Policy label SID
    ItemTypeSid19,                                  // Trust level SID
    ItemTypeSid19e,                                 // Trust level SID or "Everyone"
    ItemTypeCSA_V1,                                 // The CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 structure
    ItemTypeCSA_VType,                              // CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1::ValueType
    ItemTypeCSA_VCnt,                               // CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1::ValueCount
    ItemTypeSidN,                                   // "Counted" SID (with preceding ULONG, containing length)
    ItemTypeCondition,                              // ACE condition
} ITEM_TYPE, *PITEM_TYPE;

typedef struct _NON_EDITABLE_DATA
{
    ULONG Magic;                                    // ITEM_DATA_MAGIC
    ULONG Length;                                   // Length of the subsequent data
    BYTE Data[1];                                   // The data itself
} NON_EDITABLE_DATA, *PNON_EDITABLE_DATA;

typedef struct _TREE_ITEM_INFO
{
    ITEM_TYPE ItemType;
    UINT nIDFormat1;                                // Format string when no data
    UINT nIDFormat2;                                // Format string when there are data

    // Array of flag values and flag names
    TFlagInfo * pFlagInfos;

    // Converts the binary item to string representation that will be shown in the tree view item
    NTSTATUS (*ToString) (_TREE_ITEM_INFO * pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy);

    // Converts the string representation to binary item
    NTSTATUS(*StringTo) (_TREE_ITEM_INFO * pItemInfo, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy);

    // Creates a new item of that type
    NTSTATUS(*CreateNew)(_TREE_ITEM_INFO * pItemInfo, LPBYTE pbDataBuffer, size_t * pcbDataBuffer);
    
    // Type of the item data
    PVOID ItemData;
} TREE_ITEM_INFO, *PTREE_ITEM_INFO;
typedef const TREE_ITEM_INFO *PCTREE_ITEM_INFO;

typedef struct _ACE_FIELD_INFO
{
    ULONG AceLayoutFlag;
    TREE_ITEM_INFO TreeItem;

} ACE_FIELD_INFO, *PACE_FIELD_INFO;

typedef struct _TV_SELECTION
{
    size_t ItemIndex[MAX_NEST_LEVEL];       // Item index in each level
    size_t nNestLevel;                      // Nest level of the item that was selected
} TV_SELECTION, *PTV_SELECTION;

static LPCTSTR szAceTypeSuffix = _T("_TYPE");
static LPCSTR szUnknownAceType = "UNKNOWN_ACE_TYPE: %02x";

static size_t GLOBAL_ItemIndex = INVALID_ITEM_INDEX;
static PACL pAclInWork = NULL;              // Current ACL-in-construction
static PACE pAceInWork = NULL;              // Current ACE-in-construction

static SID_IDENTIFIER_AUTHORITY SiaNull   = SECURITY_NULL_SID_AUTHORITY;
static SID_IDENTIFIER_AUTHORITY SiaWorld  = SECURITY_WORLD_SID_AUTHORITY;
static SID_IDENTIFIER_AUTHORITY SiaLabel  = SECURITY_MANDATORY_LABEL_AUTHORITY;
static SID_IDENTIFIER_AUTHORITY SiaPolicy = SECURITY_SCOPED_POLICY_ID_AUTHORITY;
static SID_IDENTIFIER_AUTHORITY SiaTrust  = SECURITY_PROCESS_TRUST_AUTHORITY;

static const BYTE EmptyAcl[] =
{
    ACL_REVISION, 0, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const BYTE FullControlAcl[] =
{
    0x04, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
};

static const LPCTSTR szNoGuidString = _T("(none)");

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
    FLAGINFO_NUMV(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE),
    FLAGINFO_NUMV(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE),
    FLAGINFO_NUMV(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE),
    FLAGINFO_NUMV(SYSTEM_ACCESS_FILTER_ACE_TYPE),
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

static TFlagInfo AceHdrFlags2[] =
{
    FLAGINFO_BITV(OBJECT_INHERIT_ACE),
    FLAGINFO_BITV(CONTAINER_INHERIT_ACE),
    FLAGINFO_BITV(NO_PROPAGATE_INHERIT_ACE),
    FLAGINFO_BITV(INHERIT_ONLY_ACE),
    FLAGINFO_BITV(INHERITED_ACE),
    FLAGINFO_BITV(TRUST_PROTECTED_FILTER_ACE_FLAG),
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

// Process trust types
// Source: https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/NtApiDotNet/NtSemaphore.cs
#define TT_None             0
#define TT_ProtectedLight   512
#define TT_Protected        1024

static TFlagInfo PsTrustTypes[] =
{
    FLAGINFO_NUMV(TT_None),
    FLAGINFO_NUMV(TT_ProtectedLight),
    FLAGINFO_NUMV(TT_Protected),
    FLAGINFO_END()
};

// Process trust levels
#define TL_None             0
#define TL_Authenticode     1024
#define TL_AntiMalware      1536
#define TL_App              2048
#define TL_Windows          4096
#define TL_WinTcb           8192

static TFlagInfo PsTrustLevels[] =
{
    FLAGINFO_NUMV(TL_None),
    FLAGINFO_NUMV(TL_Authenticode),
    FLAGINFO_NUMV(TL_AntiMalware),
    FLAGINFO_NUMV(TL_App),
    FLAGINFO_NUMV(TL_Windows),
    FLAGINFO_NUMV(TL_WinTcb),
    FLAGINFO_END()
};

static TFlagInfo CSA_ValTypes[] =
{
    FLAGINFO_NUMV(CLAIM_SECURITY_ATTRIBUTE_TYPE_INVALID),
    FLAGINFO_NUMV(CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64),
    FLAGINFO_NUMV(CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64),
    FLAGINFO_NUMV(CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING),
    FLAGINFO_NUMV(CLAIM_SECURITY_ATTRIBUTE_TYPE_FQBN),
    FLAGINFO_NUMV(CLAIM_SECURITY_ATTRIBUTE_TYPE_SID),
    FLAGINFO_NUMV(CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN),
    FLAGINFO_NUMV(CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING),
    FLAGINFO_END()
};

static TFlagInfo CSA_Flags[] =
{
    FLAGINFO_BITV(CLAIM_SECURITY_ATTRIBUTE_NON_INHERITABLE),
    FLAGINFO_BITV(CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE),
    FLAGINFO_BITV(CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY),
    FLAGINFO_BITV(CLAIM_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT),
    FLAGINFO_BITV(CLAIM_SECURITY_ATTRIBUTE_DISABLED),
    FLAGINFO_BITV(CLAIM_SECURITY_ATTRIBUTE_MANDATORY),
    FLAGINFO_END()
};

//-----------------------------------------------------------------------------
// Local functions

static void ReverseArrayItems(HTREEITEM array[], size_t length)
{
    size_t start = 0;
    size_t end = length - 1;

    while(start < end)
    {
        // Swap elements at start and end indices
        HTREEITEM temp = array[start];
        array[start] = array[end];
        array[end] = temp;

        // Move indices towards the center
        start++;
        end--;
    }
}


static PNON_EDITABLE_DATA IsItemDataPointer(PVOID ptr)
{
    if((UINT_PTR)(ptr) > 0x100)
    {
        if(((PNON_EDITABLE_DATA)(ptr))->Magic == ITEM_DATA_MAGIC)
        {
            return (PNON_EDITABLE_DATA)(ptr);
        }
    }
    return NULL;
}

static bool IsValidAceAttributeType(LPBYTE pbBuffer)
{
    WORD wValueType = *(PWORD)(pbBuffer);

    // Check valid values
    if(CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64 <= wValueType && wValueType <= CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING)
        return true;
    if(CLAIM_SECURITY_ATTRIBUTE_TYPE_SID <= wValueType && wValueType <= CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING)
        return true;
    return false;
}

static bool IsValidAceAttributeCount(LPBYTE pbBuffer)
{
    DWORD dwValueCount = *(PDWORD)(pbBuffer);

    // Artificially limited value count
    return (0 < dwValueCount && dwValueCount <= 100);
}

static bool IsItemTypeEditable(PTREE_ITEM_INFO pItemInfo)
{
    switch(pItemInfo->ItemType)
    {
        case ItemTypeAce:
        case ItemTypeCondition:
            return false;

        default:
            return true;
    }
}

static bool IsIntegerTypeWithFlags(PTREE_ITEM_INFO pItemInfo)
{
    int nItemType;

    if(pItemInfo->pFlagInfos != NULL)
    {
        nItemType = (int)pItemInfo->ItemType;
        return ((int)ItemTypeUint08 <= nItemType && nItemType <= (int)ItemTypeUint64);
    }
    return false;
}

static LPCSTR GetAceTypeString(DWORD AceType)
{
    static CHAR szBuffer[64];
    BYTE MaxAceType = (BYTE)(_countof(AceHdrTypes) - 1);

    // Insert the "root" item with ACE type
    if(AceType < MaxAceType)
        return AceHdrTypes[AceType].szFlagText;

    // Prepare string for an unknown ACE type
    StringCchPrintfA(szBuffer, _countof(szBuffer), szUnknownAceType, AceType);
    return szBuffer;
}

static bool GetAceTypeString(LPTSTR szBuffer, size_t ccBuffer, PACE_HEADER pAceHeader)
{
    LPCSTR szAceType = GetAceTypeString(pAceHeader->AceType);
    LPTSTR szSuffix;

    // Format the ACE type name
    StringCchPrintf(szBuffer, ccBuffer, _T("%hs"), szAceType);

    // Cut off the "_TYPE" suffix
    if((szSuffix = _tcsrchr(szBuffer, _T('_'))) != NULL)
    {
        if(!_tcscmp(szSuffix, szAceTypeSuffix))
        {
            szSuffix[0] = 0;
        }
    }
    return true;
}

static ULONG AceObjectGuidFlag(ITEM_TYPE ItemType)
{
    if(ItemType == ItemTypeGuid)
        return ACE_OBJECT_TYPE_PRESENT;
    if(ItemType == ItemTypeGuid2)
        return ACE_INHERITED_OBJECT_TYPE_PRESENT;
    return 0;
}

static ULONG AceObjectGuidPresent(PACE pAce, ITEM_TYPE ItemType)
{
    if(pAce != NULL)
    {
        ACE_HELPER AceHelper(pAce->Header.AceType);

        if(AceHelper.AceLayout & ACE_FIELD_GUID_FLAGS)
        {
            return (pAce->Flags & AceObjectGuidFlag(ItemType));
        }
    }
    return 0;
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

//
// The SID in the SYSTEM_MANDATORY_LABEL_ACE has the following format:
//
// - IdentifierAuthority is set to SECURITY_MANDATORY_LABEL_AUTHORITY
// - The last subauthority is set to one of the SECURITY_MANDATORY_XXXX values
//

static LPBYTE GetSystemSidIntegerValue(PSID pSid, PSID_IDENTIFIER_AUTHORITY pSiaExpected, UCHAR SubAuthCountNeeded = 1)
{
    UCHAR SubAuthCount;

    if(pSid != NULL && RtlLengthSid(pSid) > FIELD_OFFSET(SYSTEM_MANDATORY_LABEL_ACE, SidStart))
    {
        PSID_IDENTIFIER_AUTHORITY pSia = GetSidIdentifierAuthority(pSid);

        // Compare the required identifier authority
        if(!memcmp(pSia, pSiaExpected, sizeof(SID_IDENTIFIER_AUTHORITY)))
        {
            // Get the number of sub-authorities
            if((SubAuthCount = *GetSidSubAuthorityCount(pSid)) == SubAuthCountNeeded)
            {
                // Get the last authority
                return (LPBYTE)GetSidSubAuthority(pSid, 0);
            }
        }
    }

    // Return NULL
    assert(false);
    return NULL;
}

static LPBYTE GetSidIntegrityLevel(PSID pSid)
{
    return GetSystemSidIntegerValue(pSid, &SiaLabel);
}

static LPBYTE GetSidScopedPolicyId(PSID pSid)
{
    return GetSystemSidIntegerValue(pSid, &SiaPolicy);
}

static LPBYTE GetSidProcessTrustLevel(PSID pSid)
{
    return GetSystemSidIntegerValue(pSid, &SiaTrust, 2);
}

//-----------------------------------------------------------------------------
// Local functions - tree items

static DWORD GetDefaultAceTypeForAcl(PCTREE_ITEM_INFO pItemInfo)
{
    return (pItemInfo->ItemType == ItemTypeSacl) ? SYSTEM_MANDATORY_LABEL_ACE_TYPE : ACCESS_ALLOWED_ACE_TYPE;
}

static int GetDefaultCharLimit(PCTREE_ITEM_INFO pItemInfo)
{
    if(pItemInfo->ItemType == ItemTypeUint08 || pItemInfo->ItemType == ItemTypeAceType)
        return 8;
    if(pItemInfo->ItemType == ItemTypeUint16)
        return 16;
    if(pItemInfo->ItemType == ItemTypeUint32)
        return 32;
    if(pItemInfo->ItemType == ItemTypeUint64)
        return 64;
    return 256;
}

static void UpdateAceVariables(PACE pAce, LPBYTE pbPtr)
{
    if(pAce != NULL)
    {
        LPBYTE pbAce = (LPBYTE)(pAce);

        // Update the length of the ACE
        pAce->Header.AceSize = (WORD)(pbPtr - pbAce);

        // Update the ACL-in-work variables
        if(pAclInWork != NULL)
        {
            // If the ACE is of ACCESS_ALLOWED_COMPOUND_ACE_TYPE, the ACL revision must be 3 or higher
            if(pAce->Header.AceType == ACCESS_ALLOWED_COMPOUND_ACE_TYPE)
                pAclInWork->AclRevision = max(pAclInWork->AclRevision, ACL_REVISION3);

            // If the ACE is one of the object ACEs or later, raise the ACL revision
            if(pAce->Header.AceType >= ACCESS_ALLOWED_OBJECT_ACE_TYPE)
                pAclInWork->AclRevision = max(pAclInWork->AclRevision, ACL_REVISION_DS);

            // Update the ACE count
            pAclInWork->AceCount++;
        }
    }
}

// The item text is expected to be in format "Name: 0x12345678"
static LPTSTR GetItemTextValue(LPTSTR szItemText, bool bKeepQuotedPart = false)
{
    LPTSTR szStringEnd;
    LPTSTR szTextPtr;

    // Retrieve the first occurence of ":"
    if((szTextPtr = _tcschr(szItemText, _T(':'))) != NULL)
    {
        // Skip the colon
        szItemText = szTextPtr + 1;

        // Skip spaces
        while(szItemText[0] == ' ')
            szItemText++;

        // Did we come across a quotation mark?
        if(szItemText[0] == _T('\"'))
        {
            if((szStringEnd = _tcschr(szItemText + 1, _T('\"'))) > szItemText)
            {
                szStringEnd[0] = 0;
                szItemText += 1;
            }
        }

        // If the number is followed by a space, cut it
        if(bKeepQuotedPart == false)
        {
            if((szTextPtr = _tcschr(szItemText, _T(' '))) != NULL)
            {
                szTextPtr[0] = 0;
            }
        }
    }

    // Return the text
    return szItemText;
}

static bool TV_TextToEditText(const _TREE_ITEM_INFO * pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPCTSTR szItemText)
{
    LPCTSTR szTextValue;

    // Copy the entire text from the source to the target
    StringCchCopy(szBuffer, ccBuffer, szItemText);

    // Extract the text value from the item
    szTextValue = GetItemTextValue(szBuffer, (pItemInfo->ItemType == ItemTypeCondition));

    // Move the text value
    if(szTextValue > szBuffer)
        memmove(szBuffer, szTextValue, (_tcslen(szTextValue) + 1) * sizeof(TCHAR));
    return true;
}

static void TV_MakeItemText(
    PTREE_ITEM_INFO pItemInfo,
    LPTSTR szBuffer,
    size_t ccBuffer,
    LPBYTE pbPtr,
    LPBYTE pbEnd,
    PULONG pcbMoveBy = NULL)
{
    ULONG cbMoveBy = 0;
    TCHAR szDataText[0x400] = {0};
    UINT nIDFormat = pItemInfo->nIDFormat1;
    bool bApplyIndex = false;

    // Do we have data and format for it?
    if(pItemInfo->nIDFormat2)
    {
        if(pItemInfo->ToString != NULL)
        {
            // Format the numeric or whatever value
            if(NT_SUCCESS(pItemInfo->ToString(pItemInfo, szDataText, _countof(szDataText), pbPtr, pbEnd, &cbMoveBy)))
            {
                nIDFormat = pItemInfo->nIDFormat2;
                bApplyIndex = true;
            }
        }
    }

    // Finally, format the data to the item
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    
    // Format the final value
    if(GLOBAL_ItemIndex != INVALID_ITEM_INDEX && bApplyIndex)
        rsprintf(szBuffer, ccBuffer, nIDFormat, GLOBAL_ItemIndex, szDataText);
    else
        rsprintf(szBuffer, ccBuffer, nIDFormat, szDataText);
}

//-----------------------------------------------------------------------------
// Conversion of String <-> Integer Value (Hex)

template <typename INTEGER>
NTSTATUS ToString_Hex(PTREE_ITEM_INFO pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    ULONG64 dwIntValue = 0;

    // Capture the integer value
    if((pbPtr + sizeof(INTEGER)) > pbEnd)
        return STATUS_BUFFER_OVERFLOW;
    if(ccBuffer < (sizeof(INTEGER) * 2) + 1)
        return STATUS_BUFFER_OVERFLOW;
    dwIntValue = *(INTEGER *)(pbPtr);

    // Write the "0x" prefix
    StringCchCopyEx(szBuffer, ccBuffer, _T("0x"), &szBuffer, &ccBuffer, 0);

    // Convert to string
    Hex2TextXX(dwIntValue, szBuffer, sizeof(INTEGER));

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
        pcbMoveBy[0] = sizeof(INTEGER);
    return STATUS_SUCCESS;
}

template <typename INTEGER>
NTSTATUS StringTo_Hex(PTREE_ITEM_INFO /* pItemInfo */, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    LONGLONG dwIntValue;

    if((pbPtr + sizeof(INTEGER)) <= pbEnd)
    {
        if(Text2Hex64(szString, &dwIntValue) == ERROR_SUCCESS)
        {
            // Copy the integer
            *(INTEGER *)(pbPtr) = (INTEGER)(dwIntValue);

            // Give the pcbMoveBy
            if(pcbMoveBy != NULL)
                pcbMoveBy[0] = sizeof(INTEGER);
            return STATUS_SUCCESS;
        }
    }
    return STATUS_BUFFER_OVERFLOW;
}

static NTSTATUS ToString_Hex1(PTREE_ITEM_INFO pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    return ToString_Hex<BYTE>(pItemInfo, szBuffer, ccBuffer, pbPtr, pbEnd, pcbMoveBy);
}

static NTSTATUS StringTo_Hex1(PTREE_ITEM_INFO pItemInfo, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    return StringTo_Hex<BYTE>(pItemInfo, szString, pbPtr, pbEnd, pcbMoveBy);
}

static NTSTATUS ToString_Hex2(PTREE_ITEM_INFO pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    return ToString_Hex<WORD>(pItemInfo, szBuffer, ccBuffer, pbPtr, pbEnd, pcbMoveBy);
}

static NTSTATUS StringTo_Hex2(PTREE_ITEM_INFO pItemInfo, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    return StringTo_Hex<WORD>(pItemInfo, szString, pbPtr, pbEnd, pcbMoveBy);
}

static NTSTATUS ToString_Hex4(PTREE_ITEM_INFO pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    return ToString_Hex<DWORD>(pItemInfo, szBuffer, ccBuffer, pbPtr, pbEnd, pcbMoveBy);
}

static NTSTATUS StringTo_Hex4(PTREE_ITEM_INFO pItemInfo, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    return StringTo_Hex<DWORD>(pItemInfo, szString, pbPtr, pbEnd, pcbMoveBy);
}

static NTSTATUS ToString_Hex8(PTREE_ITEM_INFO pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    return ToString_Hex<DWORD64>(pItemInfo, szBuffer, ccBuffer, pbPtr, pbEnd, pcbMoveBy);
}

static NTSTATUS StringTo_Hex8(PTREE_ITEM_INFO pItemInfo, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    return StringTo_Hex<DWORD64>(pItemInfo, szString, pbPtr, pbEnd, pcbMoveBy);
}

// For fields that are auto-calculated, such as ACE_HEADER::AceSize
static NTSTATUS StringTo_Auto(PTREE_ITEM_INFO pItemInfo, LPCTSTR /* szString */, LPBYTE /* pbPtr */, LPBYTE /* pbEnd */, PULONG pcbMoveBy = NULL)
{
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = (pItemInfo->ItemType == ItemTypeUint16) ? sizeof(USHORT) : sizeof(DWORD);
    return (pAclInWork || pAceInWork) ? STATUS_SUCCESS : STATUS_AUTO_CALCULATED;
}

//-----------------------------------------------------------------------------
// Conversion of String <-> Trust Level

static bool ToString_TrustLevel(PTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    LPDWORD PtrTrustLevels = (LPDWORD)(pbPtr);
    LPTSTR szBuffEnd = szBuffer + ccBuffer - 1;
    ULONG cbMoveBy = 0;

    if((pbPtr + sizeof(DWORD64)) <= pbEnd)
    {
        // Write the 64-bit value
        StringCchPrintfEx(szBuffer, (szBuffEnd - szBuffer), &szBuffer, NULL, 0, _T("%x-%x "), PtrTrustLevels[0], PtrTrustLevels[1]);

        // Write the trust levels
        szBuffer = FlagsToString(PsTrustTypes, szBuffer, (szBuffEnd - szBuffer), *(LPDWORD)(pbPtr + 0));
        StringCchCatEx(szBuffer, (szBuffEnd - szBuffer), _T("/"), &szBuffer, NULL, 0);
        szBuffer = FlagsToString(PsTrustLevels, szBuffer, (szBuffEnd - szBuffer), *(LPDWORD)(pbPtr + 4));
        cbMoveBy = sizeof(DWORD64);
    }

    // Give the pcbMoveBy
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return (cbMoveBy != 0);
}

static NTSTATUS StringTo_TrustLevel(PTREE_ITEM_INFO /* pItemInfo */, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    LPTSTR szHiPart;
    LPTSTR szLoPart;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    DWORD TrustLevel[2];
    TCHAR szBuffer[0x40];

    if((pbPtr + sizeof(DWORD64)) <= pbEnd)
    {
        StringCchCopy(szBuffer, _countof(szBuffer), szString);
        szHiPart = szBuffer;
        if((szLoPart = _tcschr(szHiPart, _T('-'))) != NULL)
        {
            *szLoPart++ = 0;

            if(Text2Hex32(szHiPart, &TrustLevel[0]) == ERROR_SUCCESS &&
               Text2Hex32(szLoPart, &TrustLevel[1]) == ERROR_SUCCESS)
            {
                if(pcbMoveBy != NULL)
                    pcbMoveBy[0] = sizeof(DWORD64);
                memcpy(pbPtr, TrustLevel, sizeof(TrustLevel));
                Status = STATUS_SUCCESS;
            }
        }
    }
    return Status;
}

//-----------------------------------------------------------------------------
// Conversion of String <-> Binary Data: BOOL

static NTSTATUS ToString_Bool(PTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    if((pbPtr + sizeof(BYTE)) > pbEnd)
        return STATUS_BUFFER_OVERFLOW;
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = sizeof(BYTE);

    StringCchCopy(szBuffer, ccBuffer, pbPtr[0] ? _T("TRUE") : _T("FALSE"));
    return STATUS_SUCCESS;
}

static NTSTATUS StringTo_Bool(PTREE_ITEM_INFO pItemInfo, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    NTSTATUS Status;
    BYTE FalseValue = 0;
    BYTE TrueValue = 1;
    BYTE ItemValue[1];

    // Check for TRUE / FALSE
    if(!_tcsicmp(szString, _T("FALSE")) || !_tcsicmp(szString, _T("OFF")))
        return CopyDataAway(pbPtr, pbEnd, &FalseValue, sizeof(FalseValue), pcbMoveBy);
    if(!_tcsicmp(szString, _T("TRUE")) || !_tcsicmp(szString, _T("ON")))
        return CopyDataAway(pbPtr, pbEnd, &TrueValue, sizeof(TrueValue), pcbMoveBy);

    // Try numeric value. If nonzero, it's TRUE, if not, it's FALSE
    if((Status = StringTo_Hex1(pItemInfo, szString, &ItemValue[0], &ItemValue[1])) == STATUS_SUCCESS)
    {
        if(ItemValue[0] == 0)
            return CopyDataAway(pbPtr, pbEnd, &FalseValue, sizeof(FalseValue), pcbMoveBy);
        else
            return CopyDataAway(pbPtr, pbEnd, &TrueValue, sizeof(TrueValue), pcbMoveBy);
    }
    return Status;
}

//-----------------------------------------------------------------------------
// Conversion of LPWSTR to string

static NTSTATUS ToString_STR(PTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE /* pbEnd */, PULONG pcbMoveBy = NULL)
{
    LPWSTR szString = (LPWSTR)(pbPtr);

    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = (ULONG)((wcslen(szString) + 1) * sizeof(WCHAR));
    StringCchPrintf(szBuffer, ccBuffer, _T("\"%s\""), szString);
    return STATUS_SUCCESS;
}

static NTSTATUS StringTo_STR(PTREE_ITEM_INFO /* pItemInfo */, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    ULONG cbString = (ULONG)((wcslen(szString) + 1) * sizeof(WCHAR));

    return CopyDataAway(pbPtr, pbEnd, szString, cbString, pcbMoveBy);
}

//-----------------------------------------------------------------------------
// Conversion of String <-> Binary Data: SID

static TREE_ITEM_INFO ItemType_IntLevel = {ItemTypeUint32,  0, IDS_FORMAT_INT_LEVEL, IntgrLevels};
static TREE_ITEM_INFO ItemType_PolicyId = {ItemTypeUint32,  0, IDS_FORMAT_POLICY_ID};
static TREE_ITEM_INFO ItemType_TrustLev = {ItemTypeUint64,  0, IDS_FORMAT_TRUST_LEVEL};

static NTSTATUS ToString_Sid(PTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG cbMoveBy = 0;

    // If there is a SID, format it to the buffer
    if(pbPtr != NULL)
    {
        if((pbPtr + 8) <= pbEnd)
        {
            PSID_IDENTIFIER_AUTHORITY pSia;
            LPBYTE pbIntValue;
            PSID pSid = (PSID)(pbPtr);

            // Determine the SID type by the authority
            pSia = GetSidIdentifierAuthority(pSid);

            // Is it a mandatory label?
            if(!memcmp(pSia, &SiaLabel, sizeof(SID_IDENTIFIER_AUTHORITY)))
            {
                if((pbIntValue = GetSidIntegrityLevel(pSid)) != NULL)
                    ToString_Hex4(&ItemType_IntLevel, szBuffer, ccBuffer, pbIntValue, pbIntValue + sizeof(DWORD));
                cbMoveBy = RtlLengthSid(pSid);
            }
            else if(!memcmp(pSia, &SiaPolicy, sizeof(SID_IDENTIFIER_AUTHORITY)))
            {
                if((pbIntValue = GetSidScopedPolicyId(pSid)) != NULL)
                    ToString_Hex4(&ItemType_PolicyId, szBuffer, ccBuffer, pbIntValue, pbIntValue + sizeof(DWORD));
                cbMoveBy = RtlLengthSid(pSid);
            }
            else if(!memcmp(pSia, &SiaTrust, sizeof(SID_IDENTIFIER_AUTHORITY)))
            {
                if((pbIntValue = GetSidProcessTrustLevel(pSid)) != NULL)
                    ToString_TrustLevel(&ItemType_TrustLev, szBuffer, ccBuffer, pbIntValue, pbIntValue + sizeof(ULONG64));
                cbMoveBy = RtlLengthSid(pSid);
            }
            else
            {
                SidToString(pSid, szBuffer, ccBuffer, true);
                cbMoveBy = RtlLengthSid(pSid);
            }
        }
        else
        {
            Status = STATUS_INVALID_PARAMETER;
        }
    }
    else
    {
        rsprintf(szBuffer, ccBuffer, IDS_NOT_PRESENT);
    }

    // Give the length to move
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return Status;
}

static NTSTATUS StringTo_Sid19(PTREE_ITEM_INFO /* pItemInfo */, LPCTSTR szText, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    NTSTATUS Status;
    LPBYTE pbIntegerValue;

    // Try to convert a trust level value
    if((Status = CopyDataAway(pbPtr, pbEnd, SidSystemAce19, sizeof(SidSystemAce19), pcbMoveBy)) == STATUS_SUCCESS)
    {
        if((pbIntegerValue = GetSystemSidIntegerValue((PSID)(pbPtr), &SiaTrust, 2)) != NULL)
        {
            // Convert the trust level to binary value.
            Status = StringTo_TrustLevel(&ItemType_TrustLev, szText, pbIntegerValue, pbIntegerValue + sizeof(DWORD64));
        }
    }
    return Status;
}

static NTSTATUS StringTo_Sid(PTREE_ITEM_INFO pItemInfo, LPCTSTR szText, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    SID_NAME_USE SidNameUse;
    NTSTATUS Status = STATUS_INVALID_PARAMETER;
    LPBYTE pbIntegerValue;
    TCHAR szDomainName[256];
    DWORD ccDomainName = _countof(szDomainName);
    DWORD cbSid = (ULONG)(pbEnd - pbPtr);
    PSID pSid = NULL;
    WORD AceFlags = 0;

    // Mandatory SIDs have just integrity level
    if(pItemInfo->ItemType == ItemTypeSid11)
    {
        // Copy the default SID to the buffer
        if((Status = CopyDataAway(pbPtr, pbEnd, SidLabelMedium, sizeof(SidLabelMedium), pcbMoveBy)) == STATUS_SUCCESS)
        {
            if((pbIntegerValue = GetSystemSidIntegerValue((PSID)(pbPtr), &SiaLabel)) != NULL)
            {
                Status = StringTo_Hex4(&ItemType_IntLevel, szText, pbIntegerValue, pbIntegerValue + sizeof(ULONG));
            }
        }
        return Status;
    }

    // Policy SIDs have just policy ID
    if(pItemInfo->ItemType == ItemTypeSid17)
    {
        // Copy the default SID to the buffer
        if((Status = CopyDataAway(pbPtr, pbEnd, SidSystemAce17, sizeof(SidSystemAce17), pcbMoveBy)) == STATUS_SUCCESS)
        {
            if((pbIntegerValue = GetSystemSidIntegerValue((PSID)(pbPtr), &SiaPolicy)) != NULL)
            {
                Status = StringTo_Hex4(&ItemType_PolicyId, szText, pbIntegerValue, pbIntegerValue + sizeof(ULONG));
            }
        }
        return Status;
    }

    // Trust level SID: 64-bit trust level present in the sub-authorities
    if(pItemInfo->ItemType == ItemTypeSid19)
    {
        return StringTo_Sid19(pItemInfo, szText, pbPtr, pbEnd, pcbMoveBy);
    }

    // Trust level SIDs have 64-bit trust level
    if(pItemInfo->ItemType == ItemTypeSid19e)
    {
        // Try to convert a trust level SID
        if((Status = StringTo_Sid19(pItemInfo, szText, pbPtr, pbEnd, pcbMoveBy)) != STATUS_SUCCESS)
        {
            TREE_ITEM_INFO TreeItem_NormalSid = {ItemTypeSid, IDS_NOT_PRESENT, IDS_FORMAT_SID, NULL, ToString_Sid, StringTo_Sid};

            if((Status = StringTo_Sid(&TreeItem_NormalSid, szText, pbPtr, pbEnd, pcbMoveBy)) == STATUS_SUCCESS)
            {
                AceFlags = 0;
            }
        }
        else
        {
            AceFlags = TRUST_PROTECTED_FILTER_ACE_FLAG;
        }

        // We also need to set the flags in the ACE header
        if(NT_SUCCESS(Status) && (pAceInWork != NULL) && (pAceInWork->Header.AceType == SYSTEM_ACCESS_FILTER_ACE_TYPE))
            pAceInWork->Header.AceFlags |= AceFlags;
        return Status;
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
                    Status = CopyDataAway(pbPtr, pbEnd, pSid, cbSid, pcbMoveBy);
                    LocalFree(pSid);
                    return Status;
                }
            }
        }
    }

    // Convert the account name to SID
    if(LookupAccountName(NULL, szText, (PSID)(pbPtr), &cbSid, szDomainName, &ccDomainName, &SidNameUse))
    {
        if(pcbMoveBy != NULL)
            pcbMoveBy[0] = cbSid;
        Status = STATUS_SUCCESS;
    }
    return Status;
}

static NTSTATUS CreateNew_Sid(PTREE_ITEM_INFO /* pItemInfo */, LPBYTE pbDataBuffer, size_t * pcbDataBuffer)
{
    PSID pSid;
    size_t cbDataBuffer = pcbDataBuffer[0];
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    // Create new SID
    if((pSid = ACE_HELPER::GetDefaultSid()) != NULL)
    {
        ULONG cbSid = RtlLengthSid(pSid);

        if(pcbDataBuffer != NULL)
            pcbDataBuffer[0] = cbSid;
        Status = CopyDataAway(pbDataBuffer, pbDataBuffer + cbDataBuffer, pSid, cbSid);
    }
    return Status;
}

//-----------------------------------------------------------------------------
// Conversion of String <-> Binary Data: GUID

// Get GUID from object-based ACEs, like ACCESS_ALLOWED_OBJECT_ACE
// * ACCESS_ALLOWED_OBJECT_ACE::ObjectType is only present if ACE_OBJECT_TYPE_PRESENT
// * ACCESS_ALLOWED_OBJECT_ACE::InheritedObjectType is only present if ACE_INHERITED_OBJECT_TYPE_PRESENT
static NTSTATUS ToString_Guid(PTREE_ITEM_INFO pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    NTSTATUS Status = STATUS_BUFFER_OVERFLOW;
    ULONG cbMoveBy = 0;

    // Only present if the appropriate GUID flag is present in the ACE
    if(AceObjectGuidPresent(pAceInWork, pItemInfo->ItemType))
    {
        if((pbPtr + sizeof(GUID)) <= pbEnd)
        {
            GuidToString((LPGUID)(pbPtr), szBuffer, ccBuffer);
            cbMoveBy = sizeof(GUID);
            Status = STATUS_SUCCESS;
        }
    }
    else
    {
        StringCchCopy(szBuffer, ccBuffer, szNoGuidString);
        Status = STATUS_SUCCESS;
    }

    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return Status;
}

static NTSTATUS StringTo_Guid(PTREE_ITEM_INFO pItemInfo, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    NTSTATUS Status = STATUS_BUFFER_OVERFLOW;
    DWORD dwFlagToModify = 0;
    ULONG cbMoveBy = 0;

    // Check for free space
    if((pbPtr + sizeof(GUID)) <= pbEnd)
    {
        // Try to convert the GUID. Anything unconverted is considered as no GUID
        if(StringToGuid(szString, (LPGUID)(pbPtr)))
            cbMoveBy = sizeof(GUID);
        Status = STATUS_SUCCESS;

        // Modify the flags in the ACE
        if(pAceInWork != NULL)
        {
            // Determine the modify flag
            dwFlagToModify = (pItemInfo->ItemType == ItemTypeGuid) ? ACE_OBJECT_TYPE_PRESENT : ACE_INHERITED_OBJECT_TYPE_PRESENT;
            pAceInWork->Flags = cbMoveBy ? (pAceInWork->Flags | dwFlagToModify) : (pAceInWork->Flags & ~dwFlagToModify);
        }
    }

    // Give the pcbMoveBy
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return Status;
}

//-----------------------------------------------------------------------------
// Conversion of SID preceded by 32-bit integer, containing length

static NTSTATUS ToString_SidN(PTREE_ITEM_INFO pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    NTSTATUS Status = STATUS_BUFFER_OVERFLOW;
    ULONG cbLength = 0;

    // Enough data to cover 32-bit int?
    if((pbPtr + sizeof(ULONG)) <= pbEnd)
    {
        // Copy the length
        memcpy(&cbLength, pbPtr, sizeof(ULONG));
        pbPtr += sizeof(ULONG);

        // Give the result to the caller
        if(pcbMoveBy != NULL)
            pcbMoveBy[0] = sizeof(ULONG) + cbLength;
        Status = ToString_Sid(pItemInfo, szBuffer, ccBuffer, pbPtr, pbPtr + cbLength);

    }
    return Status;
}

static NTSTATUS StringTo_SidN(PTREE_ITEM_INFO pItemInfo, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    NTSTATUS Status;
    ULONG cbMoveBy = 0;

    // Convert the string-SID to binary SID
    Status = StringTo_Sid(pItemInfo, szString, pbPtr + sizeof(ULONG), pbEnd, &cbMoveBy);
    if(NT_SUCCESS(Status))
    {
        // Supply the length of the SID
        if(pcbMoveBy != NULL)
            pcbMoveBy[0] = cbMoveBy + sizeof(ULONG);
        *(PULONG)(pbPtr) = RtlLengthSid(pbPtr + sizeof(ULONG));
    }
    return Status;
}

//-----------------------------------------------------------------------------
// Conversion of OCTET_STRING preceded by 32-bit integer, containing length

static NTSTATUS ToString_BinN(PTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    PACE_OCTET_STRING pOctetString = (PACE_OCTET_STRING)(pbPtr);
    LPTSTR szBufferEnd;

    // Can a length be there?
    if((pbPtr + sizeof(ULONG)) <= pbEnd)
    {
        // Can the whole octet string be there?
        if((pbPtr + sizeof(ULONG) + pOctetString->cbData) <= pbEnd)
        {
            // Set the string range
            pbPtr = pOctetString->pbData;
            pbEnd = pbPtr + pOctetString->cbData;
            szBufferEnd = szBuffer + ccBuffer - 1;

            // Format the binary data into a spaced string
            while(pbPtr < pbEnd && (szBuffer + 3) < szBufferEnd)
            {
                szBuffer[0] = HexaAlphabetUpper[pbPtr[0] >> 0x04];
                szBuffer[1] = HexaAlphabetUpper[pbPtr[0] & 0x0F];
                szBuffer += 2;
                pbPtr++;
            }
            szBuffer[0] = 0;

            // Give the result to the caller
            if(pcbMoveBy != NULL)
                pcbMoveBy[0] = OctetStringSize(pOctetString);
            return STATUS_SUCCESS;
        }
    }
    return STATUS_BUFFER_OVERFLOW;
}

static NTSTATUS StringTo_BinN(PTREE_ITEM_INFO /* pItemInfo */, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    LPBYTE pbBin = pbPtr + sizeof(ULONG);
    size_t cbBin = 0;
    DWORD dwErrCode;
    ULONG cbMoveBy;

    // Convert the string-SID to binary SID
    if((dwErrCode = StringToBinary(szString, pbBin, (pbEnd - pbBin), &cbBin)) != ERROR_SUCCESS)
        return STATUS_BAD_DATA;
    cbMoveBy = (ULONG)(cbBin);

    // Supply the length of the octet string
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy + sizeof(ULONG);
    *(PULONG)(pbPtr) = cbMoveBy;
    return STATUS_SUCCESS;
}

//-----------------------------------------------------------------------------
// Conversion of ACE type (string like "ACCESS_ALLOWED_ACE_TYPE")

static NTSTATUS ToString_Ace(PTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    PACE_HEADER pAceHeader = (PACE_HEADER)(pbPtr);
    ULONG cbMoveBy = 0;

    if((pbPtr + sizeof(ACE_HEADER)) < pbEnd)
    {
        GetAceTypeString(szBuffer, ccBuffer, (PACE_HEADER)(pbPtr));
        cbMoveBy = pAceHeader->AceSize;
    }
    else
    {
        LoadString(g_hInst, IDS_NOT_PRESENT, szBuffer, (int)(ccBuffer));
    }

    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return STATUS_SUCCESS;
}

static NTSTATUS StringTo_Ace(PTREE_ITEM_INFO /* pItemInfo */, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    LPTSTR szEndPtr = NULL;
    size_t nLength = _tcslen(szString);
    DWORD dwAceType;
    char szAceType[256];

    // Prepare ANSI verison of the ACE type
    StringCchCopyX(szAceType, _countof(szAceType), szString);

    // Parse all ACE types
    for(size_t i = 0; AceHdrTypes[i].szFlagText != NULL; i++)
    {
        if(!_strnicmp(szAceType, AceHdrTypes[i].szFlagText, nLength))
        {
            if(AceHdrTypes[i].szFlagText[nLength] == 0 || AceHdrTypes[i].szFlagText[nLength] == '_')
            {
                BYTE AceType = (BYTE)(i);

                return CopyDataAway(pbPtr, pbEnd, &AceType, sizeof(AceType), pcbMoveBy);
            }
        }
    }

    // An unknown ACE type: "UNKNOWN_ACE_TYPE: %02x"
    dwAceType = _tcstoul(szString, &szEndPtr, 16);
    if(dwAceType <= 0xFF && szEndPtr[0] == 0)
    {   
        BYTE AceType = (BYTE)(dwAceType);
        return CopyDataAway(pbPtr, pbEnd, &AceType, sizeof(AceType), pcbMoveBy);
    }
    return STATUS_INVALID_PARAMETER;
}

//-----------------------------------------------------------------------------
// Conversion of binary condition to string

static NTSTATUS ToString_Cond(PTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    NTSTATUS Status = STATUS_BUFFER_OVERFLOW;
    ULONG cbMoveBy = 0;

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
            Status = STATUS_SUCCESS;
        }
    }
    else
    {
        LoadString(g_hInst, IDS_EMPTY_STREAM, szBuffer, (int)(ccBuffer));
        Status = STATUS_SUCCESS;
    }

    // Give the length to move
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return Status;
}

static NTSTATUS StringTo_Saved(PTREE_ITEM_INFO pItemInfo, LPCTSTR /* szText */, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    PNON_EDITABLE_DATA pData;

    // Did we store the raw condition?
    if((pData = IsItemDataPointer(pItemInfo->ItemData)) != NULL)
    {
        if((pbPtr + pData->Length) <= pbEnd)
        {
            return CopyDataAway(pbPtr, pbEnd, pData->Data, pData->Length, pcbMoveBy);
        }
        return STATUS_SUCCESS;
    }
    return STATUS_BAD_DATA;
}

static NTSTATUS CreateNew_Acl(PTREE_ITEM_INFO pItemInfo, LPBYTE pbDataBuffer, size_t * pcbDataBuffer)
{
    LPBYTE pbEnd = pbDataBuffer + pcbDataBuffer[0];
    LPBYTE pbPtr = pbDataBuffer;

    // Pre-fill the entire buffer with zeros
    memset(pbPtr, 0, (pbEnd - pbPtr));

    // Create the ACL header
    if((pbPtr + sizeof(ACL)) <= pbEnd)
    {
        PACE_HEADER pAceHeader;
        DWORD dwAceType = GetDefaultAceTypeForAcl(pItemInfo);
        PACL pAcl = (PACL)(pbPtr);

        // Fill-in the ACL header
        pAcl->AclRevision = ACL_REVISION_DS;
        pAcl->AclSize = (WORD)(pcbDataBuffer[0]);
        pbPtr += sizeof(ACL);

        // Create an ACE and imprint it into the ACL
        if((pAceHeader = ACE_HELPER(dwAceType).AddToAcl(pAcl)) != NULL)
        {
            pcbDataBuffer[0] = pAcl->AclSize = (WORD)(pbPtr + pAceHeader->AceSize - pbDataBuffer);
            pAcl->AceCount++;
        }
        return STATUS_SUCCESS;
    }
    return STATUS_BUFFER_OVERFLOW;
}

static TREE_ITEM_INFO TreeItem_Owner    = {ItemTypeOwner,     IDS_OWNER_SECURITY_INFORMATION};
static TREE_ITEM_INFO TreeItem_Group    = {ItemTypeGroup,     IDS_GROUP_SECURITY_INFORMATION};
static TREE_ITEM_INFO TreeItem_Dacl     = {ItemTypeDacl,      IDS_DACL_SECURITY_INFORMATION};
static TREE_ITEM_INFO TreeItem_Sacl     = {ItemTypeSacl,      IDS_SACL_SECURITY_INFORMATION};
static TREE_ITEM_INFO TreeItem_NullAcl  = {ItemTypeNullAcl,   IDS_NULL_ACL,     IDS_FORMAT_STR,       NULL,        NULL,          NULL,         CreateNew_Acl};
static TREE_ITEM_INFO TreeItem_NoAcl    = {ItemTypeNoAcl,     IDS_NOT_PRESENT,  IDS_FORMAT_STR,       NULL,        NULL,          NULL,         CreateNew_Acl};
static TREE_ITEM_INFO TreeItem_UserSid  = {ItemTypeSid,       IDS_NOT_PRESENT,  IDS_FORMAT_SID,       NULL,        ToString_Sid,  StringTo_Sid, CreateNew_Sid};
static TREE_ITEM_INFO TreeItem_AclRev   = {ItemTypeUint08,    0,                IDS_FORMAT_ACL_REVIS, AclRevFlags, ToString_Hex1, StringTo_Hex1};
static TREE_ITEM_INFO TreeItem_AclSbz1  = {ItemTypeUint08,    0,                IDS_FORMAT_ACL_SBZ1,  NULL,        ToString_Hex1, StringTo_Hex1};
static TREE_ITEM_INFO TreeItem_AclSize  = {ItemTypeUint16,    0,                IDS_FORMAT_ACL_SIZE,  NULL,        ToString_Hex2, StringTo_Auto};
static TREE_ITEM_INFO TreeItem_AceCnt   = {ItemTypeUint16,    0,                IDS_FORMAT_ACL_COUNT, NULL,        ToString_Hex2, StringTo_Auto};
static TREE_ITEM_INFO TreeItem_AclSbz2  = {ItemTypeUint16,    0,                IDS_FORMAT_ACL_SBZ2,  NULL,        ToString_Hex2, StringTo_Hex2};
static TREE_ITEM_INFO TreeItem_Ace      = {ItemTypeAce,       IDS_NULL_ACL,     IDS_FORMAT_STR,       NULL,        ToString_Ace,  StringTo_Ace};

static TREE_ITEM_INFO TreeItem_CSA_Name = {ItemTypeLPWSTR,    0,                IDS_FORMAT_NAME,      NULL,        ToString_STR,  StringTo_STR};
static TREE_ITEM_INFO TreeItem_CSA_VTyp = {ItemTypeCSA_VType, 0,                IDS_FORMAT_VALTYPE,   CSA_ValTypes,ToString_Hex2, StringTo_Hex2};
static TREE_ITEM_INFO TreeItem_CSA_Res  = {ItemTypeUint16,    0,                IDS_FORMAT_RESERVED,  NULL,        ToString_Hex2, StringTo_Hex2};
static TREE_ITEM_INFO TreeItem_CSA_Flgs = {ItemTypeUint32,    0,                IDS_FORMAT_FLAGS,     CSA_Flags,   ToString_Hex4, StringTo_Hex4};
static TREE_ITEM_INFO TreeItem_CSA_VCnt = {ItemTypeCSA_VCnt,  0,                IDS_FORMAT_VALCOUNT,  NULL,        ToString_Hex4, StringTo_Hex4};
static TREE_ITEM_INFO TreeItem_CSA_U64  = {ItemTypeUint64,    IDS_FORMAT_VALUE, IDS_FORMAT_VALINDEX,  NULL,        ToString_Hex8, StringTo_Hex8};
static TREE_ITEM_INFO TreeItem_CSA_STR  = {ItemTypeLPWSTR,    IDS_FORMAT_VALUE, IDS_FORMAT_VALINDEX,  NULL,        ToString_STR,  StringTo_STR};
static TREE_ITEM_INFO TreeItem_CSA_SidN = {ItemTypeSidN,      IDS_FORMAT_VALUE, IDS_FORMAT_VALINDEX,  NULL,        ToString_SidN, StringTo_SidN};
static TREE_ITEM_INFO TreeItem_CSA_BOOL = {ItemTypeBool,      IDS_FORMAT_VALUE, IDS_FORMAT_VALINDEX,  NULL,        ToString_Bool, StringTo_Bool};
static TREE_ITEM_INFO TreeItem_CSA_BinN = {ItemTypeBinN,      IDS_FORMAT_VALUE, IDS_FORMAT_VALINDEX,  NULL,        ToString_BinN, StringTo_BinN};


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
    {ACE_FIELD_HTYPE,           {ItemTypeAceType,   0, IDS_FORMAT_ACE_HTYPE,  AceHdrTypes, ToString_Hex1, StringTo_Hex1}},
    {ACE_FIELD_HFLAGS,          {ItemTypeUint08,    0, IDS_FORMAT_ACE_HFLAGS, AceHdrFlags, ToString_Hex1, StringTo_Hex1}},
    {ACE_FIELD_HFLAGS2,         {ItemTypeUint08,    0, IDS_FORMAT_ACE_HFLAGS, AceHdrFlags2,ToString_Hex1, StringTo_Hex1}},
    {ACE_FIELD_HSIZE,           {ItemTypeUint16,    0, IDS_FORMAT_ACE_HSIZE,  NULL,        ToString_Hex2, StringTo_Auto}},
    {ACE_FIELD_ACCESS_MASK,     {ItemTypeUint32,    0, IDS_FORMAT_ACE_MASK,   AceMasks,    ToString_Hex4, StringTo_Hex4}},
    {ACE_FIELD_ADS_ACCESS_MASK, {ItemTypeUint32,    0, IDS_FORMAT_ACE_MASK,   AdsAceMasks, ToString_Hex4, StringTo_Hex4}},
    {ACE_FIELD_MANDATORY_MASK,  {ItemTypeUint32,    0, IDS_FORMAT_ACE_MASK,   LabelMasks,  ToString_Hex4, StringTo_Hex4}},
    {ACE_FIELD_GUID_FLAGS,      {ItemTypeUint32,    0, IDS_FORMAT_ACE_FLAGS,  ObjAceFlags, ToString_Hex4, StringTo_Auto}},
    {ACE_FIELD_COMPOUND_TYPE,   {ItemTypeUint16,    0, IDS_FORMAT_ACE_CTYPE,  CAceTypes,   ToString_Hex2, StringTo_Hex2}},
    {ACE_FIELD_COMPOUND_RSVD,   {ItemTypeUint16,    0, IDS_FORMAT_RESERVED,   NULL,        ToString_Hex2, StringTo_Hex2}},
    {ACE_FIELD_OBJECT_TYPE1,    {ItemTypeGuid,      0, IDS_FORMAT_OBJ_TYPE,   NULL,        ToString_Guid, StringTo_Guid}},
    {ACE_FIELD_OBJECT_TYPE2,    {ItemTypeGuid2,     0, IDS_FORMAT_OBJ_TYPEI,  NULL,        ToString_Guid, StringTo_Guid}},
    {ACE_FIELD_SID,             {ItemTypeSid,       0, IDS_FORMAT_SID,        NULL,        ToString_Sid,  StringTo_Sid}},
    {ACE_FIELD_CLIENT_SID,      {ItemTypeSid,       0, IDS_FORMAT_CSID,       NULL,        ToString_Sid,  StringTo_Sid}},
    {ACE_FIELD_MANDATORY_SID,   {ItemTypeSid11,     0, IDS_FORMAT_INT_LEVEL,  IntgrLevels, ToString_Sid,  StringTo_Sid}},
    {ACE_FIELD_POLICY_SID,      {ItemTypeSid17,     0, IDS_FORMAT_POLICY_ID,  NULL,        ToString_Sid,  StringTo_Sid}},
    {ACE_FIELD_TRUST_SID,       {ItemTypeSid19,     0, IDS_FORMAT_TRUST_LEVEL,NULL,        ToString_Sid,  StringTo_Sid}},
    {ACE_FIELD_CSA_V1,          {ItemTypeCSA_V1,    IDS_FORMAT_CSA_V1}},
    {ACE_FIELD_CONDITION,       {ItemTypeCondition, 0, IDS_FORMAT_CONDITION,  NULL,        ToString_Cond, StringTo_Saved}}
};

//-----------------------------------------------------------------------------
// Inserting items

static PTREE_ITEM_INFO TV_GetItemParam(HWND hWndTree, HTREEITEM hItem)
{
    return (PTREE_ITEM_INFO)TreeView_GetItemParam(hWndTree, hItem);
}

static PTREE_ITEM_INFO TV_GetItemParamAndText(HWND hWndTree, HTREEITEM hItem, LPTSTR szBuffer, int ccBuffer)
{
    TVITEM tvi = {TVIF_TEXT | TVIF_PARAM};

    // Get the item text and item param
    tvi.hItem = hItem;
    tvi.pszText = szBuffer;
    tvi.cchTextMax = ccBuffer;
    TreeView_GetItem(hWndTree, &tvi);

    // Return the item param
    return (PTREE_ITEM_INFO)(tvi.lParam);
}

static bool TV_IsSecurityAttributes(HWND hWndTree, HTREEITEM hItem)
{
    PTREE_ITEM_INFO pItemInfo = TV_GetItemParam(hWndTree, hItem);

    return ((pItemInfo = TV_GetItemParam(hWndTree, hItem)) != NULL && pItemInfo->ItemType == ItemTypeCSA_V1);
}

static DWORD TV_GetRemainingItemCount(HWND hWndTree, HTREEITEM hItem)
{
    DWORD ValueCount = 0;

    while(hItem != NULL)
    {
        ValueCount++;
        hItem = TreeView_GetNextSibling(hWndTree, hItem);
    }
    return ValueCount;
}

static bool TV_SaveSelection(HWND hWndTree, TV_SELECTION & tvs)
{
    HTREEITEM ItemChain[MAX_NEST_LEVEL] = {0};
    HTREEITEM hSelected = TreeView_GetSelection(hWndTree);
    HTREEITEM hParent = TVI_ROOT;
    HTREEITEM hItem = hSelected;
    size_t nIndex = 0;

    // Reset the selection structure
    memset(&tvs, 0, sizeof(TV_SELECTION));
    tvs.nNestLevel = 0;

    // Get the chain up to the root item
    while(hItem != NULL)
    {
        if(tvs.nNestLevel >= _countof(ItemChain))
            return false;
        ItemChain[tvs.nNestLevel++] = hItem;
        hItem = TreeView_GetParent(hWndTree, hItem);
    }

    // Reverse the array
    ReverseArrayItems(ItemChain, tvs.nNestLevel);

    // Search the multi-level tree view
    for(size_t nLevel = 0; nLevel < tvs.nNestLevel; nLevel++)
    {
        // Retriueve the first item of that level
        if((hItem = TreeView_GetChild(hWndTree, hParent)) == NULL)
            return false;
        nIndex = 0;

        // Enumerate all next items
        while(hItem != ItemChain[nLevel])
        {
            if((hItem = TreeView_GetNextSibling(hWndTree, hItem)) == NULL)
                return false;
            nIndex++;
        }

        // Remember the item count of that level
        tvs.ItemIndex[nLevel] = nIndex;
        hParent = hItem;
    }
    return true;
}

static bool TV_RestoreSelection(HWND hWndTree, TV_SELECTION & tvs, HTREEITEM hDefItem)
{
    HTREEITEM hParent = TVI_ROOT;
    HTREEITEM hItem = NULL;

    for(size_t nLevel = 0; nLevel < tvs.nNestLevel; nLevel++)
    {
        hItem = TreeView_GetChild(hWndTree, hParent);
        for(size_t nIndex = 0; nIndex < tvs.ItemIndex[nLevel]; )
        {
            if((hItem = TreeView_GetNextSibling(hWndTree, hItem)) == NULL)
                return false;
            nIndex++;
        }
        hParent = hItem;
    }

    // Return the found item
    TreeView_SelectItem(hWndTree, (hItem != NULL) ? hItem : hDefItem);
    return true;
}

static size_t TV_GetAceResourceValueIndex(LPNMTVDISPINFO pTVDispInfo)
{
    PTREE_ITEM_INFO pItemInfo;
    HTREEITEM hParent;
    HTREEITEM hFocus = pTVDispInfo->item.hItem;
    HTREEITEM hItem;
    size_t nIndex = 0;
    HWND hWndTree = pTVDispInfo->hdr.hwndFrom;

    // Retrieve the parent item and the first child
    if((hParent = TreeView_GetParent(hWndTree, hFocus)) != NULL)
    {
        if((pItemInfo = TV_GetItemParam(hWndTree, hParent)) != NULL)
        {
            if(pItemInfo->ItemType == ItemTypeCSA_V1)
            {
                // Retrieve the first child item and iterate over item
                hItem = TreeView_GetChild(hWndTree, hParent);
                while(hItem != NULL)
                {
                    // If we found the n-th sub item, return its index
                    if(hItem == hFocus)
                    {
                        return (nIndex >= 5) ? (nIndex - 5) : INVALID_ITEM_INDEX;
                    }

                    // Move to the next sub item
                    hItem = TreeView_GetNextSibling(hWndTree, hItem);
                    nIndex++;
                }
            }
        }
    }
    return INVALID_ITEM_INDEX;
}

static void TV_AllocateItemData(HWND hWndTree, HTREEITEM hItem, LPBYTE pbPtr, LPBYTE pbEnd)
{
    PNON_EDITABLE_DATA pData;
    PTREE_ITEM_INFO pItemInfo;
    size_t Length = (pbEnd - pbPtr) + sizeof(NON_EDITABLE_DATA);

    if((pItemInfo = TV_GetItemParam(hWndTree, hItem)) != NULL)
    {
        // There must be no data yet
        assert(pItemInfo->ItemData == ItemDataNULL || pItemInfo->ItemData == ItemDataValid);

        // Are there data of non-zero length?
        if(pbEnd > pbPtr)
        {
            if((pData = (PNON_EDITABLE_DATA)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, Length)) != NULL)
            {
                pData->Magic = ITEM_DATA_MAGIC;
                pData->Length = (ULONG)(pbEnd - pbPtr);
                memcpy(pData->Data, pbPtr, pbEnd - pbPtr);
            }
            pItemInfo->ItemData = pData;
        }
    }
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
    TCHAR szItemText[MAX_ITEM_TEXT];
    ULONG cbMoveBy = 0;

    // Create copy of the item info structure
    if((pNewInfo = (PTREE_ITEM_INFO)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, sizeof(TREE_ITEM_INFO))) != NULL)
    {
        // Copy the item data
        memcpy(pNewInfo, pItemInfo, sizeof(TREE_ITEM_INFO));
        pNewInfo->ItemData = (pbPtr && pbEnd > pbPtr) ? ItemDataValid : ItemDataNULL;

        // Prepare the item text
        TV_MakeItemText(pNewInfo, szItemText, _countof(szItemText), pbPtr, pbEnd, &cbMoveBy);
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

static HTREEITEM TV_InsertIndexedItem(
    HWND hWndTree,
    HTREEITEM hParent,
    HTREEITEM hInsertAfter,
    PTREE_ITEM_INFO pItemInfo,
    LPVOID lpElement,
    size_t cbElement,
    size_t nIndex = INVALID_ITEM_INDEX)
{
    HTREEITEM hItem;
    LPBYTE pbPtr = (LPBYTE)(lpElement);
    LPBYTE pbEnd = pbPtr + cbElement;
    size_t SaveIndex = GLOBAL_ItemIndex;

    if(nIndex != INVALID_ITEM_INDEX)
        GLOBAL_ItemIndex = nIndex;
    hItem = TV_InsertNewItem(hWndTree, hParent, hInsertAfter, pItemInfo, pbPtr, pbEnd);
    GLOBAL_ItemIndex = SaveIndex;

    return hItem;
}

static HTREEITEM TV_InsertIndexedItem(
    HWND hWndTree,
    HTREEITEM hParent,
    HTREEITEM hInsertAfter,
    PTREE_ITEM_INFO pItemInfo,
    ACE_CSA_OBJECT * pObject,
    size_t nIndex = INVALID_ITEM_INDEX)
{
    LPBYTE pbEnd;
    LPBYTE pbPtr;
    BYTE ObjectBuffer[MAX_ACL_LENGTH];

    // Export the item to the plain text
    pbEnd = ObjectBuffer + sizeof(ObjectBuffer);
    if((pbPtr = pObject->Export(ObjectBuffer, pbEnd)) == NULL)
    {
        assert(false);
        return NULL;
    }

    // Create the item
    return TV_InsertIndexedItem(hWndTree, hParent, hInsertAfter, pItemInfo, ObjectBuffer, (pbPtr - ObjectBuffer), nIndex);
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

static HTREEITEM TV_InsertNewItemCSA_V1(
    HWND hWndTree,
    HTREEITEM hParent,
    LPBYTE pbPtr,
    LPBYTE pbEnd,
    PULONG pcbMoveBy)
{
    HTREEITEM hInsertAfter = TVI_FIRST;
    ACE_CSA_HELPER CsaHelper;
    size_t cbAttrRel = (pbEnd - pbPtr);
    size_t SaveIndex = GLOBAL_ItemIndex;

    // Verify the structure
    if(cbAttrRel < sizeof(PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1))
        return NULL;

    // Convert the security attribute to absolute security attribute
    if(CsaHelper.Import(pbPtr, pbEnd, pcbMoveBy) == ERROR_SUCCESS)
    {
        // Insert members of CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1
        TV_InsertIndexedItem(hWndTree, hParent, TVI_LAST, &TreeItem_CSA_Name, &CsaHelper.Name);
        TV_InsertIndexedItem(hWndTree, hParent, TVI_LAST, &TreeItem_CSA_VTyp, &CsaHelper.ValueType, sizeof(CsaHelper.ValueType));
        TV_InsertIndexedItem(hWndTree, hParent, TVI_LAST, &TreeItem_CSA_Res,  &CsaHelper.Reserved, sizeof(CsaHelper.Reserved));
        TV_InsertIndexedItem(hWndTree, hParent, TVI_LAST, &TreeItem_CSA_Flgs, &CsaHelper.Flags, sizeof(CsaHelper.Flags));
        TV_InsertIndexedItem(hWndTree, hParent, TVI_LAST, &TreeItem_CSA_VCnt, &CsaHelper.ValueCount, sizeof(CsaHelper.ValueCount));

        // Parse all values
        if(hInsertAfter != NULL)
        {
            // Insert all values
            for(ULONG i = 0; i < CsaHelper.ValueCount && hInsertAfter != NULL; i++)
            {
                switch(CsaHelper.ValueType)
                {
                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
                        hInsertAfter = TV_InsertIndexedItem(hWndTree, hParent, TVI_LAST, &TreeItem_CSA_U64, &CsaHelper.ppObjects[i], i);
                        break;

                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
                        hInsertAfter = TV_InsertIndexedItem(hWndTree, hParent, TVI_LAST, &TreeItem_CSA_STR, &CsaHelper.ppObjects[i], i);
                        break;

                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
                        hInsertAfter = TV_InsertIndexedItem(hWndTree, hParent, TVI_LAST, &TreeItem_CSA_SidN, &CsaHelper.ppObjects[i], i);
                        break;

                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
                        hInsertAfter = TV_InsertIndexedItem(hWndTree, hParent, TVI_LAST, &TreeItem_CSA_BOOL, &CsaHelper.ppObjects[i], i);
                        break;

                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
                        hInsertAfter = TV_InsertIndexedItem(hWndTree, hParent, TVI_LAST, &TreeItem_CSA_BinN, &CsaHelper.ppObjects[i], i);
                        break;

                    default:
                        hInsertAfter = NULL;
                        assert(false);
                        break;
                }
            }
        }
    }

    GLOBAL_ItemIndex = SaveIndex;
    return hInsertAfter;
}

static void TV_InsertNewItemAceFields(
    HWND hWndTree,
    HTREEITEM hParent,
    const ACE_HELPER & AceHelper,
    LPBYTE pbPtr,
    LPBYTE pbEnd)
{
    HTREEITEM hInsertAfter = TVI_FIRST;

    // Delete any existing children
    TreeView_DeleteChildren(hWndTree, hParent);

    // Special: Save the value of ACE_HEADER::Flags
    if(pAclInWork != NULL && pAceInWork != NULL)
        pAceInWork->Header.AceFlags = AceHelper.AceFlags;

    // Insert all ACE members according to the bit mask in the ACE helper
    for(size_t i = 0; i < _countof(AceFieldInfos); i++)
    {
        ULONG cbMoveBy = 0;

        // Is that flag present there?
        if(AceHelper.AceLayout & AceFieldInfos[i].AceLayoutFlag)
        {
            // Insert the ACE field
            hInsertAfter = TV_InsertNewItem(hWndTree,
                                            hParent,
                                            hInsertAfter,
                                           &AceFieldInfos[i].TreeItem,
                                            pbPtr, pbEnd, &cbMoveBy);
            if(hInsertAfter == NULL)
                break;
            pbPtr += cbMoveBy;

            // Insert the ACE field sub structure
            switch(AceFieldInfos[i].TreeItem.ItemType)
            {
                case ItemTypeCSA_V1:
                    TV_InsertNewItemCSA_V1(hWndTree, hInsertAfter, AceHelper.AttrRel, AceHelper.AttrRel + AceHelper.AttrRelLength, &cbMoveBy);
                    pbPtr += cbMoveBy;
                    break;
            }
        }

        // Special: The CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 structure
        if((AceHelper.AceLayout & ACE_FIELD_CSA_V1) && (AceFieldInfos[i].AceLayoutFlag == ACE_FIELD_CSA_V1))
        {
            TV_AllocateItemData(hWndTree, hInsertAfter, pbPtr - cbMoveBy, pbEnd);
        }

        // Special: Allocate the item data for condition
        if((AceHelper.AceLayout & ACE_FIELD_CONDITION) && (AceFieldInfos[i].AceLayoutFlag == ACE_FIELD_CONDITION))
        {
            TV_AllocateItemData(hWndTree, hInsertAfter, pbPtr - cbMoveBy, pbEnd);
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

    // Disable redrawing
    EnableRedraw(hWndTree, FALSE);

    // Insert the main ACE item
    hAceItem = TV_InsertNewItem(hWndTree, hParent, hInsertAfter, &TreeItem_Ace, pbPtr, pbEnd);
    if(hAceItem != NULL)
    {
        // Set the ACE to the ACE helper, we can parse the ACE fields easier
        AceHelper.SetAce(pAceHeader);

        // For ACE-forming flags like GUID flags, we need to set ACE-in-work
        pAceInWork = (PACE)(pAceHeader);

        // Insert the ACE fields
        TV_InsertNewItemAceFields(hWndTree, hAceItem, AceHelper, pbPtr, pbEnd);
        
        // Invalidate pointer to the GUID flags
        pAceInWork = NULL;
    }

    // Enable redrawing
    EnableRedraw(hWndTree);
    return hAceItem;
}

static HTREEITEM TV_InsertNewItemAclFields(
    HWND hWndTree,
    HTREEITEM hParent,
    HTREEITEM hInsertAfter,
    PACL pAcl)
{
    LPBYTE pbAclPtr = (LPBYTE)(pAcl);
    LPBYTE pbAclEnd = pbAclPtr + pAcl->AclSize;
    ULONG AceCount = pAcl->AceCount;

    // Insert fields from the ACE header
    for(size_t i = 0; i < _countof(AclFieldInfos); i++)
    {
        ULONG cbMoveBy = 0;

        hInsertAfter = TV_InsertNewItem(hWndTree,
                                        hParent,
                                        hInsertAfter,
                                        AclFieldInfos[i],
                                        pbAclPtr,
                                        pbAclEnd,
                                       &cbMoveBy);
        if(hInsertAfter == NULL)
            break;
        pbAclPtr += cbMoveBy;
    }

    // Parse the ACEs
    while(AceCount > 0 && (pbAclPtr + sizeof(ACE_HEADER)) < pbAclEnd)
    {
        PACE_HEADER pAceHeader = (PACE_HEADER)(pbAclPtr);
        LPBYTE pbAceEnd = (LPBYTE)(pAceHeader) + pAceHeader->AceSize;

        // The ACE should not go past the end of ACL
        if(pbAceEnd > pbAclEnd)
            break;

        // Insert the ACE to the list
        if((hInsertAfter = TV_InsertNewItemAce(hWndTree, hParent, hInsertAfter, pAceHeader)) == NULL)
            break;

        // Move the data pointer by the size of the ACE
        pbAclPtr += pAceHeader->AceSize;
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

static NTSTATUS TV_ItemToData(HWND hWndTree, HTREEITEM hItem, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    PTREE_ITEM_INFO pItemInfo;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    TCHAR szItemText[MAX_ITEM_TEXT];

    // Retrieve the item info
    if((pItemInfo = TV_GetItemParamAndText(hWndTree, hItem, szItemText, _countof(szItemText))) != NULL)
    {
        // If there a "string-to-data" function?
        if(pItemInfo->StringTo != NULL)
        {
            Status = pItemInfo->StringTo(pItemInfo, GetItemTextValue(szItemText), pbPtr, pbEnd, pcbMoveBy);
        }
    }
    return Status;
}

static NTSTATUS TV_ItemToData(HWND hWndTree, HTREEITEM hItem, LPVOID lpBuffer, size_t cbBuffer, PULONG pcbMoveBy, HTREEITEM * phNextItem)
{
    LPBYTE pbBuffer = (LPBYTE)(lpBuffer);

    // Check the item handle
    if(hWndTree == NULL || hItem == NULL)
        return STATUS_UNSUCCESSFUL;

    // Give the next sibling, if required
    if(phNextItem != NULL)
        phNextItem[0] = TreeView_GetNextSibling(hWndTree, hItem);
    return TV_ItemToData(hWndTree, hItem, pbBuffer, pbBuffer + cbBuffer, pcbMoveBy);
}

static NTSTATUS TV_ItemsToCSA_v1(HWND hWndTree, HTREEITEM hParent, ACE_CSA_HELPER & CsaHelper)
{
    HTREEITEM hItem;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    TCHAR szName[256];
    DWORD ValueCount = 0;
    DWORD Flags = 0;
    DWORD Index = 0;
    WORD ValueType = 0;
    WORD Reserved = 0;

    // Retrieve the first child
    if((hItem = TreeView_GetChild(hWndTree, hParent)) != NULL)
    {
        // Get the name of the attribute
        if((Status = TV_ItemToData(hWndTree, hItem, szName, sizeof(szName), NULL, &hItem)) != STATUS_SUCCESS)
            return Status;
        CsaHelper.SetValueName(szName);

        // Get the value type
        if((Status = TV_ItemToData(hWndTree, hItem, &ValueType, sizeof(ValueType), NULL, &hItem)) != STATUS_SUCCESS)
            return Status;

        // Get the "Reserved" value
        if((Status = TV_ItemToData(hWndTree, hItem, &Reserved, sizeof(Reserved), NULL, &hItem)) != STATUS_SUCCESS)
            return Status;

        // Get the "Flags" value
        if((Status = TV_ItemToData(hWndTree, hItem, &Flags, sizeof(Flags), NULL, &hItem)) != STATUS_SUCCESS)
            return Status;

        // Get the supposed value count
        if((Status = TV_ItemToData(hWndTree, hItem, &ValueCount, sizeof(ValueCount), NULL, &hItem)) != STATUS_SUCCESS)
            return Status;

        // Now get the *real* value count
        if((ValueCount = TV_GetRemainingItemCount(hWndTree, hItem)) == 0)
            return STATUS_UNSUCCESSFUL;

        // Change the type of the values
        if(CsaHelper.SetValueType(ValueType, ValueCount) == ERROR_SUCCESS)
        {
            // Store the missing members
            CsaHelper.Reserved = Reserved;
            CsaHelper.Flags = Flags;

            // Load the values
            while(hItem != NULL)
            {
                ULONG cbDataLength = 0;
                BYTE ValueData[512] = {0};

                if((Status = TV_ItemToData(hWndTree, hItem, ValueData, sizeof(ValueData), &cbDataLength, &hItem)) != STATUS_SUCCESS)
                    return Status;
                if((Status = CsaHelper.SetValueData(ValueData, Index++)) != STATUS_SUCCESS)
                    return Status;
            }
        }
    }
    return Status;
}

static NTSTATUS TV_ItemsToCSA_v1(HWND hWndTree, HTREEITEM hParent, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 pAttrRel;
    ACE_CSA_HELPER CsaHelper;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG cbAttrRel = 0;

    // Create the CSA_HELPER from the tree view items
    if(TV_ItemsToCSA_v1(hWndTree, hParent, CsaHelper) == ERROR_SUCCESS)
    {
        // Export the attribute structures from the tree item
        if((pAttrRel = CsaHelper.Export(&cbAttrRel)) != NULL)
        {
            Status = CopyDataAway(pbPtr, pbEnd, pAttrRel, cbAttrRel, pcbMoveBy);
            LocalFree(pAttrRel);
        }
    }
    return Status;
}

static NTSTATUS TV_ItemsToData(HWND hWndTree, HTREEITEM hParent, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    PTREE_ITEM_INFO pParentInfo = TV_GetItemParam(hWndTree, hParent);
    HTREEITEM hItem = TreeView_GetChild(hWndTree, hParent);
    LPBYTE pbBegin = pbPtr;

    // If we're starting an ACE, then remember the ACE header
    if(pParentInfo && pParentInfo->ItemType == ItemTypeAce)
        pAceInWork = (PACE)(pbPtr);

    // Keep going over all siblings
    while(hItem != NULL)
    {
        NTSTATUS Status = STATUS_SUCCESS;
        ULONG cbMoveBy = 0;
        bool bNeedItemToData = true;

        // If there are a child items, go recursively on the children
        if(TreeView_GetChild(hWndTree, hItem) != NULL)
        {
            // Special treatment for CLAIM_SECURITY_ATTRIBUTES v1
            if(TV_IsSecurityAttributes(hWndTree, hItem))
                Status = TV_ItemsToCSA_v1(hWndTree, hItem, pbPtr, pbEnd, &cbMoveBy);
            else
                Status = TV_ItemsToData(hWndTree, hItem, pbPtr, pbEnd, &cbMoveBy);

            // If the items retrieval failed, we can try its own StringTo method
            bNeedItemToData = (Status != STATUS_SUCCESS);
        }

        // Do we still need the data from the item?
        if(bNeedItemToData)
        {
            Status = TV_ItemToData(hWndTree, hItem, pbPtr, pbEnd, &cbMoveBy);
        }

        // If the operation failed, bail out
        if(!NT_SUCCESS(Status))
            return Status;
        pbPtr += cbMoveBy;

        // Get the next sibling to the tree item
        hItem = TreeView_GetNextSibling(hWndTree, hItem);
    }

    // When an ACE is being finished, fill some variables that depend on ACE layout and size
    UpdateAceVariables(pAceInWork, pbPtr);
    pAceInWork = NULL;

    // Give length of the data to the caller
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = (ULONG)(pbPtr - pbBegin);
    return STATUS_SUCCESS;
}

static DWORD TV_GetAceType(HWND hWndTree, HTREEITEM hItem)
{
    PTREE_ITEM_INFO pItemInfo;
    PACE_HEADER pAceHeader;
    DWORD dwAceType = ACCESS_ALLOWED_ACE_TYPE;
    BYTE AceHeader[sizeof(ACE_HEADER)];

    // Retrieve the tree item info
    if((pItemInfo = TV_GetItemParam(hWndTree, hItem)) != NULL)
    {
        if(pItemInfo->ItemType == ItemTypeAce)
        {
            // The buffer will overflow here because the whole ACE can't fit in it
            if(TV_ItemsToData(hWndTree, hItem, AceHeader, AceHeader + sizeof(ACE_HEADER)) == STATUS_BUFFER_OVERFLOW)
            {
                pAceHeader = (PACE_HEADER)(AceHeader);
                dwAceType = pAceHeader->AceType;
            }
        }
    }
    return dwAceType;
}

static void TV_ResetAceItem(HWND hWndTree, HTREEITEM hItem, LPBYTE pbAceData, ULONG cbAceData)
{
    PACE_HEADER pAceHeader = (PACE_HEADER)(pbAceData);
    ACE_HELPER AceHelper;
    TCHAR szItemText[MAX_ITEM_TEXT];

    // Init the item text
    GetAceTypeString(szItemText, _countof(szItemText), pAceHeader);
    TreeView_SetItemText(hWndTree, hItem, szItemText);

    // Init the subitems
    AceHelper.SetAce(pAceHeader);

    // For ACE-forming flags like GUID flags, we need to set ACE-in-work
    pAceInWork = (PACE)(pbAceData);
    TV_InsertNewItemAceFields(hWndTree, hItem, AceHelper, pbAceData, pbAceData + cbAceData);
    pAceInWork = NULL;
}

static void TV_SwapItems(HWND hWndTree, HTREEITEM hItem1, HTREEITEM hItem2)
{
    PACE pSaveAceInWork = pAceInWork;
    ULONG cbAceData1 = 0;
    ULONG cbAceData2 = 0;
    BYTE AceData1[MAX_ACL_LENGTH];
    BYTE AceData2[MAX_ACL_LENGTH];

    // Disable redraw
    EnableRedraw(hWndTree, FALSE);

    // Read the data from the first item
    pAceInWork = (PACE)(AceData1);
    if(NT_SUCCESS(TV_ItemsToData(hWndTree, hItem1, AceData1, AceData1 + sizeof(AceData1), &cbAceData1)))
    {
        // Read the data from the second item
        pAceInWork = (PACE)(AceData2);
        if(NT_SUCCESS(TV_ItemsToData(hWndTree, hItem2, AceData2, AceData2 + sizeof(AceData2), &cbAceData2)))
        {
            // Initialize the item texts
            TV_ResetAceItem(hWndTree, hItem1, AceData2, cbAceData2);
            TV_ResetAceItem(hWndTree, hItem2, AceData1, cbAceData1);
        }
    }

    // Enable redrawing and paint
    EnableRedraw(hWndTree, TRUE);
    pAceInWork = pSaveAceInWork;
}

static NTSTATUS TreeView_ItemToAcl(HWND hWndTree, HTREEITEM hParent, PACL * ppAcl)
{
    NTSTATUS Status = STATUS_NO_MEMORY;
    LPBYTE pbAcl;
    ULONG cbMoveBy = 0;

    // Allocate buffer for the entire ACL
    if((pbAcl = (LPBYTE)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, MAX_ACL_LENGTH)) != NULL)
    {
        // Set the ACL in work
        pAclInWork = (PACL)(pbAcl);
        pAclInWork->AceCount = 0;

        // Process the ACL
        if((Status = TV_ItemsToData(hWndTree, hParent, pbAcl, pbAcl + MAX_ACL_LENGTH, &cbMoveBy)) == STATUS_SUCCESS)
        {
            pAclInWork->AclSize = (WORD)(cbMoveBy);
            ppAcl[0] = pAclInWork;
        }
        else
        {
            // Conversion to ACL failed, free the ACL
            HeapFree(g_hHeap, 0, pbAcl);
        }

        // Reset the ACL-in-work pointer
        pAclInWork = NULL;
    }
    return Status;
}

static NTSTATUS TreeView_ItemToAcl(
    HWND hWndTree,
    HTREEITEM hParent,
    PACL * ppAcl,
    BOOLEAN * pbAclPresent)
{
    PTREE_ITEM_INFO pItemInfo;
    HTREEITEM hItem = TreeView_GetChild(hWndTree, hParent);
    NTSTATUS Status;

    // Retrieve the item information
    if((pItemInfo = TV_GetItemParam(hWndTree, hItem)) != NULL)
    {
        switch(pItemInfo->ItemType)
        {
            case ItemTypeNoAcl:
                pbAclPresent[0] = FALSE;
                ppAcl[0] = NULL;
                return STATUS_SUCCESS;

            case ItemTypeNullAcl:
                pbAclPresent[0] = TRUE;
                ppAcl[0] = NULL;
                return STATUS_SUCCESS;

            default:
                if((Status = TreeView_ItemToAcl(hWndTree, hParent, ppAcl)) == STATUS_SUCCESS)
                    pbAclPresent[0] = TRUE;
                return Status;
        }
    }
    return STATUS_NOT_SUPPORTED;
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
    EnableRedraw(hWndTree, FALSE);

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
    EnableRedraw(hWndTree, TRUE);
}

static void TreeView_DeferItemText(HWND hDlg, WPARAM wParam, LPARAM lParam)
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

static void TreeView_DeferChangeIntWithFlags(HWND hDlg, WPARAM wParam)
{
    PTREE_ITEM_INFO pItemInfo;
    HTREEITEM hItem = (HTREEITEM)(wParam);
    ULONGLONG IntValue = 0;
    DWORD dwIntValue;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);

    if((pItemInfo = TV_GetItemParam(hWndTree, hItem)) != NULL)
    {
        LPBYTE pbPtr = (LPBYTE)(&dwIntValue);
        LPBYTE pbEnd = pbPtr + sizeof(dwIntValue);
        TCHAR szItemText[MAX_ITEM_TEXT];

        // Sanity checks
        assert(pItemInfo->pFlagInfos != NULL);
        dwIntValue = (DWORD)(IntValue);

        // Retrieve the integer value out of the item
        if(TV_ItemToData(hWndTree, hItem, pbPtr, pbEnd) == STATUS_SUCCESS)
        {
            DWORD dwSaveValue = dwIntValue;

            if(FlagsDialog(hDlg, IDS_SET_NEW_VALUE, pItemInfo->pFlagInfos, dwIntValue) == IDOK && dwIntValue != dwSaveValue)
            {
                IntValue = dwIntValue;
                TV_MakeItemText(pItemInfo, szItemText, _countof(szItemText), pbPtr, pbEnd);
                TreeView_SetItemText(hWndTree, hItem, szItemText);
            }
        }
    }
}

static void TreeView_DeferChangeWholeAce(HWND hDlg, WPARAM wParam, LPARAM lParam)
{
    TV_SELECTION tvs;
    ACE_HELPER * pAceHelper = (ACE_HELPER *)(lParam);
    PACE_HEADER pAceHeader;
    HTREEITEM hItem = (HTREEITEM)(wParam);
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    BYTE AceBuffer[MAX_ACL_LENGTH];

    // The ACE_HELPER must be valid
    if(pAceHelper != NULL)
    {
        // Export the ACE to the plain buffer
        if((pAceHeader = pAceHelper->Export(AceBuffer, sizeof(AceBuffer))) != NULL)
        {
            // Stop redrawing
            EnableRedraw(hWndTree, FALSE);

            // Save the selection of the tree view item
            TV_SaveSelection(hWndTree, tvs);

            // Build the ACE into the item
            TV_ResetAceItem(hWndTree, hItem, (LPBYTE)(pAceHeader), pAceHeader->AceSize);

            // Select the root item
            TV_RestoreSelection(hWndTree, tvs, hItem);

            // Enable redrawing back
            EnableRedraw(hWndTree);
        }
        delete pAceHelper;
    }
}

static int TreeView_DeferChangeAceGuid(HWND hDlg, WPARAM wParam, LPARAM lParam)
{
    PTREE_ITEM_INFO pItemInfo;
    HTREEITEM hParent;
    HTREEITEM hItem;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);

    if((hItem = TreeView_GetSelection(hWndTree)) != NULL)
    {
        if((pItemInfo = TV_GetItemParam(hWndTree, hItem)) != NULL)
        {
            if((hParent = TreeView_GetParent(hWndTree, hItem)) != NULL)
            {
                ACE_HELPER * pAceHelper;
                ULONG cbMoveBy = 0;
                BYTE AceBuffer[MAX_ACL_LENGTH] = {0};

                if(TV_ItemsToData(hWndTree, hParent, AceBuffer, &AceBuffer[MAX_ACL_LENGTH], &cbMoveBy) == STATUS_SUCCESS)
                {
                    if((pAceHelper = new ACE_HELPER()) != NULL)
                    {
                        // Setup the ACE from the data
                        pAceHelper->SetAce((PACE_HEADER)(AceBuffer));

                        // Now perform action-specific modification
                        switch(MAKELONG(wParam, lParam))
                        {
                            case MAKELONG(0, TRUE):     // Create new GUID1
                                pAceHelper->Flags |= ACE_OBJECT_TYPE_PRESENT;
                                break;

                            case MAKELONG(1, TRUE):     // Create new GUID1
                                pAceHelper->Flags |= ACE_INHERITED_OBJECT_TYPE_PRESENT;
                                break;

                            default:                    // Modify GUID1 or GUID2
                                pAceHelper->Flags |= ((PACE)(AceBuffer))->Flags;
                                break;
                        }

                        // Update the whole ACE
                        PostMessage(hDlg, WM_DEFER_CHANGE_WHOLE_ACE, (WPARAM)(hParent), (LPARAM)(pAceHelper));
                    }
                }
            }
        }
    }
    return TRUE;
}

static void TreeView_DeferChangeAceResource(HWND hDlg, WPARAM wParam, LPARAM lParam)
{
    PTREE_ITEM_INFO pItemInfo;
    HTREEITEM hParent;
    HTREEITEM hItem = (HTREEITEM)(wParam);
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    bool bResourceTypeChanged = false;
    bool bChangeWholeAce = false;

    if((pItemInfo = TV_GetItemParam(hWndTree, hItem)) != NULL)
    {
        DWORD ValueCount = 3;
        WORD ValueType = 0;

        // Item-specific
        switch(pItemInfo->ItemType)
        {
            case ItemTypeCSA_VType:
                if(TV_ItemToData(hWndTree, hItem, &ValueType, sizeof(ValueType), NULL, NULL) == STATUS_SUCCESS)
                {
                    if(lParam == TRUE)
                    {
                        DWORD dwSaveValueType = ValueType;
                        DWORD dwValueType = ValueType;

                        // Ask the user for new ACE type
                        if(FlagsDialog(hDlg, IDS_ACE_TYPE, CSA_ValTypes, dwValueType) != IDOK || dwValueType == dwSaveValueType)
                            return;
                        ValueType = (WORD)(dwValueType);
                    }
                    bResourceTypeChanged = true;
                    bChangeWholeAce = true;
                }
                break;

            case ItemTypeCSA_VCnt:
                if(TV_ItemToData(hWndTree, hItem, &ValueCount, sizeof(ValueCount), NULL, NULL) == STATUS_SUCCESS)
                    bChangeWholeAce = true;
                break;
        }

        // OK to setup new ACE?
        if(bChangeWholeAce)
        {
            ACE_CSA_HELPER CsaHelper;
            NTSTATUS Status;

            // Load the CSA helper from the tree view
            hParent = TreeView_GetParent(hWndTree, hItem);
            TV_ItemsToCSA_v1(hWndTree, hParent, CsaHelper);
            hParent = TreeView_GetParent(hWndTree, hParent);

            // Preserve the value type, if it didn't change
            if(bResourceTypeChanged == false)
                ValueType = CsaHelper.ValueType;

            // Initiate changing the resource type and count
            Status = CsaHelper.SetValueType(ValueType, ValueCount);
            PostMessage(hDlg, WM_DEFER_CHANGE_WHOLE_ACE, (WPARAM)(hParent), (LPARAM)(new ACE_HELPER(CsaHelper)));

            // If the change of the resource type/count failed, show error code
            if(Status != STATUS_SUCCESS)
                SetResultInfo(hDlg, RSI_NTSTATUS, Status);
        }
    }
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
    pcbSD[0] = cbSD;
    ppSD[0] = lpSD;
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
                        TV_InsertNewItemAclFields(hWndTree, hItem, NULL, (PACL)(EmptyAcl));
                        break;
                    }

                    case IDC_SET_FULL_CONTROL:
                    {
                        TV_InsertNewItemAclFields(hWndTree, hItem, NULL, (PACL)(FullControlAcl));
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
            DWORD dwAceType = TV_GetAceType(hWndTree, hItem);

            // Get previous or next
            if(bBeforeSelected)
            {
                if((hInsertAfter = TreeView_GetPreviousItem(hWndTree, hItem)) == NULL)
                {
                    hInsertAfter = TVI_FIRST;
                }
            }

            // Ask the user which ACE he wants to insert
            if(FlagsDialog(hDlg, IDS_ACE_TYPE, AceHdrTypes, dwAceType) == IDOK)
            {
                PACE_HEADER pAceHeader;
                ACE_HELPER AceHelper(dwAceType);

                // Export the ACE and convert to tree items
                if((pAceHeader = AceHelper.Export(AceBuffer, sizeof(AceBuffer))) != NULL)
                {
                    if((hItem = TV_InsertNewItemAce(hWndTree, hParent, hInsertAfter, pAceHeader)) != NULL)
                    {
                        TreeView_Select(hWndTree, hItem, TVGN_CARET);
                    }
                }
            }
        }
    }
    return TRUE;
}

static int OnSwapAceWith(HWND hDlg, BOOL bWithPrevious)
{
    HTREEITEM hSwapWith;
    HTREEITEM hItem;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);

    // Retrieve the item where to insert it
    hItem = TreeView_GetSelection(hWndTree);

    // Get the previous or next item to swap with
    if(bWithPrevious == FALSE)
    {
        hSwapWith = TreeView_GetNextSibling(hWndTree, hItem);
        TV_SwapItems(hWndTree, hItem, hSwapWith);
    }
    else
    {
        hSwapWith = TreeView_GetPrevSibling(hWndTree, hItem);
        TV_SwapItems(hWndTree, hSwapWith, hItem);
    }

    // Select the target item
    TreeView_Select(hWndTree, hSwapWith, TVGN_CARET);
    return TRUE;
}

static int OnSetAceType(HWND hDlg)
{
    PTREE_ITEM_INFO pItemInfo;
    HTREEITEM hItem;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);

    if((hItem = TreeView_GetSelection(hWndTree)) != NULL)
    {
        if((pItemInfo = TV_GetItemParam(hWndTree, hItem)) != NULL)
        {
            DWORD dwSaveAceType = 0;
            DWORD dwAceType;
            BYTE AceType = 0;

            if(TV_ItemToData(hWndTree, hItem, &AceType, sizeof(AceType), NULL, NULL) == STATUS_SUCCESS)
            {
                // Get the 32-bit ACE type
                dwSaveAceType = dwAceType = AceType;

                // Ask the user for new ACE type
                if(FlagsDialog(hDlg, IDS_ACE_TYPE, AceHdrTypes, dwAceType) == IDOK && dwAceType != dwSaveAceType)
                {
                    // Find the proper parent with the ACE type
                    while(pItemInfo->ItemType != ItemTypeAce)
                    {
                        if((hItem = TreeView_GetParent(hWndTree, hItem)) == NULL)
                            return FALSE;
                        pItemInfo = TV_GetItemParam(hWndTree, hItem);
                    }

                    // Rebuild the whole ACE
                    PostMessage(hDlg, WM_DEFER_CHANGE_WHOLE_ACE, (WPARAM)(hItem), (LPARAM)(new ACE_HELPER(dwAceType)));
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

    hItem = TreeView_GetSelection(hWndTree);
    hParent = TreeView_GetParent(hWndTree, hItem);
    if(hParent != NULL && hItem != NULL)
    {
        // Disable redrawing
        EnableRedraw(hWndTree, FALSE);

        // Delete the tree item
        if(TreeView_DeleteItem(hWndTree, hItem))
        {
            // If there are no children, set the enpty ACL
            if(TreeView_GetChildCount(hWndTree, hParent) == 0)
            {
                // Insert the ACL as empty
                TV_InsertNewItemAclFields(hWndTree, hParent, TVI_LAST, (PACL)(EmptyAcl));
                TreeView_Select(hWndTree, hParent, TVGN_CARET);
            }
        }
        EnableRedraw(hWndTree);
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
    HTREEITEM hChildItem[4];
    NTSTATUS Status = STATUS_SUCCESS;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    PACL pDacl = NULL;
    PACL pSacl = NULL;
    BYTE OwnerSid[MAX_SID_LENGTH];
    BYTE GroupSid[MAX_SID_LENGTH];
    BOOLEAN bDaclPresent = FALSE;
    BOOLEAN bSaclPresent = FALSE;

    // Get the mask about which security information we want
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    GetDialogSecurityInfo(hDlg);

    // Get handles of all child items
    hChildItem[0] = TreeView_GetChild(hWndTree, TVI_ROOT);
    hChildItem[1] = TreeView_GetNextSibling(hWndTree, hChildItem[0]);
    hChildItem[2] = TreeView_GetNextSibling(hWndTree, hChildItem[1]);
    hChildItem[3] = TreeView_GetNextSibling(hWndTree, hChildItem[2]);

    //
    // Put owner into the security descriptor
    //

    if(NT_SUCCESS(Status) && (pData->SecurityInformation & OWNER_SECURITY_INFORMATION))
    {
        Status = TV_ItemsToData(hWndTree, hChildItem[0], OwnerSid, OwnerSid + sizeof(OwnerSid));
        if(NT_SUCCESS(Status))
        {
            Status = RtlSetOwnerSecurityDescriptor(&sd, (PSID)(OwnerSid), FALSE);
            AppliedSecInfo |= OWNER_SECURITY_INFORMATION;
        }
    }

    //
    // Put group into the security descriptor
    //

    if(NT_SUCCESS(Status) && (pData->SecurityInformation & GROUP_SECURITY_INFORMATION))
    {
        Status = TV_ItemsToData(hWndTree, hChildItem[1], GroupSid, GroupSid + sizeof(GroupSid));
        if(NT_SUCCESS(Status))
        {
            Status = RtlSetGroupSecurityDescriptor(&sd, (PSID)(GroupSid), FALSE);
            AppliedSecInfo |= GROUP_SECURITY_INFORMATION;
        }
    }

    //
    // Put DACL into the security descriptor
    //

    if(NT_SUCCESS(Status) && (pData->SecurityInformation & DACL_SECURITY_INFORMATION))
    {
        Status = TreeView_ItemToAcl(hWndTree, hChildItem[2], &pDacl, &bDaclPresent);
        if(NT_SUCCESS(Status))
        {
            Status = RtlSetDaclSecurityDescriptor(&sd, bDaclPresent, pDacl, FALSE);
            AppliedSecInfo |= DACL_SECURITY_INFORMATION;
        }
    }

    //
    // Put SACL into the security descriptor
    //

    if(NT_SUCCESS(Status) && (pData->SecurityInformation & ALL_SACL_SECURITY_INFORMATION))
    {
        Status = TreeView_ItemToAcl(hWndTree, hChildItem[3], &pSacl, &bSaclPresent);
        if(NT_SUCCESS(Status))
        {
            Status = RtlSetSaclSecurityDescriptor(&sd, bSaclPresent, pSacl, FALSE);
            AppliedSecInfo |= (pData->SecurityInformation & ALL_SACL_SECURITY_INFORMATION);
        }
    }

    // Apply the security descriptor to the file
    if(NT_SUCCESS(Status))
        Status = NtSetSecurityObject(pData->hFile, AppliedSecInfo, &sd);
    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_NOINFO, Status);

    // Free all 4 parts of the security information
    if(pSacl != NULL)
        HeapFree(g_hHeap, 0, pSacl);
    if(pDacl != NULL)
        HeapFree(g_hHeap, 0, pDacl);
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
        // Exception: ACE condition is not editable
        if(IsItemTypeEditable(pItemInfo))
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
    ACE_HELPER * pAceHelper;
    HTREEITEM hParent;
    LPBYTE pbBuffer;
    size_t SaveIndex = GLOBAL_ItemIndex;
    ULONG cbBuffer = 0x1000;
    ULONG cbMoveBy = 0;
    BOOL bAcceptChanges = FALSE;
    TCHAR szItemText[MAX_ITEM_TEXT];

    // If pszText contains NULL, it means that the user cancelled the editing
    if(pTVDispInfo->item.pszText && pTVDispInfo->item.pszText[0])
    {
        // Can we convert both values?
        if(pItemInfo && pItemInfo->ToString && pItemInfo->StringTo)
        {
            if((pbBuffer = (LPBYTE)LocalAlloc(LPTR, cbBuffer)) != NULL)
            {
                NTSTATUS Status;

                // Convert the string to data
                Status = pItemInfo->StringTo(pItemInfo, pTVDispInfo->item.pszText, pbBuffer, pbBuffer + cbBuffer, &cbMoveBy);
                if(NT_SUCCESS(Status))
                {
                    switch(pItemInfo->ItemType)
                    {
                        case ItemTypeAceType:   // Changing ACE type: We need to set the whole ACE again
                            pAceHelper = new ACE_HELPER(pbBuffer[0]);
                            hParent = TreeView_GetParent(pTVDispInfo->hdr.hwndFrom, pTVDispInfo->item.hItem);
                            PostMessage(hDlg, WM_DEFER_CHANGE_WHOLE_ACE, (WPARAM)(hParent), (LPARAM)(pAceHelper));
                            bAcceptChanges = TRUE;
                            break;

                        case ItemTypeGuid:
                            PostMessage(hDlg, WM_DEFER_CHANGE_ACE_GUID, 0, FALSE);
                            bAcceptChanges = TRUE;
                            break;

                        case ItemTypeGuid2:
                            PostMessage(hDlg, WM_DEFER_CHANGE_ACE_GUID, 1, FALSE);
                            bAcceptChanges = TRUE;
                            break;

                        case ItemTypeCSA_VType:
                            if(IsValidAceAttributeType(pbBuffer))
                            {
                                PostMessage(hDlg, WM_DEFER_CHANGE_ACE_CSA, (WPARAM)(pTVDispInfo->item.hItem), FALSE);
                                bAcceptChanges = TRUE;
                            }
                            break;

                        case ItemTypeCSA_VCnt:
                            if(IsValidAceAttributeCount(pbBuffer))
                            {
                                PostMessage(hDlg, WM_DEFER_CHANGE_ACE_CSA, (WPARAM)(pTVDispInfo->item.hItem), FALSE);
                                bAcceptChanges = TRUE;
                            }
                            break;

                        default:                // Convert the item to text
                            GLOBAL_ItemIndex = TV_GetAceResourceValueIndex(pTVDispInfo);
                            TV_MakeItemText(pItemInfo, szItemText, _countof(szItemText), pbBuffer, pbBuffer + cbMoveBy);
                            bAcceptChanges = DeferSetItemTextValue(hDlg, pTVDispInfo->item.hItem, szItemText);
                            GLOBAL_ItemIndex = SaveIndex;
                            break;
                    }
                }

                // Set the result
                if(bAcceptChanges == FALSE)
                    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_INFO_INT32, Status, 0);
                else
                    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_NOINFO, STATUS_SUCCESS);

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
    PTREE_ITEM_INFO pItemInfo;

    if((pItemInfo = (PTREE_ITEM_INFO)pNMTreeView->itemOld.lParam) != NULL)
    {
        if(IsItemDataPointer(pItemInfo))
            HeapFree(g_hHeap, 0, pItemInfo->ItemData);
        HeapFree(g_hHeap, 0, pItemInfo);
    }
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
    HTREEITEM hInsertAfter = TVI_FIRST;
    HTREEITEM hParent;
    HTREEITEM hItem;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    BYTE DataBuffer[0x200];
    size_t cbDataBuffer = sizeof(DataBuffer);

    // Get the handle to the selected item
    if((hItem = TreeView_GetSelection(hWndTree)) != NULL)
    {
        // Retrieve the parent of the item
        hParent = TreeView_GetParent(hWndTree, hItem);

        // Retrieve the tree item info of the selected item
        if((pItemInfo = TV_GetItemParam(hWndTree, hItem)) != NULL)
        {
            switch(pItemInfo->ItemType)
            {
                case ItemTypeAce:           // Change the whole ACE type
                case ItemTypeAceType:
                    PostMessage(hDlg, WM_COMMAND, MAKEWPARAM(IDC_SET_ACE_TYPE, 0), 0);
                    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, TRUE);
                    return TRUE;

                case ItemTypeGuid:          // Create new ACE guid here
                    PostMessage(hDlg, WM_DEFER_CHANGE_ACE_GUID, 0, TRUE);
                    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, TRUE);
                    return TRUE;

                case ItemTypeGuid2:
                    PostMessage(hDlg, WM_DEFER_CHANGE_ACE_GUID, 1, TRUE);
                    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, TRUE);
                    return TRUE;

                case ItemTypeCSA_VType:
                    PostMessage(hDlg, WM_DEFER_CHANGE_ACE_CSA, (WPARAM)(hItem), TRUE);
                    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, TRUE);
                    return TRUE;
            }

            // Does the item have handler for double click?
            if(pItemInfo->CreateNew != NULL && pItemInfo->ItemData != ItemDataValid)
            {
                PTREE_ITEM_INFO pNewInfo = pItemInfo;
                TREE_ITEM_INFO SaveItemInfo;

                // Save the item info
                memcpy(&SaveItemInfo, pItemInfo, sizeof(TREE_ITEM_INFO));
                pItemInfo = &SaveItemInfo;

                // Special case: When replacing NO_ACL or NULL_ACL, we want to pass parent item
                if(pItemInfo->ItemType == ItemTypeNoAcl || pItemInfo->ItemType == ItemTypeNullAcl)
                    pNewInfo = TV_GetItemParam(hWndTree, hParent);

                // Let the item to create new one
                if(NT_SUCCESS(pItemInfo->CreateNew(pNewInfo, DataBuffer, &cbDataBuffer)))
                {
                    // Get the previous item
                    hInsertAfter = TreeView_GetPreviousItem(hWndTree, hItem);

                    EnableRedraw(hWndTree, FALSE);

                    // Delete the subitems of the item
                    TreeView_DeleteItem(hWndTree, hItem);

                    // Insert the new item with the created data
                    switch(SaveItemInfo.ItemType)
                    {
                        case ItemTypeSid:
                            TV_InsertNewItemSid(hWndTree, hParent, hInsertAfter, &SaveItemInfo, (PSID)(DataBuffer));
                            break;

                        case ItemTypeNoAcl:
                            TV_InsertNewItemAclFields(hWndTree, hParent, hInsertAfter, (PACL)(DataBuffer));
                            break;

                        case ItemTypeNullAcl:
                            TV_InsertNewItemAclFields(hWndTree, hParent, NULL, (PACL)(FullControlAcl));
                            break;
                    }

                    EnableRedraw(hWndTree);
                }
            }

            // If the item is an integer type and has flags, we can show the supporting dialog
            if(IsIntegerTypeWithFlags(pItemInfo))
            {
                PostMessage(hDlg, WM_DEFER_CHANGE_INT_FLAGS, (WPARAM)(hItem), TRUE);
                return TRUE;
            }
        }
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

        case WM_DEFER_CHANGE_INT_FLAGS:
            TreeView_DeferChangeIntWithFlags(hDlg, wParam);
            return TRUE;

        case WM_DEFER_CHANGE_WHOLE_ACE:
            TreeView_DeferChangeWholeAce(hDlg, wParam, lParam);
            return TRUE;

        case WM_DEFER_CHANGE_ACE_GUID:
            TreeView_DeferChangeAceGuid(hDlg, wParam, lParam);
            return TRUE;

        case WM_DEFER_CHANGE_ACE_CSA:
            TreeView_DeferChangeAceResource(hDlg, wParam, lParam);
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
