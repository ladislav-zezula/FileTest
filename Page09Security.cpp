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
    ItemTypeNullAcl,                                // The item says that the ACL is present but it's NULL
    ItemTypeSid,                                    // The item contains Security Identifier (SID)
    ItemTypeAce,                                    // The item contains Access Control Entry (ACE) from DACL
    ItemTypeBool,                                   // The item is a boolean value
    ItemTypeUint08,                                 // The item contains 8-bit integer
    ItemTypeUint16,                                 // The item contains 16-bit integer
    ItemTypeUint32,                                 // The item contains 32-bit integer
    ItemTypeUint64,                                 // The item contains 64-bit integer
    ItemTypeLPWSTR,                                 // The item is pointer to a zero-terminate unicode string (LPWSTR)
    ItemTypeOctStr,                                 // The item is an octet string with length at the beginning
    ItemTypeGuid,                                   // The item is an object GUID
    ItemTypeGuid2,                                  // The item is an inherited object GUID
    ItemTypeSid11,                                  // The item is a mandatory label SID
    ItemTypeSid17,                                  // The item is a policy label SID
    ItemTypeSid19,                                  // The item is a trust level SID
    ItemTypeCSA_V1,                                 // The item is the CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 structure
    ItemTypeCSASid,                                 // Sid with preceding ULONG, containing length
    ItemTypeCondition,                              // The item is an ACE condition
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
    bool (*ToString) (_TREE_ITEM_INFO * pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy);

    // Converts the string representation to binary item
    bool (*StringTo) (_TREE_ITEM_INFO * pItemInfo, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy);

    // Creates a new item of that type
    bool (*CreateNew)(_TREE_ITEM_INFO * pItemInfo, LPBYTE pbDataBuffer, size_t * pcbDataBuffer);
    
    // Type of the item data
    PVOID ItemData;
} TREE_ITEM_INFO, *PTREE_ITEM_INFO;
typedef const TREE_ITEM_INFO *PCTREE_ITEM_INFO;

typedef struct _ACE_FIELD_INFO
{
    ULONG AceLayoutFlag;
    TREE_ITEM_INFO TreeItem;

} ACE_FIELD_INFO, *PACE_FIELD_INFO;

static LPCTSTR szAceTypeSuffix = _T("_TYPE");

static SID_IDENTIFIER_AUTHORITY SiaNull   = SECURITY_NULL_SID_AUTHORITY;
static SID_IDENTIFIER_AUTHORITY SiaWorld  = SECURITY_WORLD_SID_AUTHORITY;
static SID_IDENTIFIER_AUTHORITY SiaLabel  = SECURITY_MANDATORY_LABEL_AUTHORITY;
static SID_IDENTIFIER_AUTHORITY SiaPolicy = SECURITY_SCOPED_POLICY_ID_AUTHORITY;
static SID_IDENTIFIER_AUTHORITY SiaTrust  = SECURITY_PROCESS_TRUST_AUTHORITY;

static const ACL EmptyAcl = {ACL_REVISION_DS, 0, sizeof(ACL)};
static const BYTE FullControlAcl[] =
{
    0x04, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
};

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

static size_t GLOBAL_ItemIndex = INVALID_ITEM_INDEX;    // If we're inserting indexed item
static ULONG ACE_ObjAceFlags = 0;                       // ACCESS_ALLOWED_OBJECT_ACE::Flags (and other object ACEs)
static BYTE ACL_AclRevision = 0;
static WORD ACL_AceCount = 0;

//-----------------------------------------------------------------------------
// Local functions - SID

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

static bool SetSystemSidIntegerValue(PSID pSid, PSID_IDENTIFIER_AUTHORITY pSiaExpected, DWORD dwIntValue)
{
    LPBYTE pbIntValue;

    // Get the pointer to the integrity level
    if((pbIntValue = GetSystemSidIntegerValue(pSid, pSiaExpected)) != NULL)
        memcpy(pbIntValue, &dwIntValue, sizeof(DWORD));
    return (pbIntValue != NULL);
}

static LPBYTE GetSidIntegrityLevel(PSID pSid)
{
    return GetSystemSidIntegerValue(pSid, &SiaLabel);
}

static bool SetSidIntegrityLevel(PSID pSid, DWORD dwIntLevel)
{
    return SetSystemSidIntegerValue(pSid, &SiaLabel, dwIntLevel);
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

static void UpdateAceVariables(PACE_HEADER pAceHeader, LPBYTE pbPtr)
{
    ACE_HELPER AceHelper;
    LPBYTE pbAce = (LPBYTE)(pAceHeader);

    assert(pAceHeader != NULL);

    if(AceHelper.SetAceType(pAceHeader->AceType))
    {
        // If the ACE is one of the object ACEs, raise the ACL revision
        if(pAceHeader->AceType >= ACCESS_ALLOWED_OBJECT_ACE_TYPE)
            ACL_AclRevision = ACL_REVISION_DS;

        // Update the length of the ACE
        pAceHeader->AceSize = (WORD)(pbPtr - pbAce);

        // If this ACE contains GUID flags, put them in
        if(AceHelper.AceLayout & ACE_FIELD_FLAGS)
            ((PACCESS_ALLOWED_OBJECT_ACE)(pAceHeader))->Flags = ACE_ObjAceFlags;

        // Increment the number of ACEs
        ACL_AceCount++;
    }
}

// The item text is expected to be in format "Name: 0x12345678"
static LPTSTR GetItemTextValue(LPTSTR szItemText, bool bKeepQuotedPart = false)
{
    LPTSTR szTextPtr;

    // Retrieve the first occurence of ":"
    if((szTextPtr = _tcschr(szItemText, _T(':'))) != NULL)
    {
        // Skip the colon
        szItemText = szTextPtr + 1;

        // Skip spaces
        while(szItemText[0] == ' ')
            szItemText++;

        // If the number is followed by a space, cut it
        if(bKeepQuotedPart == false)
        {
            if((szTextPtr = _tcschr(szItemText, _T(' '))) != NULL)
                szTextPtr[0] = 0;
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
            if(pItemInfo->ToString(pItemInfo, szDataText, _countof(szDataText), pbPtr, pbEnd, &cbMoveBy))
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
// Conversion of String <-> Binary Data: BOOL

static bool ToString_Bool(PTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    if(pbPtr >= pbEnd)
        return false;

    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = sizeof(BYTE);
    StringCchCopy(szBuffer, ccBuffer, pbPtr[0] ? _T("TRUE") : _T("FALSE"));
    return true;
}

//-----------------------------------------------------------------------------
// Conversion of String <-> Binary Data: Hex

static bool ToString_Hex(PTREE_ITEM_INFO pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    ULONG64 dwIntValue = 0;
    ULONG cbMoveBy = 0;

#define FORMAT_VALUE_INTEGER(format, type)                               \
    if((pbPtr + sizeof(type)) > pbEnd) { return false; }                 \
    dwIntValue = *(type *)(pbPtr);                                       \
    StringCchPrintf(szBuffer, ccBuffer, _T(format), (type)(dwIntValue)); \
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

        case ItemTypeUint64:
            FORMAT_VALUE_INTEGER("0x%08I64x", ULONG64);
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

static bool StringTo_Hex(PTREE_ITEM_INFO pItemInfo, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
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

static bool ToString_TrustLevel(PTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    DWORD dwTrustLevel1;
    DWORD dwTrustLevel2;
    ULONG cbMoveBy = 0;

    if((pbPtr + sizeof(DWORD64)) <= pbEnd)
    {
        dwTrustLevel1 = *(LPDWORD)(pbPtr + 0);
        dwTrustLevel2 = *(LPDWORD)(pbPtr + 4);
        StringCchPrintf(szBuffer, ccBuffer, _T("%08x-%08x"), dwTrustLevel1, dwTrustLevel2);
        cbMoveBy = sizeof(DWORD64);
    }

    // Give the pcbMoveBy
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return (cbMoveBy != 0);
}

//-----------------------------------------------------------------------------
// Conversion of LPWSTR to string

static bool ToString_STR(PTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE /* pbEnd */, PULONG pcbMoveBy = NULL)
{
    LPWSTR szString = (LPWSTR)(pbPtr);

    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = (ULONG)((wcslen(szString) + 1) * sizeof(WCHAR));
    StringCchPrintf(szBuffer, ccBuffer, _T("\"%s\""), szString);
    return true;
}

//-----------------------------------------------------------------------------
// Conversion of OCTET_STRING to string

static bool ToString_Octs(PTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
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
                szBuffer[2] = _T(' ');
                szBuffer += 3;
                pbPtr++;
            }
            szBuffer[0] = 0;

            // Give the result to the caller
            if(pcbMoveBy != NULL)
                pcbMoveBy[0] = OctetStringSize(pOctetString);
            return true;
        }
    }
    return false;
}

//-----------------------------------------------------------------------------
// Conversion of String <-> Binary Data: SID

static TREE_ITEM_INFO ItemType_IntLevel = {ItemTypeUint32,  0, IDS_FORMAT_INT_LEVEL, IntgrLevels};
static TREE_ITEM_INFO ItemType_PolicyId = {ItemTypeUint32,  0, IDS_FORMAT_POLICY_ID};
static TREE_ITEM_INFO ItemType_TrustLev = {ItemTypeUint32,  0, IDS_FORMAT_TRUST_LEVEL};

static bool ToString_Sid(PTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    LPBYTE pbIntValue;
    ULONG cbMoveBy = 0;

    // If there is a SID, format it to the buffer
    if(pbPtr && pbEnd > pbPtr)
    {
        PSID_IDENTIFIER_AUTHORITY pSia;
        PSID pSid = (PSID)(pbPtr);

        // Determine the SID type by the authority
        pSia = GetSidIdentifierAuthority(pSid);

        // Is it a mandatory label?
        if(!memcmp(pSia, &SiaLabel, sizeof(SID_IDENTIFIER_AUTHORITY)))
        {
            if((pbIntValue = GetSidIntegrityLevel(pSid)) != NULL)
                ToString_Hex(&ItemType_IntLevel, szBuffer, ccBuffer, pbIntValue, pbIntValue + sizeof(DWORD));
            cbMoveBy = RtlLengthSid(pSid);
        }
        else if(!memcmp(pSia, &SiaPolicy, sizeof(SID_IDENTIFIER_AUTHORITY)))
        {
            if((pbIntValue = GetSidScopedPolicyId(pSid)) != NULL)
                ToString_Hex(&ItemType_PolicyId, szBuffer, ccBuffer, pbIntValue, pbIntValue + sizeof(DWORD));
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
        rsprintf(szBuffer, ccBuffer, IDS_NOT_PRESENT);
    }

    // Give the length to move
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return TRUE;
}

static bool ToString_Sidn(PTREE_ITEM_INFO pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    ULONG cbLength = 0;
    bool bResult = false;

    // Enough data to cover 32-bit int?
    if((pbPtr + sizeof(ULONG)) <= pbEnd)
    {
        // Copy the length
        memcpy(&cbLength, pbPtr, sizeof(ULONG));
        pbPtr += sizeof(ULONG);

        // Give the result to the caller
        if(pcbMoveBy != NULL)
            pcbMoveBy[0] = sizeof(ULONG) + cbLength;
        bResult = ToString_Sid(pItemInfo, szBuffer, ccBuffer, pbPtr, pbPtr + cbLength);

    }
    return bResult;
}

static bool StringTo_Sid(PTREE_ITEM_INFO pItemInfo, LPCTSTR szText, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    SID_NAME_USE SidNameUse;
    TCHAR szDomainName[256];
    DWORD ccDomainName = _countof(szDomainName);
    DWORD cbSid = (ULONG)(pbEnd - pbPtr);
    PSID pSid = NULL;
    bool bResult = false;

    // Mandatory SIDs have just integrity level
    if(pItemInfo->ItemType == ItemTypeSid11)
    {
        DWORD dwIntLevel = SECURITY_MANDATORY_MEDIUM_RID;

        if(StringTo_Hex(&ItemType_IntLevel, szText, (LPBYTE)(&dwIntLevel), (LPBYTE)(&dwIntLevel) + sizeof(ULONG)))
        {
            if((pSid = ACE_HELPER::GetDefaultSid(SYSTEM_MANDATORY_LABEL_ACE_TYPE)) != NULL)
            {
                if((bResult = CopyDataAway(pbPtr, pbEnd, pSid, cbSid, pcbMoveBy)) != ERROR_SUCCESS)
                {
                    SetSidIntegrityLevel((PSID)(pbPtr), dwIntLevel);
                }
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

static bool CreateNew_Sid(PTREE_ITEM_INFO /* pItemInfo */, LPBYTE pbDataBuffer, size_t * pcbDataBuffer)
{
    PSID pSid;
    size_t cbDataBuffer = pcbDataBuffer[0];
    bool bResult = false;

    // Create new SID
    if((pSid = ACE_HELPER::GetDefaultSid()) != NULL)
    {
        ULONG SidLength = RtlLengthSid(pSid);

        if(SidLength <= cbDataBuffer)
        {
            memcpy(pbDataBuffer, pSid, SidLength);
            pcbDataBuffer[0] = SidLength;
            bResult = true;
        }
    }
    return bResult;
}

//-----------------------------------------------------------------------------
// Conversion of String <-> Binary Data: GUID

// Get GUID from object-based ACEs, like ACCESS_ALLOWED_OBJECT_ACE
// * ACCESS_ALLOWED_OBJECT_ACE::ObjectType is only present if ACE_OBJECT_TYPE_PRESENT
// * ACCESS_ALLOWED_OBJECT_ACE::InheritedObjectType is only present if ACE_INHERITED_OBJECT_TYPE_PRESENT
static bool ToString_Guid(PTREE_ITEM_INFO pItemInfo, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    ULONG FlagToTest = (pItemInfo->ItemType == ItemTypeGuid2) ? ACE_INHERITED_OBJECT_TYPE_PRESENT : ACE_OBJECT_TYPE_PRESENT;
    ULONG cbMoveBy = 0;
    bool bResult = false;

    // Only present if the 
    if(ACE_ObjAceFlags & FlagToTest)
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

static bool StringTo_Guid(PTREE_ITEM_INFO pItemInfo, LPCTSTR szString, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    ULONG cbMoveBy = 0;

    // If the GUID is not present, we do not store anything
    if(pItemInfo->ItemData == ItemDataNULL)
    {
        if(pcbMoveBy != NULL)
            pcbMoveBy[0] = 0;
        return true;
    }

    // Check for free space
    if((pbPtr + sizeof(GUID)) <= pbEnd)
    {
        if(StringToGuid(szString, (LPGUID)(pbPtr)))
        {
            if(pItemInfo->ItemType == ItemTypeGuid)
                ACE_ObjAceFlags |= ACE_OBJECT_TYPE_PRESENT;
            if(pItemInfo->ItemType == ItemTypeGuid2)
                ACE_ObjAceFlags |= ACE_INHERITED_OBJECT_TYPE_PRESENT;
            cbMoveBy = sizeof(GUID);
        }
    }

    // Give the pcbMoveBy
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return (cbMoveBy != 0);
}


static bool CreateNew_Guid(PTREE_ITEM_INFO pItemInfo, LPBYTE pbDataBuffer, size_t * pcbDataBuffer)
{
    size_t cbDataBuffer = pcbDataBuffer[0];
    ULONG FlagToSet = (pItemInfo->ItemType == ItemTypeGuid2) ? ACE_INHERITED_OBJECT_TYPE_PRESENT : ACE_OBJECT_TYPE_PRESENT;
    bool bResult = false;

    // Create new NULL GUID
    if(cbDataBuffer >= sizeof(GUID))
    {
        memset(pbDataBuffer, 0, sizeof(GUID));
        ACE_ObjAceFlags |= FlagToSet;
        pcbDataBuffer[0] = sizeof(GUID);
        bResult = true;
    }
    return bResult;
}

static bool ToString_Cnd(PTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
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

static bool StringTo_Saved(PTREE_ITEM_INFO pItemInfo, LPCTSTR /* szText */, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
{
    PNON_EDITABLE_DATA pData;

    // Did we store the raw condition?
    if((pData = IsItemDataPointer(pItemInfo->ItemData)) != NULL)
    {
        if((pbPtr + pData->Length) <= pbEnd)
        {
            return CopyDataAway(pbPtr, pbEnd, pData->Data, pData->Length, pcbMoveBy);
        }
        return true;
    }
    return false;
}

static bool ToString_Ace(PTREE_ITEM_INFO /* pItemInfo */, LPTSTR szBuffer, size_t ccBuffer, LPBYTE pbPtr, LPBYTE pbEnd, PULONG pcbMoveBy = NULL)
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
        if((pSid = ACE_HELPER::GetDefaultSid(pAce->Header.AceType)) != NULL)
        {
            // Retrieve the length of the SID
            cbSid = RtlLengthSid(pSid);

            // Enough space for the SID?
            if((pbPtr + cbSid) <= pbEnd)
            {
                // Copy the SID to the ACE
                memcpy(pbPtr, pSid, cbSid);
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

static bool CreateNew_Acl(PTREE_ITEM_INFO pItemInfo, LPBYTE pbDataBuffer, size_t * pcbDataBuffer)
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
static TREE_ITEM_INFO TreeItem_NullAcl  = {ItemTypeNullAcl, IDS_NULL_ACL,     IDS_FORMAT_STR,       NULL,        NULL,         NULL,         CreateNew_Acl};
static TREE_ITEM_INFO TreeItem_NoAcl    = {ItemTypeNoAcl,   IDS_NOT_PRESENT,  IDS_FORMAT_STR,       NULL,        NULL,         NULL,         CreateNew_Acl};
static TREE_ITEM_INFO TreeItem_UserSid  = {ItemTypeSid,     IDS_NOT_PRESENT,  IDS_FORMAT_SID,       NULL,        ToString_Sid, StringTo_Sid, CreateNew_Sid};
static TREE_ITEM_INFO TreeItem_AclRev   = {ItemTypeUint08,  0,                IDS_FORMAT_ACL_REVIS, AclRevFlags, ToString_Hex, StringTo_Hex};
static TREE_ITEM_INFO TreeItem_AclSbz1  = {ItemTypeUint08,  0,                IDS_FORMAT_ACL_SBZ1,  NULL,        ToString_Hex, StringTo_Hex};
static TREE_ITEM_INFO TreeItem_AclSize  = {ItemTypeUint16,  0,                IDS_FORMAT_ACL_SIZE,  NULL,        ToString_Hex, StringTo_Hex};
static TREE_ITEM_INFO TreeItem_AceCnt   = {ItemTypeUint16,  0,                IDS_FORMAT_ACL_COUNT, NULL,        ToString_Hex, StringTo_Hex};
static TREE_ITEM_INFO TreeItem_AclSbz2  = {ItemTypeUint16,  0,                IDS_FORMAT_ACL_SBZ2,  NULL,        ToString_Hex, StringTo_Hex};
static TREE_ITEM_INFO TreeItem_Ace      = {ItemTypeAce,     IDS_NULL_ACL,     IDS_FORMAT_STR,       NULL,        ToString_Ace};

static TREE_ITEM_INFO TreeItem_CSA_Name = {ItemTypeLPWSTR,  0,                IDS_FORMAT_NAME,      NULL,        ToString_STR};
static TREE_ITEM_INFO TreeItem_CSA_VTyp = {ItemTypeUint16,  0,                IDS_FORMAT_VALTYPE,   CSA_ValTypes,ToString_Hex};
static TREE_ITEM_INFO TreeItem_CSA_Res  = {ItemTypeUint16,  0,                IDS_FORMAT_RESERVED,  NULL,        ToString_Hex};
static TREE_ITEM_INFO TreeItem_CSA_Flgs = {ItemTypeUint32,  0,                IDS_FORMAT_FLAGS,     CSA_Flags,   ToString_Hex};
static TREE_ITEM_INFO TreeItem_CSA_VCnt = {ItemTypeUint32,  0,                IDS_FORMAT_VALCOUNT,  NULL,        ToString_Hex};
static TREE_ITEM_INFO TreeItem_CSA_U64  = {ItemTypeUint64,  IDS_FORMAT_VALUE, IDS_FORMAT_VALINDEX,  NULL,        ToString_Hex};
static TREE_ITEM_INFO TreeItem_CSA_STR  = {ItemTypeLPWSTR,  IDS_FORMAT_VALUE, IDS_FORMAT_VALINDEX,  NULL,        ToString_STR};
static TREE_ITEM_INFO TreeItem_CSA_SID  = {ItemTypeCSASid,  IDS_FORMAT_VALUE, IDS_FORMAT_VALINDEX,  NULL,        ToString_Sidn};
static TREE_ITEM_INFO TreeItem_CSA_BOOL = {ItemTypeBool,    IDS_FORMAT_VALUE, IDS_FORMAT_VALINDEX,  NULL,        ToString_Bool};
static TREE_ITEM_INFO TreeItem_CSA_Octs = {ItemTypeOctStr,  IDS_FORMAT_VALUE, IDS_FORMAT_VALINDEX,  NULL,        ToString_Octs};


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
    {ACE_FIELD_HTYPE,           {ItemTypeUint08,    0, IDS_FORMAT_ACE_HTYPE,  AceHdrTypes, ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_HFLAGS,          {ItemTypeUint08,    0, IDS_FORMAT_ACE_HFLAGS, AceHdrFlags, ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_HSIZE,           {ItemTypeUint16,    0, IDS_FORMAT_ACE_HSIZE,  NULL,        ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_ACCESS_MASK,     {ItemTypeUint32,    0, IDS_FORMAT_ACE_MASK,   AceMasks,    ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_ADS_ACCESS_MASK, {ItemTypeUint32,    0, IDS_FORMAT_ACE_MASK,   AdsAceMasks, ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_MANDATORY_MASK,  {ItemTypeUint32,    0, IDS_FORMAT_ACE_MASK,   LabelMasks,  ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_FLAGS,           {ItemTypeUint32,    0, IDS_FORMAT_ACE_FLAGS,  ObjAceFlags, ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_COMPOUND_TYPE,   {ItemTypeUint16,    0, IDS_FORMAT_ACE_CTYPE,  CAceTypes,   ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_COMPOUND_RSVD,   {ItemTypeUint16,    0, IDS_FORMAT_RESERVED,   NULL,        ToString_Hex,  StringTo_Hex}},
    {ACE_FIELD_OBJECT_TYPE1,    {ItemTypeGuid,      0, IDS_FORMAT_OBJ_TYPE,   NULL,        ToString_Guid, StringTo_Guid, CreateNew_Guid}},
    {ACE_FIELD_OBJECT_TYPE2,    {ItemTypeGuid2,     0, IDS_FORMAT_OBJ_TYPEI,  NULL,        ToString_Guid, StringTo_Guid, CreateNew_Guid}},
    {ACE_FIELD_ACCESS_SID,      {ItemTypeSid,       0, IDS_FORMAT_SID,        NULL,        ToString_Sid,  StringTo_Sid}},
    {ACE_FIELD_SERVER_SID,      {ItemTypeSid,       0, IDS_FORMAT_SSID,       NULL,        ToString_Sid,  StringTo_Sid}},
    {ACE_FIELD_CLIENT_SID,      {ItemTypeSid,       0, IDS_FORMAT_CSID,       NULL,        ToString_Sid,  StringTo_Sid}},
    {ACE_FIELD_MANDATORY_SID,   {ItemTypeSid11,     0, IDS_FORMAT_INT_LEVEL,  IntgrLevels, ToString_Sid,  StringTo_Sid}},
    {ACE_FIELD_POLICY_SID,      {ItemTypeSid17,     0, IDS_FORMAT_POLICY_ID,  NULL,        ToString_Sid,  NULL}},
    {ACE_FIELD_TRUST_SID,       {ItemTypeSid19,     0, IDS_FORMAT_TRUST_LEVEL,NULL,        ToString_Sid,  NULL}},
    {ACE_FIELD_CSA_V1,          {ItemTypeCSA_V1,    IDS_FORMAT_CSA_V1,     0, NULL,        NULL,          StringTo_Saved}},
    {ACE_FIELD_CONDITION,       {ItemTypeCondition, 0, IDS_FORMAT_CONDITION,  NULL,        ToString_Cnd,  StringTo_Saved} }
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
                        hInsertAfter = TV_InsertIndexedItem(hWndTree, hParent, TVI_LAST, &TreeItem_CSA_SID, &CsaHelper.ppObjects[i], i);
                        break;

                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
                        hInsertAfter = TV_InsertIndexedItem(hWndTree, hParent, TVI_LAST, &TreeItem_CSA_BOOL, &CsaHelper.ppObjects[i], i);
                        break;

                    case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
                        hInsertAfter = TV_InsertIndexedItem(hWndTree, hParent, TVI_LAST, &TreeItem_CSA_Octs, &CsaHelper.ppObjects[i], i);
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

    // Special: Save the value of XXX_YYY_OBJECT_ACE::Flags
    if(AceHelper.AceLayout & ACE_FIELD_FLAGS)
        ACE_ObjAceFlags = AceHelper.Flags;

    // Insert all ACE members according to the bit mask in the ace helper
    for(size_t i = 0; i < _countof(AceFieldInfos); i++)
    {
        ULONG cbMoveBy = 0;

        // Special: Save the value of XXX_YYY_OBJECT_ACE::Flags
        if((AceHelper.AceLayout & ACE_FIELD_FLAGS) && (AceFieldInfos[i].AceLayoutFlag == ACE_FIELD_FLAGS))
            ACE_ObjAceFlags = AceHelper.Flags;

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

    // Reset the XXX_YYY_OBJECT_ACE::Flags
    ACE_ObjAceFlags = 0;

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
    ACE_ObjAceFlags = 0;
    return hAceItem;
}

static HTREEITEM TV_InsertNewItemAclFields(
    HWND hWndTree,
    HTREEITEM hParent,
    HTREEITEM hInsertAfter,
    const ACL * pAcl)
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

static bool TV_ItemsToData(
    HWND hWndTree,
    HTREEITEM hParent,
    LPBYTE pbPtr,
    LPBYTE pbEnd,
    PULONG pcbMoveBy = NULL)
{
    PTREE_ITEM_INFO pParentInfo = TV_GetItemParam(hWndTree, hParent);
    PTREE_ITEM_INFO pItemInfo;
    PACE_HEADER pAceHeader = NULL;
    HTREEITEM hItem = TreeView_GetChild(hWndTree, hParent);
    LPBYTE pbBegin = pbPtr;

    // If we're starting an ACE, then remember the ACE header
    if(pParentInfo && pParentInfo->ItemType == ItemTypeAce)
        pAceHeader = (PACE_HEADER)(pbPtr);

    // Keep going over all siblings
    while(hItem != NULL)
    {
        TCHAR szItemText[256] = {0};
        ULONG cbMoveBy = 0;
        bool bResult = false;

        // Retrieve the item info
        if((pItemInfo = TV_GetItemParamAndText(hWndTree, hItem, szItemText, _countof(szItemText))) != NULL)
        {
            // When we encountered an object ACE, we reset the flags
            if(pItemInfo->nIDFormat2 == IDS_FORMAT_ACE_FLAGS)
                ACE_ObjAceFlags = 0;

            // If there is a child item, go recursively on the children
            if(TreeView_GetChild(hWndTree, hItem) != NULL)
            {
                // Retrieve items from all children
                if((bResult = TV_ItemsToData(hWndTree, hItem, pbPtr, pbEnd, &cbMoveBy)) == FALSE)
                {
                    // Try to use normal StringTo
                    if(pItemInfo->StringTo != NULL)
                    {
                        bResult = pItemInfo->StringTo(pItemInfo, szItemText, pbPtr, pbEnd, &cbMoveBy);
                    }
                }
            }
            else
            {
                // The item must have conversion routine, otherwise we bail out
                if(pItemInfo->StringTo != NULL)
                {
                    bResult = pItemInfo->StringTo(pItemInfo, GetItemTextValue(szItemText), pbPtr, pbEnd, &cbMoveBy);
                }
            }
        }

        // If the operation failed, bail out
        if(bResult == false)
            return false;

        // Move the data pointer and the tree item
        hItem = TreeView_GetNextSibling(hWndTree, hItem);
        pbPtr += cbMoveBy;
    }

    // When an ACE is being finished, fill some variables that depend on ACE layout and size
    if(pAceHeader != NULL)
        UpdateAceVariables(pAceHeader, pbPtr);

    // Give length of the data to the caller
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = (ULONG)(pbPtr - pbBegin);
    return true;
}

static void TV_ResetAceItem(HWND hWndTree, HTREEITEM hItem, LPBYTE pbAceData, ULONG cbAceData)
{
    PACE_HEADER pAceHeader = (PACE_HEADER)(pbAceData);
    ACE_HELPER AceHelper;
    TCHAR szItemText[256];

    // Init the item text
    GetAceTypeString(szItemText, _countof(szItemText), pAceHeader);
    TreeView_SetItemText(hWndTree, hItem, szItemText);

    // Init the subitems
    AceHelper.SetAce(pAceHeader);
    TV_InsertNewItemAceFields(hWndTree, hItem, AceHelper, pbAceData, pbAceData + cbAceData);
}

static void TV_SwapItems(HWND hWndTree, HTREEITEM hItem1, HTREEITEM hItem2)
{
    ULONG cbAceData1 = 0;
    ULONG cbAceData2 = 0;
    BYTE AceData1[0x200];
    BYTE AceData2[0x200];

    // Disable redraw
    SendMessage(hWndTree, WM_SETREDRAW, FALSE, 0);

    // Read the data from the first item
    if(TV_ItemsToData(hWndTree, hItem1, AceData1, AceData1 + sizeof(AceData1), &cbAceData1))
    {
        // Read the data from the second item
        if(TV_ItemsToData(hWndTree, hItem2, AceData2, AceData2 + sizeof(AceData2), &cbAceData2))
        {
            // Initialize the item texts
            TV_ResetAceItem(hWndTree, hItem1, AceData2, cbAceData2);
            TV_ResetAceItem(hWndTree, hItem2, AceData1, cbAceData1);
        }
    }

    // Enable redrawing and paint
    SendMessage(hWndTree, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hWndTree, NULL, TRUE);
}

static PACL TreeView_ItemToAcl(HWND hWndTree, HTREEITEM hParent)
{
    LPBYTE pbAcl;
    ULONG cbMoveBy = 0;

    // Allocate buffer for the entire ACL
    if((pbAcl = (LPBYTE)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, MAX_ACL_LENGTH)) != NULL)
    {
        // Reset the ACE count
        ACL_AclRevision = ACL_REVISION2;
        ACL_AceCount = 0;

        // Process the ACL
        if(TV_ItemsToData(hWndTree, hParent, pbAcl, pbAcl + MAX_ACL_LENGTH, &cbMoveBy))
        {
            PACL pAcl = (PACL)(pbAcl);

            pAcl->AclRevision = ACL_AclRevision;
            pAcl->AceCount = ACL_AceCount;
            pAcl->AclSize = (WORD)(cbMoveBy);
        }
    }
    return (PACL)(pbAcl);
}

static bool TreeView_ItemToAcl(
    HWND hWndTree,
    HTREEITEM hParent,
    PACL * ppAcl,
    BOOLEAN * pbAclPresent)
{
    PTREE_ITEM_INFO pItemInfo;
    HTREEITEM hItem = TreeView_GetChild(hWndTree, hParent);

    // Retrieve the item information
    if((pItemInfo = TV_GetItemParam(hWndTree, hItem)) != NULL)
    {
        switch(pItemInfo->ItemType)
        {
            case ItemTypeNoAcl:
                pbAclPresent[0] = FALSE;
                ppAcl[0] = NULL;
                return true;

            case ItemTypeNullAcl:
                pbAclPresent[0] = TRUE;
                ppAcl[0] = NULL;
                return true;

            default:
                ppAcl[0] = TreeView_ItemToAcl(hWndTree, hParent);
                pbAclPresent[0] = TRUE;
                return (ppAcl[0] != NULL);
        }
    }

    return false;
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
    PACE_HEADER pAceHeader = NULL;
    HTREEITEM hItem;
    DWORD dwAceType = ACCESS_ALLOWED_ACE_TYPE;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    TCHAR szItemText[256];
    BYTE AceBuffer[256];

    if((hItem = TreeView_GetSelection(hWndTree)) != NULL)
    {
        if((pItemInfo = TV_GetItemParamAndText(hWndTree, hItem, szItemText, _countof(szItemText))) != NULL)
        {
            // Ask the user for new ACE type
            if(FlagsDialog(hDlg, IDS_ACE_TYPE, AceHdrTypes, szItemText, dwAceType) == IDOK)
            {
                ACE_HELPER AceHelper(dwAceType);

                // Stop redrawing
                SendMessage(hWndTree, WM_SETREDRAW, FALSE, 0);

                // Build the ACE
                if((pAceHeader = AceHelper.Export(AceBuffer, sizeof(AceBuffer))) != NULL)
                {
                    // Build the ACE into the item
                    TV_ResetAceItem(hWndTree, hItem, AceBuffer, pAceHeader->AceSize);

                    // Select the root item
                    TreeView_SelectItem(hWndTree, hItem);
                }
                else
                {
                    SetResultInfo(hDlg, RSI_NTSTATUS, STATUS_CANNOT_EDIT_THIS);
                }

                // Enable redrawing back
                SendMessage(hWndTree, WM_SETREDRAW, TRUE, 0);
                InvalidateRect(hWndTree, NULL, TRUE);
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
                TV_InsertNewItemAclFields(hWndTree, hParent, TVI_LAST, &EmptyAcl);
                TreeView_Select(hWndTree, hParent, TVGN_CARET);
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

    if(pData->SecurityInformation & OWNER_SECURITY_INFORMATION)
    {
        if(TV_ItemsToData(hWndTree, hChildItem[0], OwnerSid, OwnerSid + sizeof(OwnerSid)))
        {
            RtlSetOwnerSecurityDescriptor(&sd, (PSID)(OwnerSid), FALSE);
            AppliedSecInfo |= OWNER_SECURITY_INFORMATION;
        }
    }

    //
    // Put group into the security descriptor
    //

    if(pData->SecurityInformation & GROUP_SECURITY_INFORMATION)
    {
        if(TV_ItemsToData(hWndTree, hChildItem[1], GroupSid, GroupSid + sizeof(GroupSid)))
        {
            RtlSetGroupSecurityDescriptor(&sd, (PSID)(GroupSid), FALSE);
            AppliedSecInfo |= GROUP_SECURITY_INFORMATION;
        }
    }

    //
    // Put DACL into the security descriptor
    //

    if(pData->SecurityInformation & DACL_SECURITY_INFORMATION)
    {
        if(TreeView_ItemToAcl(hWndTree, hChildItem[2], &pDacl, &bDaclPresent))
        {
            RtlSetDaclSecurityDescriptor(&sd, bDaclPresent, pDacl, FALSE);
            AppliedSecInfo |= DACL_SECURITY_INFORMATION;
        }
    }

    //
    // Put SACL into the security descriptor
    //

    if(pData->SecurityInformation & ALL_SACL_SECURITY_INFORMATION)
    {
        if(TreeView_ItemToAcl(hWndTree, hChildItem[3], &pSacl, &bSaclPresent))
        {
            RtlSetSaclSecurityDescriptor(&sd, bSaclPresent, pSacl, FALSE);
            AppliedSecInfo |= (pData->SecurityInformation & ALL_SACL_SECURITY_INFORMATION);
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
        if(pItemInfo->ItemType != ItemTypeCondition)
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

                // Set the result
                if(bAcceptChanges == FALSE)
                    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_INFO_INT32, STATUS_INVALID_DATA_FORMAT, 0);
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
    TREE_ITEM_INFO SaveItemInfo;
    HTREEITEM hInsertAfter = TVI_FIRST;
    HTREEITEM hParent;
    HTREEITEM hItem;
    HWND hWndTree = GetDlgItem(hDlg, IDC_SECURITY);
    BYTE DataBuffer[0x200];
    size_t cbDataBuffer = sizeof(DataBuffer);

    // Reset the XXX_YYY_OBJECT_ACE::Flags
    ACE_ObjAceFlags = 0;

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
