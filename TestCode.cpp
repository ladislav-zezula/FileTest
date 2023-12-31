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

#ifdef __TEST_MODE__

typedef struct _OCTET_STRING_07
{
    ULONG Length;
    BYTE Data[0x07];
} OCTET_STRING_07, *POCTET_STRING_07;

typedef struct _OCTET_STRING_11
{
    ULONG Length;
    BYTE Data[0x11];
} OCTET_STRING_11, *POCTET_STRING_11;

typedef struct _OCTET_STRING_SID
{
    ULONG Length;
    BYTE Sid[MAX_SID_LENGTH];
} OCTET_STRING_SID, *POCTET_STRING_SID;

static const GUID NullGuid = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};

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
/*
static PSID GetUserSid(LPCTSTR szUserName, LPDWORD pcbSid)
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
*/

static OCTET_STRING_SID MakeOctetSid(LPCBYTE pbSid, size_t cbSid)
{
    OCTET_STRING_SID OctetSid;

    memcpy(OctetSid.Sid, pbSid, cbSid);
    OctetSid.Length = cbSid;
    return OctetSid;
}

static PACE_HEADER AddAce(
    PACL pAcl,
    BYTE AceType,
    PSID pSid = NULL)
{
    return ACE_HELPER(AceType, pSid).AddToAcl(pAcl);
}

static PACE_HEADER AddAce(
    PACL pAcl,
    BYTE AceType,
    LPCGUID pGuid1,
    LPCGUID pGuid2 = NULL)
{
    ACE_HELPER AceHelper(AceType);

    // Append object type GUID
    if(pGuid1 != NULL)
    {
        memcpy(&AceHelper.ObjectType, pGuid1, sizeof(GUID));
        AceHelper.Flags |= ACE_OBJECT_TYPE_PRESENT;
    }

    // Append object type GUID
    if(pGuid2 != NULL)
    {
        memcpy(&AceHelper.InheritedObjectType, pGuid2, sizeof(GUID));
        AceHelper.Flags |= ACE_INHERITED_OBJECT_TYPE_PRESENT;
    }

    // Add the ACE to the ACL
    return AceHelper.AddToAcl(pAcl);
}

static PACE_HEADER AddAce(
    PACL pAcl,
    BYTE AceType,
    LPCVOID lpCondition,
    size_t cbCondition)
{
    ACE_HELPER AceHelper(AceType);

    // Capture the condition
    AceHelper.SetCondition((LPVOID)lpCondition, cbCondition);

    // Add the ACE to the ACL
    return AceHelper.AddToAcl(pAcl);
}

static PACE_HEADER AddAce(
    PACL pAcl,
    PSID pSid, 
    ACE_CSA_HELPER & CsaHelper)
{
    ACE_HELPER AceHelper(CsaHelper, pSid);

    return AceHelper.AddToAcl(pAcl);
}

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

PACL CreateDacl(PSID pSidAdmin)
{
    PACL pAcl;
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;

    // Allocate space for ACL
    if((pAcl = (PACL)LocalAlloc(LPTR, MAX_ACL_LENGTH)) != NULL)
    {
        if((Status = RtlCreateAcl(pAcl, MAX_ACL_LENGTH, ACL_REVISION_DS)) == STATUS_SUCCESS)
        {
            PACE_HEADER pAceHeader;
            ULONG cbAclSize = sizeof(ACL);

            if((pAceHeader = AddAce(pAcl, ACCESS_ALLOWED_ACE_TYPE)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = AddAce(pAcl, ACCESS_DENIED_ACE_TYPE, pSidAdmin)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = AddAce(pAcl, ACCESS_ALLOWED_COMPOUND_ACE_TYPE, pSidAdmin)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = AddAce(pAcl, ACCESS_ALLOWED_OBJECT_ACE_TYPE)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = AddAce(pAcl, ACCESS_ALLOWED_OBJECT_ACE_TYPE, &NullGuid)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = AddAce(pAcl, ACCESS_ALLOWED_OBJECT_ACE_TYPE, &NullGuid, &NullGuid)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = AddAce(pAcl, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, Condition1, sizeof(Condition1))) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = AddAce(pAcl, ACCESS_DENIED_CALLBACK_ACE_TYPE, Condition2, sizeof(Condition2))) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            pAcl->AclSize = (WORD)(cbAclSize);
        }
    }
    return pAcl;
}

PACL CreateCustomAcl(SECURITY_INFORMATION & SecurityInfo, PSID pSidEveryone)
{
    PACL pAcl;
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;

    // Allocate space for ACL
    if((pAcl = (PACL)LocalAlloc(LPTR, MAX_ACL_LENGTH)) != NULL)
    {
        if((Status = RtlCreateAcl(pAcl, MAX_ACL_LENGTH, ACL_REVISION_DS)) == STATUS_SUCCESS)
        {
            OCTET_STRING_SID OctetStringSid1 = MakeOctetSid(SidLocAdmins, sizeof(SidLocAdmins));
            OCTET_STRING_SID OctetStringSid2 = MakeOctetSid(SidLocUsers, sizeof(SidLocUsers));
            OCTET_STRING_SID OctetStringSid3 = MakeOctetSid(SidEveryone, sizeof(SidEveryone));
            OCTET_STRING_07 OctetString07 = {0x07, {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}};
            OCTET_STRING_11 OctetString11 = {0x11, {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x3C, 0x4D, 0x01, 0x02, 0x03, 0x04}};
            ACE_CSA_HELPER CsaHelper;
            PACE_HEADER pAceHeader;
            WORD cbAclSize = sizeof(ACL);

            if((pAceHeader = AddAce(pAcl, ACCESS_ALLOWED_ACE_TYPE, pSidEveryone)) != NULL)
            {
                SecurityInfo |= DACL_SECURITY_INFORMATION;
                cbAclSize = cbAclSize + pAceHeader->AceSize;
            }
/*
            if((pAceHeader = AddAce(pAcl, SYSTEM_MANDATORY_LABEL_ACE_TYPE)) != NULL)
            {
                SecurityInfo |= LABEL_SECURITY_INFORMATION;
                cbAclSize = cbAclSize + pAceHeader->AceSize;
            }
*/
            CsaHelper.Create(L"RESOURCE_ITEM_I64_VALUES", CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64, 3, 0xDEADBABFULL, 0x02ULL, 0x1234567812345679ULL);
            CsaHelper.Flags = CLAIM_SECURITY_ATTRIBUTE_NON_INHERITABLE | CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY;
            if((pAceHeader = AddAce(pAcl, pSidEveryone, CsaHelper)) != NULL)
            {
                SecurityInfo |= ATTRIBUTE_SECURITY_INFORMATION;
                cbAclSize = cbAclSize + pAceHeader->AceSize;
            }

            CsaHelper.Create(L"RESOURCE_ITEM_U64_VALUES", CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64, 3, 0xDEADBABEULL, 0x01ULL, 0x1234567812345678ULL);
            CsaHelper.Flags = CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;
            if((pAceHeader = AddAce(pAcl, pSidEveryone, CsaHelper)) != NULL)
            {
                SecurityInfo |= ATTRIBUTE_SECURITY_INFORMATION;
                cbAclSize = cbAclSize + pAceHeader->AceSize;
            }

            CsaHelper.Create(L"RESOURCE_ITEM_STRINGS", CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING, 4, L"DAENERYS", L"TARGARYEN", L"EDDARD", L"WINTERFELL");
            CsaHelper.Flags = CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;
            if((pAceHeader = AddAce(pAcl, pSidEveryone, CsaHelper)) != NULL)
            {
                SecurityInfo |= ATTRIBUTE_SECURITY_INFORMATION;
                cbAclSize = cbAclSize + pAceHeader->AceSize;
            }

            CsaHelper.Create(L"RESOURCE_ITEM_SIDS", CLAIM_SECURITY_ATTRIBUTE_TYPE_SID, 3, &OctetStringSid1, &OctetStringSid2, &OctetStringSid3);
            CsaHelper.Flags = 0;
            if((pAceHeader = AddAce(pAcl, pSidEveryone, CsaHelper)) != NULL)
            {
                SecurityInfo |= ATTRIBUTE_SECURITY_INFORMATION;
                cbAclSize = cbAclSize + pAceHeader->AceSize;
            }

            CsaHelper.Create(L"RESOURCE_ITEM_BOOLEANS", CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN, 4, TRUE, TRUE, FALSE, FALSE);
            CsaHelper.Flags = 0;
            if((pAceHeader = AddAce(pAcl, pSidEveryone, CsaHelper)) != NULL)
            {
                SecurityInfo |= ATTRIBUTE_SECURITY_INFORMATION;
                cbAclSize = cbAclSize + pAceHeader->AceSize;
            }

            CsaHelper.Create(L"RESOURCE_ITEM_OCTET_STRINGS", CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING, 2, &OctetString07, &OctetString11);
            CsaHelper.Flags = 0;
            if((pAceHeader = AddAce(pAcl, pSidEveryone, CsaHelper)) != NULL)
            {
                SecurityInfo |= ATTRIBUTE_SECURITY_INFORMATION;
                cbAclSize = cbAclSize + pAceHeader->AceSize;
            }
/*
            if((pAceHeader = AddAce(pAcl, SYSTEM_SCOPED_POLICY_ID_ACE_TYPE)) != NULL)
            {
                SecurityInfo |= SCOPE_SECURITY_INFORMATION;
                cbAclSize = cbAclSize + pAceHeader->AceSize;
            }

            if((pAceHeader = AddAce(pAcl, SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, FILE_READ_DATA)) != NULL)
            {
                SecurityInfo |= PROCESS_TRUST_LABEL_SECURITY_INFORMATION;
                cbAclSize = cbAclSize + pAceHeader->AceSize;
            }

            if((pAceHeader = AddAce(pAcl, SYSTEM_ACCESS_FILTER_ACE_TYPE, FILE_READ_DATA, (PSID)SidEveryone)) != NULL)
            {
                SecurityInfo |= ACCESS_FILTER_SECURITY_INFORMATION;
                cbAclSize = cbAclSize + pAceHeader->AceSize;
            }
*/
            pAcl->AclSize = cbAclSize;
        }
    }
    return pAcl;
}

static DWORD SetCustomSecurityDescriptor(HANDLE hObject)
{
    SECURITY_INFORMATION SecurityInfo = 0;
    SECURITY_DESCRIPTOR sd;
    NTSTATUS Status = STATUS_SUCCESS;
    PACL pAcl = NULL;

    UNREFERENCED_PARAMETER(hObject);

    // Initialize the blank security descriptor
    Status = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    if(NT_SUCCESS(Status))
    {
        // Create custom ACL
        if((pAcl = CreateCustomAcl(SecurityInfo, (PSID)(SidEveryone))) != NULL)
        {
            // Set the ACL to the security descriptor
            Status = RtlSetDaclSecurityDescriptor(&sd, TRUE, pAcl, FALSE);
            if(NT_SUCCESS(Status))
            {
                // Set the security descriptor to the object
                Status = NtSetSecurityObject(hObject, DACL_SECURITY_INFORMATION, &sd);
            }
            LocalFree(pAcl);
        }
        else
        {
            Status = STATUS_NO_MEMORY;
        }
    }
    return Status;
}

void SetCustomSecurityDescriptor(LPCTSTR szPath)
{
    HANDLE hFolder;

    // Make sure that the folder exists
    ForcePathExist(szPath, TRUE);

    // Open the folder and set security descriptor
    hFolder = CreateFile(szPath, READ_CONTROL | WRITE_DAC | WRITE_OWNER, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if(hFolder != INVALID_HANDLE_VALUE)
    {
        SetCustomSecurityDescriptor(hFolder);
        CloseHandle(hFolder);
    }
}

void LoadSpecialSecurityDescriptor(LPCTSTR szPath)
{
    HANDLE hFolder;

    // Open the folder and set security descriptor
    hFolder = CreateFile(szPath, GENERIC_ALL | READ_CONTROL | WRITE_DAC | WRITE_OWNER, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if(hFolder != INVALID_HANDLE_VALUE)
    {
        PSECURITY_DESCRIPTOR pSD;
        BOOLEAN bSaclPresent = FALSE;
        BOOLEAN bTemp = FALSE;
        PACL pAcl = NULL;
        ULONG Length = 0;
        BYTE Buffer[0x1024];

        pSD = (PSECURITY_DESCRIPTOR)(Buffer);
        NtQuerySecurityObject(hFolder, ATTRIBUTE_SECURITY_INFORMATION, pSD, sizeof(Buffer), &Length);

        if(Length != 0)
        {
            RtlGetSaclSecurityDescriptor(pSD, &bSaclPresent, &pAcl, &bTemp);
            if(pAcl != NULL)
            {
                for(WORD i = 0; i < pAcl->AceCount; i++)
                {
                    PSYSTEM_RESOURCE_ATTRIBUTE_ACE pAce = NULL;

                    RtlGetAce(pAcl, i, (PVOID *)(&pAce));

                    if(pAce->Header.AceType == SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE)
                    {
                        PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 pAttrRel;
                        ACE_CSA_HELPER CsaHelper;
                        PSID pSid = (PSID)(&pAce->SidStart);
                        LPBYTE pbAce = (LPBYTE)(pAce);
                        LPBYTE pbPtr = pbAce + FIELD_OFFSET(SYSTEM_RESOURCE_ATTRIBUTE_ACE, SidStart) + RtlLengthSid(pSid);
                        LPBYTE pbEnd = pbAce + pAce->Header.AceSize;
                        ULONG cbRelSize = 0;
                        ULONG cbMoveBy = 0;

                        CsaHelper.Import(pbPtr, pbEnd, &cbRelSize);
                        pAttrRel = CsaHelper.Export(&cbMoveBy);

                        assert(memcmp(pAttrRel, pbPtr, cbMoveBy) == 0);
                        assert(cbMoveBy == cbRelSize);
                    }
                }
            }
        }
        CloseHandle(hFolder);
    }
}

void DebugCode_SecurityDescriptor(LPCTSTR /* szPath */)
{
    EnablePrivilege(SE_TCB_NAME);
    EnablePrivilege(SE_SECURITY_NAME);

    //SetCustomSecurityDescriptor(_T("c:\\VMWARE\\TestValidAcl"));
    //LoadSpecialSecurityDescriptor(_T("c:\\VMWARE\\Test-004-RES_ATTR"));
}
#endif

