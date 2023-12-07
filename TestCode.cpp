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

static const GUID NullGuid = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};

static const BYTE SidEveryone[]  = {0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
static const BYTE SidLocAdmins[] = {0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00};
static const BYTE SidLocUsers[]  = {0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x21, 0x02, 0x00, 0x00};

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

static PACE_HEADER AddAce(
    PACL pAcl,
    BYTE AceType,
    ACCESS_MASK AccessMask = GENERIC_ALL,
    PSID pSid = NULL)
{
    return ACE_HELPER(AceType, AccessMask, pSid).AddToAcl(pAcl);
}

static PACE_HEADER AddAce(
    PACL pAcl,
    BYTE AceType,
    ACCESS_MASK AccessMask,
    LPCGUID pGuid1,
    LPCGUID pGuid2 = NULL)
{
    ACE_HELPER AceHelper(AceType, AccessMask);

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
    ACCESS_MASK AccessMask,
    LPCVOID lpCondition,
    size_t cbCondition)
{
    ACE_HELPER AceHelper(AceType, AccessMask);

    // Capture the condition
    AceHelper.SetCondition((LPVOID)lpCondition, cbCondition);

    // Add the ACE to the ACL
    return AceHelper.AddToAcl(pAcl);
}

static PACE_HEADER AddAce(
    PACL pAcl,
    BYTE AceType,
    ACCESS_MASK AccessMask,
    PSID pSid, 
    ACE_CSA_HELPER & CsaHelper)
{
    PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 pAttrRel;
    ACE_HELPER AceHelper(AceType, AccessMask);
    ULONG cbAttrRel = 0;

    // Set the SID into the ACE helper
    AceHelper.SetSid(pSid, 0);

    // Convert to absolute security attributes
    if((pAttrRel = CsaHelper.Export(&cbAttrRel)) != NULL)
    {
        // Capture the relative ACE
        AceHelper.SetAttributes(pAttrRel, cbAttrRel);
        LocalFree(pAttrRel);
    }

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

            if((pAceHeader = AddAce(pAcl, ACCESS_DENIED_ACE_TYPE, FILE_EXECUTE, pSidAdmin)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = AddAce(pAcl, ACCESS_ALLOWED_COMPOUND_ACE_TYPE, FILE_EXECUTE)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = AddAce(pAcl, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ADS_RIGHT_DS_READ_PROP)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = AddAce(pAcl, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ADS_RIGHT_DS_READ_PROP, &NullGuid)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = AddAce(pAcl, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ADS_RIGHT_DS_READ_PROP, &NullGuid, &NullGuid)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = AddAce(pAcl, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, FILE_READ_DATA, Condition1, sizeof(Condition1))) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = AddAce(pAcl, ACCESS_DENIED_CALLBACK_ACE_TYPE, FILE_EXECUTE, Condition2, sizeof(Condition2))) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            pAcl->AclSize = (WORD)(cbAclSize);
        }
    }
    return pAcl;
}

PACL CreateSacl(PSID pSidUser)
{
    PACL pAcl;
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;

    // Allocate space for ACL
    if((pAcl = (PACL)LocalAlloc(LPTR, MAX_ACL_LENGTH)) != NULL)
    {
        if((Status = RtlCreateAcl(pAcl, MAX_ACL_LENGTH, ACL_REVISION_DS)) == STATUS_SUCCESS)
        {
            ACE_CSA_HELPER CsaHelper;
            PACE_HEADER pAceHeader;
            ULONG cbAclSize = sizeof(ACL);

            CsaHelper.Create(L"RESOURCE_ITEM_I64_VALUES", CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64, 3, 0xDEADBABFULL, 0x02ULL, 0x1234567812345679ULL);
            CsaHelper.Flags = CLAIM_SECURITY_ATTRIBUTE_NON_INHERITABLE | CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY;
            if((pAceHeader = AddAce(pAcl, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, GENERIC_READ, pSidUser, CsaHelper)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            CsaHelper.Create(L"RESOURCE_ITEM_U64_VALUES", CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64, 3, 0xDEADBABEULL, 0x01ULL, 0x1234567812345678ULL);
            CsaHelper.Flags = CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;
            if((pAceHeader = AddAce(pAcl, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, GENERIC_READ, pSidUser, CsaHelper)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            CsaHelper.Create(L"RESOURCE_ITEM_STRINGS", CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING, 4, L"DAENERYS", L"TARGARYEN", L"EDDARD", L"WINTERFELL");
            CsaHelper.Flags = CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;
            if((pAceHeader = AddAce(pAcl, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, GENERIC_READ, pSidUser, CsaHelper)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            CsaHelper.Create(L"RESOURCE_ITEM_SIDS", CLAIM_SECURITY_ATTRIBUTE_TYPE_SID, 3, (PSID)SidLocAdmins, (PSID)SidLocUsers, (PSID)SidEveryone);
            CsaHelper.Flags = 0;
            if((pAceHeader = AddAce(pAcl, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, GENERIC_READ, pSidUser, CsaHelper)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            CsaHelper.Create(L"RESOURCE_ITEM_BOOLEANS", CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN, 4, TRUE, TRUE, FALSE, FALSE);
            CsaHelper.Flags = 0;
            if((pAceHeader = AddAce(pAcl, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, GENERIC_READ, pSidUser, CsaHelper)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            pAcl->AclSize = (WORD)(cbAclSize);
        }
    }
    return pAcl;
}

static DWORD SetCustomSecurityDescriptor(HANDLE hObject, ULONG AclType)
{
    SID_IDENTIFIER_AUTHORITY SiaWorld = SECURITY_WORLD_SID_AUTHORITY;
    SECURITY_INFORMATION SecurityInfo = 0;
    SECURITY_DESCRIPTOR sd;
    NTSTATUS Status = STATUS_SUCCESS;
    PSID pSidEveryone = NULL;
    PSID pSidAdmin = NULL;
    PSID pSidUser = NULL;
    PACL pDacl = NULL;
    PACL pSacl = NULL;
    ULONG ccUserName = 0;
    ULONG cbSidEveryone = 0;
    ULONG cbSidAdmin = 0;
    ULONG cbSidUser = 0;
    TCHAR szUserName[128];

    // Get two sids: Admins and current user
    ccUserName = _countof(szUserName);
    GetUserName(szUserName, &ccUserName);
    pSidAdmin = GetUserSid(_T("Administrator"), &cbSidAdmin);
    pSidUser = GetUserSid(szUserName, &cbSidUser);

    // Get the SID of Everyone
    pSidEveryone = (PSID)(SidEveryone);
    cbSidEveryone = sizeof(SidEveryone);

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
                if((pDacl = CreateDacl(pSidAdmin)) != NULL)
                {
                    if((Status = RtlSetDaclSecurityDescriptor(&sd, TRUE, pDacl, FALSE)) == STATUS_SUCCESS)
                    {
                        SecurityInfo |= DACL_SECURITY_INFORMATION;
                    }
                }
                break;
            case 3:
                if((pSacl = CreateSacl(pSidUser)) != NULL)
                {
                    if((Status = RtlSetSaclSecurityDescriptor(&sd, TRUE, pSacl, FALSE)) == STATUS_SUCCESS)
                    {
                        SecurityInfo |= ATTRIBUTE_SECURITY_INFORMATION;
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

static void SetCustomSecurityDescriptor(LPCTSTR szPath, ULONG AclType)
{
    HANDLE hFolder;

    // Make sure that the folder exists
    ForcePathExist(szPath, TRUE);

    // Open the folder and set security descriptor
    hFolder = CreateFile(szPath, GENERIC_ALL | READ_CONTROL | WRITE_DAC | WRITE_OWNER, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if(hFolder != INVALID_HANDLE_VALUE)
    {
        SetCustomSecurityDescriptor(hFolder, AclType);
        CloseHandle(hFolder);
    }
}

static void LoadSpecialSecurityDescriptor(LPCTSTR szPath)
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

/*
static void FindSpecialSecurityDescriptor(LPTSTR szPathBuffer, LPTSTR szPathBufferEnd)
{
    WIN32_FIND_DATA wf;
    LPTSTR szPlainName = szPathBuffer + _tcslen(szPathBuffer);
    HANDLE hFind;
    BOOL bFound = TRUE;

    // Append the search mask
    StringCchCopy(szPlainName, (szPathBufferEnd - szPlainName), _T("\\*"));
    szPlainName = szPlainName + 1;

    // Perform the search
    if((hFind = FindFirstFile(szPathBuffer, &wf)) != INVALID_HANDLE_VALUE)
    {
        while(bFound)
        {
            if(_tcscmp(wf.cFileName, _T(".")) && _tcscmp(wf.cFileName, _T("..")))
            {
                StringCchCopy(szPlainName, (szPathBufferEnd - szPlainName), wf.cFileName);
                LoadSpecialSecurityDescriptor(szPathBuffer);

                if(wf.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                {
                    FindSpecialSecurityDescriptor(szPathBuffer, szPathBufferEnd);
                }
            }
            bFound = FindNextFile(hFind, &wf);
        }
    
        FindClose(hFind);
    }
}

static void FindSpecialSecurityDescriptor()
{
    LPTSTR szPathBuffer;
    SIZE_T ccPathBuffer = 0x1000;

    if((szPathBuffer = (LPTSTR)LocalAlloc(LPTR, ccPathBuffer * sizeof(TCHAR))) != NULL)
    {
        StringCchCopy(szPathBuffer, ccPathBuffer, _T("C:"));
        FindSpecialSecurityDescriptor(szPathBuffer, szPathBuffer + ccPathBuffer);
        LocalFree(szPathBuffer);
    }
}
*/
void DebugCode_SecurityDescriptor(LPCTSTR szPath)
{
    // FindSpecialSecurityDescriptor();

    LoadSpecialSecurityDescriptor(szPath);

    //SetCustomSecurityDescriptor(_T("c:\\VMWARE\\Test-001-NULL_ACL"), 0);
    //SetCustomSecurityDescriptor(_T("c:\\VMWARE\\Test-002-EMPTY_ACL"), 1);
    //SetCustomSecurityDescriptor(_T("c:\\VMWARE\\Test-003-VALID_ACL"), 2);
      SetCustomSecurityDescriptor(_T("c:\\VMWARE\\Test-004-RES_ATTR"),  3);
}
#endif
