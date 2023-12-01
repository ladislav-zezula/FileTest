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

static PSYSTEM_RESOURCE_ATTRIBUTE_ACE AddAce(PACL pAcl, ACCESS_MASK AccessMask, PSID pSid, PCLAIM_SECURITY_ATTRIBUTE_V1 pAttrAbs)
{
    PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 pAttrRel;
    PSYSTEM_RESOURCE_ATTRIBUTE_ACE pAce = NULL;
    ULONG cbAttrRel = 0;
    ULONG cbMoveBy = 0;

    // Convert to absolute security attributes
    if((pAttrRel = ClaimSecurityAttributeAbs2Rel(pAttrAbs, &cbAttrRel)) != NULL)
    {
        if((pAce = AddAce0<SYSTEM_RESOURCE_ATTRIBUTE_ACE>(pAcl, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, AccessMask, pSid)) != NULL)
            AppendAceData(&pAce->Header, (LPBYTE)(pAttrRel), cbAttrRel);
        LocalFree(pAttrRel);
    }
    return pAce;
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

PACL CreateSacl(PSID pSidUser)
{
    PACL pAcl;
    ULONG cbAclSize = 0x1000;
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;

    // Allocate space for ACL
    if((pAcl = (PACL)LocalAlloc(LPTR, cbAclSize)) != NULL)
    {
        if((Status = RtlCreateAcl(pAcl, cbAclSize, ACL_REVISION_DS)) == STATUS_SUCCESS)
        {
            CLAIM_SECURITY_ATTRIBUTE_V1 Csa1 = {0};
            ULONG64 ItemArray_U64[] = {0xDEADBABF, 0x02, 0x1234567812345679};
            LPWSTR ItemArray_STR[] = {L"DAENERYS", L"TARGARYEN", L"EDDARD", L"WINTERFELL"};
            LONG64 ItemArray_I64[] = {0xDEADBABE, 0x01, 0x1234567812345678};
            PACE_HEADER pAceHeader;

            Csa1.Name = L"RESOURCE_ITEM_I64_VALUES";
            Csa1.ValueType  = CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64;
            Csa1.Flags      = CLAIM_SECURITY_ATTRIBUTE_NON_INHERITABLE | CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY;
            Csa1.ValueCount = _countof(ItemArray_I64);
            Csa1.Values.pInt64 = ItemArray_I64;
            pAceHeader = &AddAce(pAcl, GENERIC_READ, pSidUser, &Csa1)->Header;
            cbAclSize = sizeof(ACL) + pAceHeader->AceSize;

            Csa1.Name = L"RESOURCE_ITEM_U64_VALUES";
            Csa1.ValueType = CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64;
            Csa1.Flags = CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;
            Csa1.ValueCount = _countof(ItemArray_U64);
            Csa1.Values.pUint64 = ItemArray_U64;
            pAceHeader = &AddAce(pAcl, GENERIC_READ, pSidUser, &Csa1)->Header;
            cbAclSize = cbAclSize + pAceHeader->AceSize;

            Csa1.Name = L"RESOURCE_ITEM_STRING_VALUES";
            Csa1.ValueType = CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING;
            Csa1.Flags = CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;
            Csa1.ValueCount = _countof(ItemArray_STR);
            Csa1.Values.ppString = ItemArray_STR;
            pAceHeader = &AddAce(pAcl, GENERIC_READ, pSidUser, &Csa1)->Header;
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
    CreateDirectory(szPath, NULL);

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
                        PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 pAttrRel1;
                        PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 pAttrRel2;
                        PCLAIM_SECURITY_ATTRIBUTE_V1 pAttrAbs;
                        PSID pSid = (PSID)(&pAce->SidStart);
                        LPBYTE pbAce = (LPBYTE)(pAce);
                        LPBYTE pbPtr = pbAce + FIELD_OFFSET(SYSTEM_RESOURCE_ATTRIBUTE_ACE, SidStart) + RtlLengthSid(pSid);
                        LPBYTE pbEnd = pbAce + pAce->Header.AceSize;
                        ULONG cbRelSize = 0;
                        ULONG cbMoveBy = 0;

                        pAttrRel1 = (PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1)(pbPtr);
                        pAttrAbs = ClaimSecurityAttributeRel2Abs(pAttrRel1, (ULONG)(pbEnd - pbAce), &cbMoveBy);
                        pAttrRel2 = ClaimSecurityAttributeAbs2Rel(pAttrAbs, &cbRelSize);
                        assert(memcmp(pAttrRel1, pAttrRel2, cbMoveBy) == 0);
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
