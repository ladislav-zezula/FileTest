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

PACL CreateCustomAcl()
{
    PACL pAcl;
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;

    // Allocate space for ACL
    if((pAcl = (PACL)LocalAlloc(LPTR, MAX_ACL_LENGTH)) != NULL)
    {
        if((Status = RtlCreateAcl(pAcl, MAX_ACL_LENGTH, ACL_REVISION_DS)) == STATUS_SUCCESS)
        {
            PACE_HEADER pAceHeader;
            WORD cbAclSize = sizeof(ACL);

            if((pAceHeader = ACE_HELPER(ACCESS_ALLOWED_ACE_TYPE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;
/*
            if((pAceHeader = ACE_HELPER(ACCESS_DENIED_ACE_TYPE, FILE_EXECUTE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(SYSTEM_AUDIT_ACE_TYPE, FILE_EXECUTE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(SYSTEM_ALARM_ACE_TYPE, FILE_EXECUTE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(ACCESS_ALLOWED_COMPOUND_ACE_TYPE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(ACCESS_ALLOWED_OBJECT_ACE_TYPE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(ACCESS_DENIED_OBJECT_ACE_TYPE, FILE_EXECUTE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(SYSTEM_AUDIT_OBJECT_ACE_TYPE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(SYSTEM_ALARM_OBJECT_ACE_TYPE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(ACCESS_ALLOWED_CALLBACK_ACE_TYPE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(ACCESS_DENIED_CALLBACK_ACE_TYPE, FILE_EXECUTE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, FILE_EXECUTE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(SYSTEM_AUDIT_CALLBACK_ACE_TYPE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(SYSTEM_ALARM_CALLBACK_ACE_TYPE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(SYSTEM_MANDATORY_LABEL_ACE_TYPE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(ACE_CSA_HELPER(L"RESOURCE_ITEM_I64_VALUES", CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64)).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(ACE_CSA_HELPER(L"RESOURCE_ITEM_U64_VALUES", CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64)).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;
*/
            if((pAceHeader = ACE_HELPER(ACE_CSA_HELPER(L"RESOURCE_ITEM_STRINGS", CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING, 5)).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;
/*
            if((pAceHeader = ACE_HELPER(ACE_CSA_HELPER(L"RESOURCE_ITEM_SIDS", CLAIM_SECURITY_ATTRIBUTE_TYPE_SID)).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(ACE_CSA_HELPER(L"RESOURCE_ITEM_BOOLEANS", CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN, 4)).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(ACE_CSA_HELPER(L"RESOURCE_ITEM_OCTET_STRINGS", CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING)).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;

            if((pAceHeader = ACE_HELPER(SYSTEM_ACCESS_FILTER_ACE_TYPE).AddToAcl(pAcl)) != NULL)
                cbAclSize = cbAclSize + pAceHeader->AceSize;
*/
            pAcl->AclSize = cbAclSize;
        }
    }
    return pAcl;
}

static DWORD SetCustomSecurityDescriptor(HANDLE hObject)
{
    SECURITY_DESCRIPTOR sd;
    NTSTATUS Status = STATUS_SUCCESS;
    PACL pAcl = NULL;

    UNREFERENCED_PARAMETER(hObject);

    // Initialize the blank security descriptor
    Status = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    if(NT_SUCCESS(Status))
    {
        // Create custom ACL
        if((pAcl = CreateCustomAcl()) != NULL)
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

void DebugCode_SecurityDescriptor(LPCTSTR /* szPath */)
{
    //SetCustomSecurityDescriptor(_T("c:\\VMWARE\\TestValidAcl"));
}
#endif

