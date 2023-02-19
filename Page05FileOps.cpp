/*****************************************************************************/
/* Page05FileOps.cpp                      Copyright (c) Ladislav Zezula 2004 */
/*---------------------------------------------------------------------------*/
/* Description:                                                              */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 19.04.04  1.00  Lad  The first version of Page05FileOps.cpp               */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Flags

static TFlagInfo CopyFileFlags[] =
{
    FLAGINFO_BITV(COPY_FILE_FAIL_IF_EXISTS),
    FLAGINFO_BITV(COPY_FILE_RESTARTABLE),
    FLAGINFO_BITV(COPY_FILE_OPEN_SOURCE_FOR_WRITE),
    FLAGINFO_BITV(COPY_FILE_ALLOW_DECRYPTED_DESTINATION),
    FLAGINFO_SEPARATOR(),
    {{"Use Manual Copy (ReadFile+WriteFile)"}, COPY_FILE_USE_READ_WRITE, COPY_FILE_USE_READ_WRITE},
    {{"Manual Copy: Skip Read Errors"},        COPY_FILE_SKIP_IO_ERRORS, COPY_FILE_SKIP_IO_ERRORS},
    {{"Manual Copy: Log Read Errors"},         COPY_FILE_LOG_IO_ERRORS,  COPY_FILE_LOG_IO_ERRORS},
    {{"Manual Copy: Copy per sector"},         COPY_FILE_PER_SECTOR,     COPY_FILE_PER_SECTOR},
    FLAGINFO_END()
};

static TFlagInfo MoveFileFlags[] =
{
    FLAGINFO_BITV(MOVEFILE_REPLACE_EXISTING),
    FLAGINFO_BITV(MOVEFILE_COPY_ALLOWED),
    FLAGINFO_BITV(MOVEFILE_DELAY_UNTIL_REBOOT),
    FLAGINFO_BITV(MOVEFILE_WRITE_THROUGH),
    FLAGINFO_BITV(MOVEFILE_CREATE_HARDLINK),
    FLAGINFO_BITV(MOVEFILE_FAIL_IF_NOT_TRACKABLE),
    FLAGINFO_END()
};

static TFlagInfo Win7OplockFlags[] =
{
    FLAGINFO_BITV(OPLOCK_LEVEL_CACHE_READ),
    FLAGINFO_BITV(OPLOCK_LEVEL_CACHE_HANDLE),
    FLAGINFO_BITV(OPLOCK_LEVEL_CACHE_WRITE),
    FLAGINFO_END()
};

//-----------------------------------------------------------------------------
// Helper functions

static LPTSTR FormatOplockTypeWindows7(LPTSTR szBuffer, size_t cchBuffer, DWORD dwOplockFlags)
{
    size_t nIndex;

    // Print the base information
    StringCchPrintf(szBuffer, cchBuffer, _T("windows7:"));
    nIndex = _tcslen(szBuffer);

    if(dwOplockFlags & OPLOCK_LEVEL_CACHE_READ)
        szBuffer[nIndex++] = _T('R');
    if(dwOplockFlags & OPLOCK_LEVEL_CACHE_WRITE)
        szBuffer[nIndex++] = _T('W');
    if(dwOplockFlags & OPLOCK_LEVEL_CACHE_HANDLE)
        szBuffer[nIndex++] = _T('H');
    if(dwOplockFlags == 0)
        szBuffer[nIndex++] = _T('0');
    szBuffer[nIndex] = 0;

    return szBuffer;
}

static bool IsDotDirectoryName(PFILE_DIRECTORY_INFORMATION pDirInfo)
{
    if(pDirInfo->FileNameLength == 2 && pDirInfo->FileName[0] == L'.')
        return true;
    if(pDirInfo->FileNameLength == 4 && pDirInfo->FileName[0] == L'.' && pDirInfo->FileName[1] == L'.')
        return true;

    return false;
}

// Takes ownership on handle (file or registry key).
// The handle must be open for WRITE_OWNER access
static NTSTATUS NtTakeOwnershipObject(HANDLE ObjectHandle)
{
    SECURITY_DESCRIPTOR sd;
    PTOKEN_USER pTokenUser = NULL;
    NTSTATUS Status;
    HANDLE TokenHandle = NULL;
    ULONG cbTokenUser = 0;

    // Open the token of the current process
    Status = NtOpenProcessToken(NtCurrentProcess(),
                                TOKEN_QUERY,
                               &TokenHandle);
    if(NT_SUCCESS(Status))
    {
        NtQueryInformationToken(TokenHandle, 
                                TokenUser,
                                pTokenUser,
                                cbTokenUser,
                               &cbTokenUser);
        if(cbTokenUser == 0)
        {
            NtClose(TokenHandle);
            return STATUS_UNSUCCESSFUL;
        }

        pTokenUser = (PTOKEN_USER)RtlAllocateHeap(RtlProcessHeap(), 0, cbTokenUser);
        if(pTokenUser != NULL)
        {
            Status = NtQueryInformationToken(TokenHandle, 
                                             TokenUser,
                                             pTokenUser,
                                             cbTokenUser,
                                            &cbTokenUser);
        }
        else
        {
            Status = STATUS_NO_MEMORY;
        }
    }

    // Initialize the blank security descriptor
    if(NT_SUCCESS(Status))
    {
        Status = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    }

    // Set the owner to the security descriptor
    if(NT_SUCCESS(Status))
    {
        Status = RtlSetOwnerSecurityDescriptor(&sd, pTokenUser->User.Sid, FALSE);
    }

    // Apply the owner to the object handle
    if(NT_SUCCESS(Status))
    {
        Status = NtSetSecurityObject(ObjectHandle, OWNER_SECURITY_INFORMATION, &sd);
    }

    // Free buffers
    if(pTokenUser != NULL)
        RtlFreeHeap(RtlProcessHeap(), 0, pTokenUser);
    if(TokenHandle != NULL)
        NtClose(TokenHandle);
    return Status;
}
/*
// Gives the object a NULL Dacl, granting access to everyone
// https://technet.microsoft.com/en-us/library/cc781716%28v=ws.10%29.aspx
static NTSTATUS NtSetObjectNullDacl(IN HANDLE ObjectHandle)
{
    SECURITY_DESCRIPTOR sd;
    NTSTATUS Status;

    // Initialize the blank security descriptor
    Status = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);

    // Set the ACL to the security descriptor
    if(NT_SUCCESS(Status))
    {
        Status = RtlSetDaclSecurityDescriptor(&sd, TRUE, NULL, FALSE);
    }

    // Apply the security information to the handle
    if(NT_SUCCESS(Status))
    {
        Status = NtSetSecurityObject(ObjectHandle, DACL_SECURITY_INFORMATION, &sd);
    }

    return Status;
}
*/
// Sets the access-control list for a handle to "Everyone:AccessMask"
// The handle must be open for WRITE_DAC access
static NTSTATUS NtSetObjectAccessForEveryone(
    IN HANDLE ObjectHandle,
    IN ACCESS_MASK AccessMask)
{
    SID_IDENTIFIER_AUTHORITY SiaEveryone = SECURITY_WORLD_SID_AUTHORITY;
    SECURITY_DESCRIPTOR sd;
    NTSTATUS Status;
    ULONG cbAclLength = 0;
    PSID pSidEveryone = NULL; 
    PACL pAcl = NULL;

    // Get the SID of Everyone
    Status = RtlAllocateAndInitializeSid(&SiaEveryone, 1, 0, 0, 0, 0, 0, 0, 0, 0, &pSidEveryone);

    // Allocate space for ACL
    if(NT_SUCCESS(Status))
    {
        ULONG dwSidLength = RtlLengthSid(pSidEveryone);

        // Create ACL for full access to the file
        cbAclLength = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + dwSidLength - sizeof(DWORD);
        pAcl = (PACL)RtlAllocateHeap(RtlProcessHeap(), 0, cbAclLength);
        if(pAcl == NULL)
            Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    // Create the Access control list with one ACE
    if(NT_SUCCESS(Status))
    {
        Status = RtlCreateAcl(pAcl, cbAclLength, ACL_REVISION);
    }

    // Add the ACE to the ACL
    if(NT_SUCCESS(Status))
    {
        Status = RtlAddAccessAllowedAce(pAcl, ACL_REVISION, AccessMask, pSidEveryone);
    }

    // Initialize the blank security descriptor
    if(NT_SUCCESS(Status))
    {
        Status = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    }

    // Set the ACL to the security descriptor
    if(NT_SUCCESS(Status))
    {
        Status = RtlSetDaclSecurityDescriptor(&sd, TRUE, pAcl, FALSE);
    }

    // Apply the security information to the handle
    if(NT_SUCCESS(Status))
    {
        Status = NtSetSecurityObject(ObjectHandle, DACL_SECURITY_INFORMATION, &sd);
    }

    // Free buffers
    if(pAcl != NULL)
        RtlFreeHeap(RtlProcessHeap(), 0, pAcl);
    if(pSidEveryone != NULL)
        RtlFreeSid(pSidEveryone);
    return Status;
}

static NTSTATUS NtSetFileAccessToEveryone(POBJECT_ATTRIBUTES PtrObjectAttributes, ACCESS_MASK AccessMask)
{
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;
    HANDLE FileHandle;
    ULONG OpenOptions = FILE_OPEN_REPARSE_POINT;
    ULONG TryCount = 0;

    // Attempt to set the file's security. If this fails, it either means that
    // the current user doesn't have WRITE_DAC access or the current user
    // is not the owner of the file
    __TryOpenFsObject:
    Status = NtOpenFile(&FileHandle,
                         WRITE_DAC,
                         PtrObjectAttributes,
                        &IoStatus,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         OpenOptions);
    if(Status == STATUS_ACCESS_DENIED && TryCount++ == 0)
    {
        // Write the owner to the file.
        Status = NtOpenFile(&FileHandle,
                             WRITE_OWNER,
                             PtrObjectAttributes,
                            &IoStatus,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             OpenOptions);
        if(NT_SUCCESS(Status))
        {
            NtTakeOwnershipObject(FileHandle);
            NtClose(FileHandle);
        }

        // Retry to open for WRITE_DAC
        goto __TryOpenFsObject;
    }

    // If succeeded, write the file security
    if(NT_SUCCESS(Status))
    {
        // Vers: Windows 10, build 17763.rs5_release.180914-1434
        // File: C:\Windows.old\$WINDOWS.~BT\Sources\SafeOS\boot.sdi
        // Looks like NtSetObjectNullDacl succeeds, but does nothing
        // On the other hand, setting DACL with Everyone:GENERIC_ALL works OK.
        Status = NtSetObjectAccessForEveryone(FileHandle, GENERIC_ALL);
//      Status = NtSetObjectNullDacl(FileHandle);
        NtClose(FileHandle);
    }

    // If the file access also includes WRITE, we also clear all attributes
    if(AccessMask & (GENERIC_ALL | GENERIC_WRITE | FILE_WRITE_DATA | DELETE))
    {
        FILE_BASIC_INFORMATION BasicInfo;

        Status = NtOpenFile(&FileHandle,
                             FILE_WRITE_ATTRIBUTES,
                             PtrObjectAttributes,
                            &IoStatus,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             OpenOptions);
        if(NT_SUCCESS(Status))
        {
            memset(&BasicInfo, 0xFF, sizeof(FILE_BASIC_INFORMATION));
            BasicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
            NtSetInformationFile(FileHandle,
                                &IoStatus,
                                &BasicInfo,
                                 sizeof(FILE_BASIC_INFORMATION), 
                                 FileBasicInformation);
            NtClose(FileHandle);
        }
    }

    return Status;
}

static NTSTATUS NtRemoveSingleFile(POBJECT_ATTRIBUTES PtrObjectAttributes)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG TryCount = 0;

    // Attempt to delete the file
    __TryDeleteFile:
    Status = NtDeleteFile(PtrObjectAttributes);

    // If STATUS_ACCESS_DENIED, try to rewrite the security descriptor
    if(Status == STATUS_ACCESS_DENIED && TryCount == 0)
    {
        Status = NtSetFileAccessToEveryone(PtrObjectAttributes, GENERIC_ALL | DELETE);
        if(NT_SUCCESS(Status))
        {
            TryCount++;
            goto __TryDeleteFile;
        }
    }

    return Status;
}

static NTSTATUS NtDeleteFsObject(
    POBJECT_ATTRIBUTES PtrObjectAttributes,     // OBJECT_ATTRIBUTES of the object to be deleted
    PVOID WorkBuffer,                           // Work buffer to be used for queries
    ULONG WorkBufferSize,                       // Size of the work buffer
    BOOLEAN RecursiveDelete)                    // TRUE - delete recursively
{
    PFILE_DIRECTORY_INFORMATION pDirInfo = (PFILE_DIRECTORY_INFORMATION)WorkBuffer;
    PFILE_BASIC_INFORMATION pFileInfo = (PFILE_BASIC_INFORMATION)WorkBuffer;
    OBJECT_ATTRIBUTES ChildAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING ChildPath;
    NTSTATUS Status;
    HANDLE ObjectHandle = NULL;
    BOOLEAN NeedDeleteManually;
    BOOLEAN IsSubdirectory;
    ULONG TryCount = 0;

    // Open the directory for enumeration+delete
    // Use FILE_OPEN_REPARSE_POINT, because the directory can be
    // a reparse point (even an invalid one) and still contain files/subdirs
    __TryOpenFsObject:
    Status = NtOpenFile(&ObjectHandle,
                         FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | DELETE | SYNCHRONIZE,
                         PtrObjectAttributes,
                        &IoStatus,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         FILE_SYNCHRONOUS_IO_ALERT | FILE_DELETE_ON_CLOSE | FILE_OPEN_REPARSE_POINT);
    NeedDeleteManually = FALSE;

    // When the access is denied, we can try to reset the permissions
    // Note that if the file/directory has FILE_ATTRIBUTE_READONLY,
    // then NtOpenFile return STATUS_CANNOT_DELETE
    if(Status == STATUS_ACCESS_DENIED || Status == STATUS_CANNOT_DELETE)
    {
        // Reason number one could be a reset security descriptor/read-only attribute.
        // Reset DACL and attributes and retry
        if(TryCount++ == 0)
        {
            // Reset the complete security descriptor to Everyone:Full Control.
            // Also reset the file/directory attributes
            Status = NtSetFileAccessToEveryone(PtrObjectAttributes, GENERIC_ALL | DELETE);
            goto __TryOpenFsObject;
        }

        // In some cases, the previous one could fail with STATUS_CANNOT_DELETE
        // Example: Opening a second hardlink to a file that is currently mapped
        Status = NtOpenFile(&ObjectHandle,
                             FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | DELETE | SYNCHRONIZE,
                             PtrObjectAttributes,
                            &IoStatus,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_SYNCHRONOUS_IO_ALERT | FILE_OPEN_REPARSE_POINT);

        // We need the manual delete here
        NeedDeleteManually = TRUE;
    }

    if(NT_SUCCESS(Status) && RecursiveDelete)
    {
        // Check if the FS object is a directory
        Status = NtQueryInformationFile(ObjectHandle,
                                       &IoStatus,
                                        pFileInfo,
                                        WorkBufferSize,
                                        FileBasicInformation);

        // If the opened object has reparse point on it,
        // we need to delete the reparse point first 
        if(NT_SUCCESS(Status) && (pFileInfo->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        {
            Status = NtDeleteReparsePoint(ObjectHandle);
            if(NT_SUCCESS(Status))
            {
                // Note that the NtClose might cause the directory be deleted
                // if it is empty.
                NtClose(ObjectHandle);
                ObjectHandle = NULL;
                TryCount = 0;
                goto __TryOpenFsObject;
            }
        }

        // If the FS object is a directory
        if(NT_SUCCESS(Status) && (pFileInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            // Prepare the child object attributes and the pointer to directory entry
            InitializeObjectAttributes(&ChildAttr, &ChildPath, OBJ_CASE_INSENSITIVE, ObjectHandle, NULL);

            // Work as long as we have something
            for(;;)
            {
                // Query a single directory item
                Status = NtQueryDirectoryFile(ObjectHandle,
                                              NULL,
                                              NULL,
                                              NULL,
                                             &IoStatus,
                                              pDirInfo,
                                              WorkBufferSize,
                                              FileDirectoryInformation,
                                              TRUE,
                                              NULL,
                                              FALSE);

                // STATUS_NO_MORE_FILES means there are no files
                // STATUS_INVALID_PARAMETER means that it is a file
                if(Status == STATUS_NO_MORE_FILES || Status == STATUS_INVALID_PARAMETER)
                {
                    Status = STATUS_SUCCESS;
                    break;
                }

                // Skip "." and ".."
                if(!IsDotDirectoryName(pDirInfo))
                {
                    // Create the child path
                    ChildPath.MaximumLength =
                    ChildPath.Length = (USHORT)pDirInfo->FileNameLength;
                    ChildPath.Buffer = pDirInfo->FileName;

                    // Terminate the child path with zero. Redundant, but easier to debug
                    ChildPath.Buffer[ChildPath.Length / sizeof(WCHAR)] = 0;

                    // If the found object is a file, we pass RecursiveDelete = FALSE,
                    // which will skip subdirectory enumeration
                    IsSubdirectory = (pDirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? TRUE : FALSE;

                    // Delete the files/directories in the directory itself
                    // Note that the content of the work buffer is destroyed after this call
                    Status = NtDeleteFsObject(&ChildAttr, WorkBuffer, WorkBufferSize, IsSubdirectory);
                    if(!NT_SUCCESS(Status))
                        break;
                }
            }
        }
    }

    // Close the file/directory handle. This causes it to be deleted.
    if(ObjectHandle != NULL)
    {
        if(NeedDeleteManually)
        {
            FILE_DISPOSITION_INFORMATION_EX DispInfoEx = {FILE_DISPOSITION_DELETE};
            FILE_DISPOSITION_INFORMATION DispInfo = {TRUE};

            // Try the classic FILE_DISPOSITION_INFORMATION
            Status = NtSetInformationFile(ObjectHandle, &IoStatus, &DispInfo, sizeof(FILE_DISPOSITION_INFORMATION), FileDispositionInformation);

            // If the file is a hardlink to a running file (mapped image), the previous call will fail.
            // Try the new FILE_DISPOSITION_INFORMATION_EX. Thanks Scott Noone from Open System Resources (OSR)
            // for this valuable hint: http://www.osronline.com/showthread.cfm?link=286551
            if(Status == STATUS_CANNOT_DELETE)
                Status = NtSetInformationFile(ObjectHandle, &IoStatus, &DispInfoEx, sizeof(FILE_DISPOSITION_INFORMATION_EX), FileDispositionInformationEx);

            // When closed, the file goes away
            NtClose(ObjectHandle);
        }
        else
        {
            NTSTATUS DelStatus = NtClose(ObjectHandle);
            Status = NT_SUCCESS(Status) ? DelStatus : Status;
        }
    }

    // If the file was not found, we consider this a success
    if(Status == STATUS_OBJECT_NAME_NOT_FOUND || Status == STATUS_OBJECT_PATH_NOT_FOUND)
        Status = STATUS_SUCCESS;
    return Status;
}

static NTSTATUS ForceRemoveFile(LPCTSTR szFileName)
{
    OBJECT_ATTRIBUTES ObjAttr;
    UNICODE_STRING PathName;
    NTSTATUS Status;

    // Convert to UNICODE_STRING
    Status = FileNameToUnicodeString(&PathName, szFileName);
    if(NT_SUCCESS(Status))
    {
        InitializeObjectAttributes(&ObjAttr, &PathName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = NtRemoveSingleFile(&ObjAttr);
        FreeFileNameString(&PathName);
    }

    return Status;
}

static NTSTATUS RemoveFsObjectTree(LPCTSTR szDirName, BOOLEAN RecursiveDelete)
{
    OBJECT_ATTRIBUTES ObjAttr;
    UNICODE_STRING PathName;
    NTSTATUS Status;
    PVOID WorkBuffer;
    ULONG WorkBufferSize = 0x1000;

    // Convert to UNICODE_STRING
    Status = FileNameToUnicodeString(&PathName, szDirName);
    if(NT_SUCCESS(Status))
    {
        // Allocate working buffer so the recursive function will not consume so much memory
        WorkBuffer = RtlAllocateHeap(RtlProcessHeap(), 0, WorkBufferSize);
        if(WorkBuffer != NULL)
        {
            // Call the recursive function
            InitializeObjectAttributes(&ObjAttr, &PathName, OBJ_CASE_INSENSITIVE, NULL, NULL);
            Status = NtDeleteFsObject(&ObjAttr, WorkBuffer, WorkBufferSize, RecursiveDelete);
            FreeFileNameString(&PathName);

            // Free the work buffer
            RtlFreeHeap(RtlProcessHeap(), 0, WorkBuffer);
        }
        else
        {
            Status = STATUS_NO_MEMORY;
        }
    }

    return Status;
}

static int SaveDialog(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    if((pData->OpenFile.dwCreateOptions & FILE_OPEN_BY_FILE_ID) == 0)
        GetDlgItemText(hDlg, IDC_FILE_NAME1, pData->szFileName1, MAX_NT_PATH);
    GetDlgItemText(hDlg, IDC_FILE_NAME2, pData->szFileName2, MAX_NT_PATH);
    return ERROR_SUCCESS;
}


// This function enables/disables the buttons for map operations
static int UpdateDialogButtons(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    BOOL bEnable;

    // Enable/Disable handle-based buttons
    bEnable = IsHandleValid(pData->hFile) ? TRUE : FALSE;
    EnableDlgItems(hDlg, bEnable, 
                         IDC_FLUSH_FILE_BUFFERS,
                         IDC_REQUEST_OPLOCK_MENU,
                         IDC_BREAK_ACKNOWLEDGE_1,
                         IDC_REQUEST_OPLOCK_WIN7,
                         IDC_BREAK_ACKNOWLEDGE_2,
                         0);

    // Enable/Disable CreateHardLink button
    bEnable = (pfnCreateHardLink != NULL) ? TRUE : FALSE;
    EnableDlgItems(hDlg, bEnable, IDC_CREATE_HARDLINK, 0);

    return TRUE;
}

//-----------------------------------------------------------------------------
// Message handlers

static TAnchors * pAnchors = NULL;

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    PROPSHEETPAGE * pPage = (PROPSHEETPAGE *)lParam;
    TFileTestData * pData = (TFileTestData *)pPage->lParam;

    SetDialogData(hDlg, pPage->lParam);

    // Configure dialog resizing
    if(pData->bEnableResizing)
    {
        pAnchors = new TAnchors();
        pAnchors->AddAnchor(hDlg, IDC_MAIN_FRAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_NAME1, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_NAME1_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_NAME2, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_NAME2_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_MOVE_FILE, akLeftCenter | akTop);
        pAnchors->AddAnchor(hDlg, IDC_MOVE_OPTIONS, akLeftCenter | akTop);
        pAnchors->AddAnchor(hDlg, IDC_DELETE_FILE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_DELETE_OBJECT_MENU, akTop | akRight);

        pAnchors->AddAnchor(hDlg, IDC_FILEID_FRAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_ID, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_ID_USE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_OBJECT_ID, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_OBJECT_ID_USE, akTop | akRight);

        pAnchors->AddAnchor(hDlg, IDC_OTHERS_FRAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_NT_QUERY_ATTRIBUTES_FILE, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_GET_FILE_ATTRIBUTES, akRight | akTop);
        pAnchors->AddAnchor(hDlg, IDC_FLUSH_FILE_BUFFERS, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_CREATE_HARDLINK, akRight | akTop);
        pAnchors->AddAnchor(hDlg, IDC_ENCRYPT_FILE, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_DECRYPT_FILE, akRight | akTop);
        pAnchors->AddAnchor(hDlg, IDC_NT_DELETE_FILE, akLeft | akTop);

        pAnchors->AddAnchor(hDlg, IDC_OPLOCKS_FRAME, akAll);
        pAnchors->AddAnchor(hDlg, IDC_REQUEST_OPLOCK_MENU, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_BREAK_ACKNOWLEDGE_1, akRight | akTop);
        pAnchors->AddAnchor(hDlg, IDC_REQUEST_OPLOCK_WIN7, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_BREAK_ACKNOWLEDGE_2, akRight | akTop);


        pAnchors->AddAnchor(hDlg, IDC_RESULT_FRAME, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE, akLeft | akRight | akBottom);
    }

    // Initialize tooltips
    g_Tooltip.AddToolTip(hDlg, IDC_NT_QUERY_ATTRIBUTES_FILE, IDS_TIP_NT_QUERY_ATTRIBUTES_FILE);
    g_Tooltip.AddToolTip(hDlg, IDC_GET_FILE_ATTRIBUTES,      IDS_TIP_GET_FILE_ATTRIBUTES);
    g_Tooltip.AddToolTip(hDlg, IDC_FLUSH_FILE_BUFFERS,       IDS_TIP_FLUSH_FILE_BUFFERS);

    Hex2DlgText64(hDlg, IDC_BYTE_OFFSET, 0);
    Hex2DlgText32(hDlg, IDC_LENGTH, 0x10000);
    return TRUE;
}

static int OnSetActive(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    if((pData->OpenFile.dwCreateOptions & FILE_OPEN_BY_FILE_ID) == 0)
    {
        SetDlgItemText(hDlg, IDC_FILE_NAME1, pData->szFileName1);
        ConvertToWin32Name(hDlg, IDC_FILE_NAME1);
    }
    else
    {
        pData->szDirName[0] = 0;
        pData->OpenFile.dwCreateOptions &= ~FILE_OPEN_BY_FILE_ID;
    }

    if(pData->szFileName2[0] != 0)
    {
        SetDlgItemText(hDlg, IDC_FILE_NAME2, pData->szFileName2);
        ConvertToWin32Name(hDlg, IDC_FILE_NAME2);
    }

    UpdateDialogButtons(hDlg);
    return TRUE;
}

static int OnKillActive(HWND hDlg)
{
    SaveDialog(hDlg);
    UpdateDialogButtons(hDlg);
    return TRUE;
}

static int OnDeltaPos(HWND hDlg, NMUPDOWN * pNMHDR)
{
    LARGE_INTEGER Uint64;
    DWORD Uint32;

    // Get the proper edit box
    if(pNMHDR->hdr.idFrom == IDC_BYTE_OFFSET_SPIN)
    {
        DlgText2Hex64(hDlg, IDC_BYTE_OFFSET, &Uint64.QuadPart);
        if(pNMHDR->iDelta < 0)
            Uint64.QuadPart += 0x10000;
        else
            Uint64.QuadPart -= 0x10000;
        if(Uint64.HighPart & 0x80000000)
            Uint64.QuadPart = 0;
        Hex2DlgText64(hDlg, IDC_BYTE_OFFSET, Uint64.QuadPart);
        return TRUE;
    }
    
    if(pNMHDR->hdr.idFrom == IDC_LENGTH_SPIN)
    {
        DlgText2Hex32(hDlg, IDC_LENGTH, &Uint32);
        if(pNMHDR->iDelta < 0)
            Uint32 += 0x10000;
        else
            Uint32 -= 0x10000;
        if(Uint32 & 0x80000000)
            Uint32 = 0;
        Hex2DlgText32(hDlg, IDC_LENGTH, Uint32);
        return TRUE;
    }

    return FALSE;
}


static int OnCopyFileClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    DWORD dwErrCode;

    // Get the source and target file
    GetDlgItemText(hDlg, IDC_FILE_NAME1, pData->szFileName1, MAX_NT_PATH);
    GetDlgItemText(hDlg, IDC_FILE_NAME2, pData->szFileName2, MAX_NT_PATH);

    // Run the copy file dialog
    dwErrCode = (DWORD)CopyFileDialog(hDlg, pData);

    // Set the result
    SetResultInfo(hDlg, RSI_LAST_ERROR, dwErrCode);
    return TRUE;
}

static int OnMoveFileClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    DWORD dwErrCode = ERROR_SUCCESS;

    SaveDialog(hDlg);

    // Perform the rename
    if(!MoveFileEx(pData->szFileName1, pData->szFileName2, pData->dwMoveFileFlags))
        dwErrCode = GetLastError();

    // Set the result
    SetResultInfo(hDlg, RSI_LAST_ERROR, dwErrCode);
    return TRUE;
}

static int OnCopyOptions(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    FlagsDialog(hDlg, IDS_COPYFILE_FLAGS, CopyFileFlags, pData->dwCopyFileFlags);
    return TRUE;
}

static int OnMoveOptions(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    FlagsDialog(hDlg, IDS_MOVEFILE_FLAGS, MoveFileFlags, pData->dwMoveFileFlags);
    return TRUE;
}

static int OnDeleteFileClick(HWND hDlg, UINT nIDCtrl)
{
    TFileTestData * pData = GetDialogData(hDlg);
    NTSTATUS Status;
    DWORD dwErrCode = ERROR_SUCCESS;

    // Save the dialog variables
    SaveDialog(hDlg);

    // Choose what exactly to do
    switch(nIDCtrl)
    {
        case IDC_SIMPLE_DELETE:
            if(!DeleteFile(pData->szFileName1))
                dwErrCode = GetLastError();
            SetResultInfo(hDlg, RSI_LAST_ERROR, dwErrCode);
            break;

        case IDC_FORCED_DELETE:
            Status = ForceRemoveFile(pData->szFileName1);
            SetResultInfo(hDlg, RSI_NTSTATUS, Status);
            break;

        default:
            return TRUE;
    }

    UpdateDialogButtons(hDlg);
    return TRUE;
}

static int OnDeleteFsObject(HWND hDlg, BOOLEAN RecursiveDelete)
{
    TFileTestData * pData = GetDialogData(hDlg);
    NTSTATUS Status;

    // Save the dialog variables
    SaveDialog(hDlg);

    // Perform the delete
    Status = RemoveFsObjectTree(pData->szFileName1, RecursiveDelete);
    SetResultInfo(hDlg, RSI_NTSTATUS, Status);
    return TRUE;
}

// Querying the file ID from the file itself
static int OnFileIdGetClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING FolderName = {0, 0, NULL};
    UNICODE_STRING FileName = {0, 0, NULL};
    ULARGE_INTEGER FileId = {0};
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE Handle = NULL;
    TCHAR szFileID[MAX_FILEID_PATH];
    BYTE InfoBuff[0x200];

    // Convert the file name to the NT file name
    if(NT_SUCCESS(Status))
    {
        SaveDialog(hDlg);
        Status = FileNameToUnicodeString(&FolderName, pData->szFileName1);
    }

    // Get the directory name from the file name
    if(NT_SUCCESS(Status))
    {
        PWSTR sz = FolderName.Buffer + (FolderName.Length / sizeof(WCHAR));

        // Go back and find the last directory name
        while(sz > FolderName.Buffer && sz[0] != L'\\')
            sz--;

        // Did we find it?
        if(sz[0] == L'\\' && sz > FolderName.Buffer)
        {
            // Initialize the file name
            sz = sz + 1;
            RtlInitUnicodeString(&FileName, sz);

            // Cut the folder name. Make sure that the ending backslash is there,
            // because we don't want to open "\??\C:" instead of "\??\C:\"
            FolderName.MaximumLength =
            FolderName.Length = (USHORT)((sz - FolderName.Buffer) * sizeof(WCHAR));

            // Attempt to open the folder and query the ID
            InitializeObjectAttributes(&ObjAttr, &FolderName, OBJ_CASE_INSENSITIVE, NULL, NULL);
            Status = NtOpenFile(&Handle,
                                 FILE_READ_DATA | SYNCHRONIZE,
                                &ObjAttr,
                                &IoStatus,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_SYNCHRONOUS_IO_ALERT);

            // If succeeded, we call for query directory on thet file
            if(NT_SUCCESS(Status))
            {
                PFILE_ID_BOTH_DIR_INFORMATION pDirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)InfoBuff;

                Status = NtQueryDirectoryFile(Handle,
                                              NULL,
                                              NULL,
                                              NULL,
                                             &IoStatus,
                                              pDirInfo,
                                              sizeof(InfoBuff),
                                              FileIdBothDirectoryInformation,
                                              TRUE,
                                             &FileName,
                                              FALSE);
                if(NT_SUCCESS(Status))
                    FileId.QuadPart = pDirInfo->FileId.QuadPart;
                NtClose(Handle);
            }
        }
        else
        {
            // Do it by Open - QueryID - Close
            InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
            Status = NtOpenFile(&Handle,
                                 FILE_READ_ATTRIBUTES,
                                &ObjAttr,
                                &IoStatus,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 0);

            if(NT_SUCCESS(Status))
            {
                PFILE_INTERNAL_INFORMATION pFileInfo = (PFILE_INTERNAL_INFORMATION)InfoBuff;

                Status = NtQueryInformationFile(Handle,
                                               &IoStatus,
                                                pFileInfo,
                                                sizeof(FILE_INTERNAL_INFORMATION),
                                                FileInternalInformation);
                if(NT_SUCCESS(Status))
                    FileId.QuadPart = pFileInfo->IndexNumber.QuadPart;
                NtClose(Handle);
            }
        }
    }

    // Did we query the file ID just fine?
    if(NT_SUCCESS(Status))
    {
        FileIDToString(pData, FileId.QuadPart, szFileID);
        SetDlgItemText(hDlg, IDC_FILE_ID, szFileID);
    }

    // On the end, set the file ID
    SetResultInfo(hDlg, RSI_NTSTATUS, Status);
    FreeFileNameString(&FolderName);
    return TRUE;
}

static int OnFileIDChange(HWND hDlg, UINT nIDEdit, UINT nIDButton)
{
    HWND hWndButton = GetDlgItem(hDlg, nIDButton);
    HWND hWndEdit = GetDlgItem(hDlg, nIDEdit);
    BOOL bEnable = (GetWindowTextLength(hWndEdit) != 0);

    EnableWindow(hWndButton, bEnable);
    return TRUE;
}

static int OnFileIdUse(HWND hDlg, UINT nIDEdit)
{
    TCHAR szFileId[0x100] = _T("");

    // Retrieve the file ID or object ID from the edit box
    GetDlgItemText(hDlg, nIDEdit, szFileId, _countof(szFileId));
    NtUseFileId(hDlg, szFileId);
    return TRUE;
}    

static int OnObjectIdMoreClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    FILE_OBJECTID_BUFFER ObjId = {0};
    UINT_PTR nAction;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    TCHAR szObjectID[0x40];
    DWORD dwFlagsAndAttributes = 0;
    DWORD dwDesiredAccess = FILE_READ_ATTRIBUTES;
    DWORD dwBytesReturned;
    DWORD dwIoctlCode = FSCTL_CREATE_OR_GET_OBJECT_ID;
    DWORD dwErrCode = ERROR_SUCCESS;

    // Ask the user for the action
    nAction = ObjectIDActionDialog(hDlg);
    if(nAction == IDCANCEL)
        return TRUE;
    SaveDialog(hDlg);
    
    // Use the proper desired access
    // Note that we also need restore privilege in order to succeed
    if(nAction == IDC_SET_OBJECT_ID || nAction == IDC_DELETE_OBJECT_ID)
    {
        dwFlagsAndAttributes = FILE_FLAG_BACKUP_SEMANTICS;
        dwDesiredAccess = FILE_WRITE_DATA;
    }

    // Convert the file name to the NT file name
    hFile = CreateFile(pData->szFileName1, dwDesiredAccess, 0, NULL, OPEN_EXISTING, dwFlagsAndAttributes, NULL);
    if(hFile == INVALID_HANDLE_VALUE)
        dwErrCode = GetLastError();

    // Perform an action specific to 
    if(dwErrCode == ERROR_SUCCESS)
    {
        switch(nAction)
        {
            case IDC_CREATE_OR_GET:
            case IDC_GET_OBJECT_ID:

                if(nAction == IDC_GET_OBJECT_ID)
                    dwIoctlCode = FSCTL_GET_OBJECT_ID;

                memset(&ObjId, 0, sizeof(FILE_OBJECTID_BUFFER));
                if(DeviceIoControl(hFile, dwIoctlCode,
                                          NULL,
                                          0,
                                         &ObjId,
                                          sizeof(FILE_OBJECTID_BUFFER),
                                         &dwBytesReturned,
                                          NULL))
                {
                    ObjectIDToString(ObjId.ObjectId, pData->szFileName1, szObjectID);
                    SetDlgItemText(hDlg, IDC_OBJECT_ID, szObjectID);
                }
                else
                {
                    dwErrCode = GetLastError();
                }
                break;
            
            case IDC_SET_OBJECT_ID:

                GetDlgItemText(hDlg, IDC_OBJECT_ID, szObjectID, _countof(szObjectID));
                dwErrCode = StringToFileID(szObjectID, NULL, ObjId.ObjectId, NULL);
                if(dwErrCode != ERROR_SUCCESS)
                    break;

                if(!DeviceIoControl(hFile, FSCTL_SET_OBJECT_ID,
                                          &ObjId,
                                           sizeof(FILE_OBJECTID_BUFFER),
                                           NULL,
                                           0,
                                          &dwBytesReturned,
                                           NULL))
                {
                    dwErrCode = GetLastError();
                }
                break;

            case IDC_DELETE_OBJECT_ID:

                if(!DeviceIoControl(hFile, FSCTL_DELETE_OBJECT_ID,
                                            NULL,
                                            0,
                                            NULL,
                                            0,
                                           &dwBytesReturned,
                                            NULL))
                {
                    dwErrCode = GetLastError();
                }
                break;
        }
    }

    if(hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    SetResultInfo(hDlg, RSI_LAST_ERROR, dwErrCode);
    return TRUE;
}

static int OnGetFileAttributes(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    FILE_BASIC_INFORMATION BasicInfo;

    // Save the current state of the dialog
    SaveDialog(hDlg);

    // Retrieve the file attributes
    BasicInfo.FileAttributes = GetFileAttributes(pData->szFileName1);
    if(BasicInfo.FileAttributes != INVALID_FILE_ATTRIBUTES)
    {
        FileAttributesDialog(hDlg, &BasicInfo);
        return TRUE;
    }

    SetResultInfo(hDlg, RSI_LAST_ERROR, GetLastError());
    return TRUE;
}

static int OnNtQueryAttributesFile(HWND hDlg)
{
    FILE_BASIC_INFORMATION BasicInfo;
    OBJECT_ATTRIBUTES ObjAttr;
    TFileTestData * pData = GetDialogData(hDlg);
    UNICODE_STRING FileName = {0, 0, NULL};
    NTSTATUS Status;

    // Save the current state of the dialog
    SaveDialog(hDlg);

    // Retrieve the NT name of the file
    InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = FileNameToUnicodeString(&FileName, pData->szFileName1);

    // Query the attributes
    if(NT_SUCCESS(Status))
    {
        Status = NtQueryAttributesFile(&ObjAttr, &BasicInfo);
        if(NT_SUCCESS(Status))
        {
            NtAttributesDialog(hDlg, &BasicInfo);
        }
    }

    // Set the result information
    if(!NT_SUCCESS(Status))
        SetResultInfo(hDlg, RSI_NTSTATUS, Status);
    FreeFileNameString(&FileName);
    return TRUE;
}

static int OnFlushFile(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    DWORD dwErrCode = ERROR_SUCCESS;

    // Flush the file
    if(!FlushFileBuffers(pData->hFile))
        dwErrCode = GetLastError();

    SetResultInfo(hDlg, RSI_LAST_ERROR, dwErrCode);
    return TRUE;
}

static int OnCreateHardLink(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    DWORD dwErrCode = ERROR_SUCCESS;

    // Check presence of the function
    if(pfnCreateHardLink == NULL)
        return ERROR_CALL_NOT_IMPLEMENTED;

    // Save the current state of the dialog
    SaveDialog(hDlg);

	// Create the hard link
    if(!pfnCreateHardLink(pData->szFileName1, pData->szFileName2, NULL))
        dwErrCode = GetLastError();

    SetResultInfo(hDlg, RSI_LAST_ERROR, dwErrCode);
    return TRUE;
}

static int OnNtDeleteFile(HWND hDlg)
{
    OBJECT_ATTRIBUTES ObjAttr;
    TFileTestData* pData = GetDialogData(hDlg);
    UNICODE_STRING FileName = { 0, 0, NULL };
    NTSTATUS Status;

    // Save the current state of the dialog
    SaveDialog(hDlg);

    // Retrieve the NT name of the file
    InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = FileNameToUnicodeString(&FileName, pData->szFileName1);

    // Delete it
    if(NT_SUCCESS(Status))
    {
        Status = NtDeleteFile(&ObjAttr);
    }

    // Set the result information
    SetResultInfo(hDlg, RSI_NTSTATUS, Status);
    FreeFileNameString(&FileName);
    return TRUE;
}

static int OnEncryptFile(HWND hDlg, UINT nIDCtrl)
{
    TFileTestData* pData = GetDialogData(hDlg);
    DWORD dwErrCode = ERROR_SUCCESS;

    // Save the current state of the dialog
    SaveDialog(hDlg);

    switch (nIDCtrl)
    {
        case IDC_ENCRYPT_FILE:            
            // Perform encryption
            if(!EncryptFile(pData->szFileName1))
                dwErrCode = GetLastError();
            break;

        case IDC_DECRYPT_FILE:
            // Perform decryption
            if(!DecryptFile(pData->szFileName1, 0))
                dwErrCode = GetLastError();
            break;
    }

    SetResultInfo(hDlg, RSI_LAST_ERROR, dwErrCode);
    return TRUE;
}

static int OnSendAsynchronousFsctl(
    HWND hDlg,
    ULONG IoctlCode,
    PVOID InputBuffer = NULL,
    ULONG InputBufferSize = 0,
    PVOID OutputBuffer = NULL,
    ULONG OutputBufferSize = 0)
{
    TFileTestData * pData = GetDialogData(hDlg);
    TApcEntry * pApc;
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;

    // Create new APC entry 
    pApc = (TApcEntry *)CreateApcEntry(pData, APC_TYPE_FSCTL, OutputBufferSize);
    if(pApc != NULL)
    {
        // If there's an output buffer, move it to the APC structure
        if(OutputBuffer && OutputBufferSize)
        {
            memcpy(pApc + 1, OutputBuffer, OutputBufferSize);
            OutputBuffer = (pApc + 1);
        }

        // Send the FSCTL
        Status = NtFsControlFile(pData->hFile,
                                 pApc->hEvent,
                                 NULL,
                                 NULL,
                                &pApc->IoStatus,
                                 IoctlCode,
                                 InputBuffer,
                                 InputBufferSize,
                                 OutputBuffer,
                                 OutputBufferSize);

        // If the IOCTL returned STATUS_PENDING, it means that the oplock is active.
        // If the oplock breaks, the event becomes signalled, and we get the APC message
        if(Status == STATUS_PENDING)
        {
            pApc->UserParam = IoctlCode;
            InsertApcEntry(pData, pApc);
        }
        else
        {
            FreeApcEntry(pApc);
        }
    }

    SetResultInfo(hDlg, RSI_NTSTATUS, Status);
    return TRUE;
}

static int OnSendRequestOplock(HWND hDlg, bool bRequestOplock)
{
    REQUEST_OPLOCK_OUTPUT_BUFFER Out;
    REQUEST_OPLOCK_INPUT_BUFFER In;
    TFileTestData * pData = GetDialogData(hDlg);
    DWORD RequestedOplockLevel = 0;
    DWORD InputFlags = REQUEST_OPLOCK_INPUT_FLAG_ACK;

    // If the caller is requesting oplock, ask the user which one he wants
    if(bRequestOplock)
    {
        // Ask the user for flags
        if(FlagsDialog(hDlg, IDS_OPLOCK_FLAGS, Win7OplockFlags, pData->dwOplockLevel) != IDOK)
            return TRUE;
        RequestedOplockLevel = pData->dwOplockLevel;
        InputFlags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;
    }

    // Prepare the input buffer
    // Note that value of 0 in In.Flags causes BSOD in FastFat.sys
    // 
    memset(&In, 0, sizeof(REQUEST_OPLOCK_INPUT_BUFFER));
    In.StructureLength = sizeof(REQUEST_OPLOCK_INPUT_BUFFER);
    In.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    In.RequestedOplockLevel = RequestedOplockLevel;
    In.Flags = InputFlags;

    // Prepare the output buffer
    memset(&Out, 0, sizeof(REQUEST_OPLOCK_OUTPUT_BUFFER));
    Out.StructureLength = sizeof(REQUEST_OPLOCK_OUTPUT_BUFFER);
    Out.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;

    // Send the FSCTL to the file system
    return OnSendAsynchronousFsctl(hDlg,
                                   FSCTL_REQUEST_OPLOCK,
                                  &In,
                                   sizeof(REQUEST_OPLOCK_INPUT_BUFFER),
                                  &Out,
                                   sizeof(REQUEST_OPLOCK_OUTPUT_BUFFER));
}

static void OnCompleteOplockApc(TWindowData * pData, TApcEntry * pApc)
{
    LPCTSTR szOplockType = _T("unknown");
    LPCTSTR szBrokenTo = _T("unknown");

    // Sanity check
    assert(pApc->ApcType == APC_TYPE_FSCTL);

    // Get the type of oplock
    switch(pApc->UserParam)
    {
        case FSCTL_REQUEST_OPLOCK_LEVEL_1:
            szOplockType = _T("level 1/exclusive");
            break;

        case FSCTL_REQUEST_OPLOCK_LEVEL_2:
            szOplockType = _T("level 2/shared");
            break;

        case FSCTL_REQUEST_BATCH_OPLOCK:
            szOplockType = _T("batch");
            break;

        case FSCTL_REQUEST_FILTER_OPLOCK:
            szOplockType = _T("filter");
            break;

        default:
            assert(false);
            break;
    }

    // Get the type of oplock that the old has been broken to
    switch(pApc->IoStatus.Information)
    {
        case FILE_OPLOCK_BROKEN_TO_LEVEL_2:
            szBrokenTo = _T("level 2/shared");
            break;

        case FILE_OPLOCK_BROKEN_TO_NONE:
            szBrokenTo = _T("none");
            break;

        default:
            assert(false);
            break;
    }

    // Show the message box that the oplock broke
    MessageBoxRc(pData->hDlg, IDS_INFO, IDS_OPLOCK_BROKE, szOplockType, szBrokenTo);
}

static void OnCompleteOplockApc_Win7(TWindowData * pData, TApcEntry * pApc)
{
    PREQUEST_OPLOCK_OUTPUT_BUFFER pOut;
    LPCTSTR szOplockType;
    LPCTSTR szBrokenTo;
    TCHAR szBuffer1[0x40];
    TCHAR szBuffer2[0x40];

    // Sanity check
    assert(pApc->UserParam == FSCTL_REQUEST_OPLOCK);
    pOut = (PREQUEST_OPLOCK_OUTPUT_BUFFER)(pApc + 1);

    // Get the original and new type of oplock
    // Note: Even if the new oplock is non-zero,
    // the event will not trigger again even if we requeue it to the APC thread
    szOplockType = FormatOplockTypeWindows7(szBuffer1, _countof(szBuffer1), pOut->OriginalOplockLevel);
    szBrokenTo = FormatOplockTypeWindows7(szBuffer2, _countof(szBuffer2), pOut->NewOplockLevel);

    // Show the message box that the oplock broke
    MessageBoxRc(pData->hDlg, IDS_INFO, IDS_OPLOCK_BROKE, szOplockType, szBrokenTo);
}

static int OnApc(HWND hDlg, LPARAM lParam)
{
    TWindowData * pData = GetDialogData(hDlg);
    TApcEntry * pApc = (TApcEntry *)lParam;

    // Perform APC-specific action
    if(pApc->ApcType == APC_TYPE_FSCTL)
    {
        // Show the result in the result UI
        SetResultInfo(hDlg, RSI_NTSTATUS, pApc->IoStatus.Status);
       
        // If the APC was an oplock APC, also show the result
        switch(pApc->UserParam)
        {
            case FSCTL_REQUEST_OPLOCK_LEVEL_1:
            case FSCTL_REQUEST_OPLOCK_LEVEL_2:
            case FSCTL_REQUEST_BATCH_OPLOCK:
            case FSCTL_REQUEST_FILTER_OPLOCK:
                OnCompleteOplockApc(pData, pApc);
                break;

            case FSCTL_REQUEST_OPLOCK:
                OnCompleteOplockApc_Win7(pData, pApc);
                break;
        }
    }

    FreeApcEntry(pApc);
    return TRUE;
}

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    OPENFILENAME ofn;

    if(nNotify == BN_CLICKED)
    {
        switch(nIDCtrl)
        {
            case IDC_FILE_NAME1_BROWSE:

                InitOpenFileName(&ofn);
                ofn.lpstrFile = MAKEINTRESOURCE(IDC_FILE_NAME1);
                ofn.lpstrTitle = MAKEINTRESOURCE(IDS_SELECT_FILE);
                ofn.lpstrFilter = MAKEINTRESOURCE(IDS_FILTER_ALL);
                GetOpenFileNameRc(hDlg, &ofn);
                return TRUE;

            case IDC_FILE_NAME2_BROWSE:
                InitOpenFileName(&ofn);
                ofn.lpstrFile = MAKEINTRESOURCE(IDC_FILE_NAME2);
                ofn.lpstrTitle = MAKEINTRESOURCE(IDS_SELECT_FILE);
                ofn.lpstrFilter = MAKEINTRESOURCE(IDS_FILTER_ALL);
                GetOpenFileNameRc(hDlg, &ofn);
                return TRUE;

            case IDC_COPY_FILE:
                return OnCopyFileClick(hDlg);

            case IDC_MOVE_FILE:
                return OnMoveFileClick(hDlg);

            case IDC_COPY_OPTIONS:
                return OnCopyOptions(hDlg);

            case IDC_MOVE_OPTIONS:
                return OnMoveOptions(hDlg);

            case IDC_DELETE_FILE_MENU:
                return ExecuteContextMenuForDlgItem(hDlg, FindContextMenu(IDR_DELETE_FILE_MENU), IDC_DELETE_FILE_MENU);

            case IDC_SIMPLE_DELETE:
            case IDC_FORCED_DELETE:
                return OnDeleteFileClick(hDlg, nIDCtrl);

            case IDC_DELETE_OBJECT_MENU:
                return ExecuteContextMenuForDlgItem(hDlg, FindContextMenu(IDR_DELETE_OBJECT_MENU), IDC_DELETE_OBJECT_MENU);

            case IDC_DELETE_OBJECT_SINGLE:
                return OnDeleteFsObject(hDlg, FALSE);

            case IDC_DELETE_OBJECT_TREE:
                return OnDeleteFsObject(hDlg, TRUE);

            case IDC_FILE_ID_GET:
                return OnFileIdGetClick(hDlg);

            case IDC_FILE_ID_USE:
                return OnFileIdUse(hDlg, IDC_FILE_ID);

            case IDC_OBJECT_ID_MORE:
                return OnObjectIdMoreClick(hDlg);

            case IDC_OBJECT_ID_USE:
                return OnFileIdUse(hDlg, IDC_OBJECT_ID);

            case IDC_NT_QUERY_ATTRIBUTES_FILE:
                return OnNtQueryAttributesFile(hDlg);

            case IDC_GET_FILE_ATTRIBUTES:
                return OnGetFileAttributes(hDlg);

            case IDC_FLUSH_FILE_BUFFERS:
                return OnFlushFile(hDlg);

            case IDC_CREATE_HARDLINK:
                return OnCreateHardLink(hDlg);

            case IDC_NT_DELETE_FILE:
                return OnNtDeleteFile(hDlg);

            case IDC_ENCRYPT_FILE:
            case IDC_DECRYPT_FILE:
                return OnEncryptFile(hDlg, nIDCtrl);

            case IDC_REQUEST_OPLOCK_MENU:
                return ExecuteContextMenuForDlgItem(hDlg, FindContextMenu(IDR_REQUEST_OPLOCK_MENU), IDC_REQUEST_OPLOCK_MENU);

            case IDC_REQUEST_OPLOCK_1:
                return OnSendAsynchronousFsctl(hDlg, FSCTL_REQUEST_OPLOCK_LEVEL_1);

            case IDC_REQUEST_OPLOCK_2:
                return OnSendAsynchronousFsctl(hDlg, FSCTL_REQUEST_OPLOCK_LEVEL_2);

            case IDC_REQUEST_BATCH_OPLOCK:
                return OnSendAsynchronousFsctl(hDlg, FSCTL_REQUEST_BATCH_OPLOCK);

            case IDC_REQUEST_FILTER_OPLOCK:
                return OnSendAsynchronousFsctl(hDlg, FSCTL_REQUEST_FILTER_OPLOCK);

            case IDC_BREAK_ACKNOWLEDGE_1:
                return OnSendAsynchronousFsctl(hDlg, FSCTL_OPLOCK_BREAK_ACKNOWLEDGE);

            case IDC_REQUEST_OPLOCK_WIN7:
                return OnSendRequestOplock(hDlg, true);

            case IDC_BREAK_ACKNOWLEDGE_2:
                return OnSendRequestOplock(hDlg, false);
        }
    }

    if(nNotify == EN_CHANGE)
    {
        if(nIDCtrl == IDC_FILE_ID)
            OnFileIDChange(hDlg, nIDCtrl, IDC_FILE_ID_USE);
        if(nIDCtrl == IDC_OBJECT_ID)
            OnFileIDChange(hDlg, nIDCtrl, IDC_OBJECT_ID_USE);
    }

    return FALSE;
}

static int OnNotify(HWND hDlg, NMHDR * pNMHDR)
{
    switch(pNMHDR->code)
    {
        case PSN_SETACTIVE:
            return OnSetActive(hDlg);

        case PSN_KILLACTIVE:
            return OnKillActive(hDlg);

        case UDN_DELTAPOS:
            return OnDeltaPos(hDlg, (NMUPDOWN *)pNMHDR);
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// Public functions

INT_PTR CALLBACK PageProc05(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
        case WM_INITDIALOG:
            return OnInitDialog(hDlg, lParam);

        case WM_SIZE:
            if(pAnchors != NULL)
                pAnchors->OnSize();
            return FALSE;

        case WM_APC:
            return OnApc(hDlg, lParam);

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

