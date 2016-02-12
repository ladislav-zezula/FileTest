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
    FLAG_INFO_ENTRY(COPY_FILE_FAIL_IF_EXISTS),
    FLAG_INFO_ENTRY(COPY_FILE_RESTARTABLE),
    FLAG_INFO_ENTRY(COPY_FILE_OPEN_SOURCE_FOR_WRITE),
    FLAG_INFO_ENTRY(COPY_FILE_ALLOW_DECRYPTED_DESTINATION),
    FLAG_INFO_SEPARATOR(),
    {{_T("Use Manual Copy (ReadFile+WriteFile)")}, COPY_FILE_USE_READ_WRITE, COPY_FILE_USE_READ_WRITE},
    {{_T("Manual Copy: Skip Read Errors")},        COPY_FILE_SKIP_IO_ERRORS, COPY_FILE_SKIP_IO_ERRORS},
    {{_T("Manual Copy: Log Read Errors")},         COPY_FILE_LOG_IO_ERRORS,  COPY_FILE_LOG_IO_ERRORS},
    {{_T("Manual Copy: Copy per sector")},         COPY_FILE_PER_SECTOR,     COPY_FILE_PER_SECTOR},
    FLAG_INFO_END
};

static TFlagInfo MoveFileFlags[] =
{
    FLAG_INFO_ENTRY(MOVEFILE_REPLACE_EXISTING),
    FLAG_INFO_ENTRY(MOVEFILE_COPY_ALLOWED),
    FLAG_INFO_ENTRY(MOVEFILE_DELAY_UNTIL_REBOOT),
    FLAG_INFO_ENTRY(MOVEFILE_WRITE_THROUGH),
    FLAG_INFO_ENTRY(MOVEFILE_CREATE_HARDLINK),
    FLAG_INFO_ENTRY(MOVEFILE_FAIL_IF_NOT_TRACKABLE),
    FLAG_INFO_END
};

static TFlagInfo Win7OplockFlags[] =
{
    FLAG_INFO_ENTRY(OPLOCK_LEVEL_CACHE_READ),
    FLAG_INFO_ENTRY(OPLOCK_LEVEL_CACHE_HANDLE),
    FLAG_INFO_ENTRY(OPLOCK_LEVEL_CACHE_WRITE),
    FLAG_INFO_END
};

//-----------------------------------------------------------------------------
// Helper functions

extern TFlagInfo FileAttributesValues[];

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

static NTSTATUS NtSetFileAccessToEveryone(POBJECT_ATTRIBUTES ObjAttr, ACCESS_MASK AccessMask)
{
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;
    HANDLE FileHandle;
    ULONG OpenOptions = FILE_OPEN_REPARSE_POINT;

    // Attempt to set the file's security. If this fails, it either means that
    // the current user doesn't have WRITE_DAC access or the current user
    // is not the owner of the file
    Status = NtOpenFile(&FileHandle,
                         WRITE_DAC,
                         ObjAttr,
                        &IoStatus,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         OpenOptions);
    if(Status == STATUS_ACCESS_DENIED)
    {
        // Write the owner to the file.
        Status = NtOpenFile(&FileHandle,
                             WRITE_OWNER,
                             ObjAttr,
                            &IoStatus,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             OpenOptions);
        if(NT_SUCCESS(Status))
        {
            NtTakeOwnershipObject(FileHandle);
            NtClose(FileHandle);
        }

        // After writing ownership, attempt to set the file access again
        Status = NtOpenFile(&FileHandle,
                             WRITE_DAC,
                             ObjAttr,
                            &IoStatus,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             OpenOptions);
    }

    // If succeeded, write the file security
    if(NT_SUCCESS(Status))
    {
        Status = NtSetObjectAccessForEveryone(FileHandle, AccessMask);
        NtClose(FileHandle);
    }

    // If the file access also includes WRITE, we also clear all attributes
    if(AccessMask & (GENERIC_ALL | GENERIC_WRITE | FILE_WRITE_DATA | DELETE))
    {
        FILE_BASIC_INFORMATION BasicInfo;

        Status = NtOpenFile(&FileHandle,
                             FILE_WRITE_ATTRIBUTES,
                             ObjAttr,
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

static NTSTATUS NtRemoveDirectoryTree(POBJECT_ATTRIBUTES PtrObjectAttributes)
{
    PFILE_DIRECTORY_INFORMATION pDirInfo;
    OBJECT_ATTRIBUTES ChildAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING ChildPath;
    NTSTATUS DelStatus;
    NTSTATUS Status;
    HANDLE DirHandle = NULL;
    ULONG TryCount = 0;
    BYTE DirBuffer[0x300];

    // Open the directory for enumeration+delete
    // Use FILE_OPEN_REPARSE_POINT, because the directory can be
    // a reparse point (even an invalid one) and still contain files/subdirs
    __TryOpenDirectory:
    Status = NtOpenFile(&DirHandle,
                         FILE_LIST_DIRECTORY | DELETE | SYNCHRONIZE,
                         PtrObjectAttributes,
                        &IoStatus,
                         FILE_SHARE_READ,
                         FILE_SYNCHRONOUS_IO_ALERT | FILE_DELETE_ON_CLOSE | FILE_OPEN_REPARSE_POINT);
    
    // When the access is denied, we can try to reset the permissions
    if(Status == STATUS_ACCESS_DENIED && TryCount == 0)
    {
        Status = NtSetFileAccessToEveryone(PtrObjectAttributes, GENERIC_ALL | DELETE);
        if(NT_SUCCESS(Status))
        {
            TryCount++;
            goto __TryOpenDirectory;
        }
    }

    if(NT_SUCCESS(Status))
    {
        // Prepare the child object attributes and the pointer to directory entry
        InitializeObjectAttributes(&ChildAttr, &ChildPath, OBJ_CASE_INSENSITIVE, DirHandle, NULL);
        pDirInfo = (PFILE_DIRECTORY_INFORMATION)DirBuffer;

        // Work as long as we have something
        while(Status == STATUS_SUCCESS)
        {
            // Query a single item
            Status = NtQueryDirectoryFile(DirHandle,
                                          NULL,
                                          NULL,
                                          NULL,
                                         &IoStatus,
                                          pDirInfo,
                                          sizeof(DirBuffer),
                                          FileDirectoryInformation,
                                          TRUE,
                                          NULL,
                                          FALSE);
            if(Status == STATUS_SUCCESS && !IsDotDirectoryName(pDirInfo))
            {
                // Create the child path
                ChildPath.MaximumLength =
                ChildPath.Length = (USHORT)pDirInfo->FileNameLength;
                ChildPath.Buffer = pDirInfo->FileName;

                // If the entry is a reparse point, we need to delete the reparse first
                if(pDirInfo->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                {
                    Status = NtDeleteReparsePoint(&ChildAttr);
                    if(!NT_SUCCESS(Status))
                        break;
                }

                // If the entry has the FILE_ATTRIBUTE_READONLY (both file/subdir),
                // we need to clear it first
                if(pDirInfo->FileAttributes & FILE_ATTRIBUTE_READONLY)
                {
                    Status = NtSetFileAccessToEveryone(&ChildAttr, GENERIC_ALL | DELETE);
                    if(!NT_SUCCESS(Status))
                        break;
                }

                // If this is a directory, we need to delete the directory
                if(pDirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                {
                    Status = NtRemoveDirectoryTree(&ChildAttr);
                }
                else
                {
                    Status = NtRemoveSingleFile(&ChildAttr);
                }
            }
        }

        // Close the directory handle, (also) performing the delete
        DelStatus = NtClose(DirHandle);
        if(NT_SUCCESS(Status) || Status == STATUS_NO_MORE_FILES)
            Status = DelStatus;
    }

    // Return the result
    return Status;
}

static int ForceRemoveFile(LPCTSTR szFileName)
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

    return RtlNtStatusToDosError(Status);
}

static int RemoveDirectoryTree(LPCTSTR szDirName)
{
    OBJECT_ATTRIBUTES ObjAttr;
    UNICODE_STRING PathName;
    NTSTATUS Status;

    // Convert to UNICODE_STRING
    Status = FileNameToUnicodeString(&PathName, szDirName);
    if(NT_SUCCESS(Status))
    {
        InitializeObjectAttributes(&ObjAttr, &PathName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = NtRemoveDirectoryTree(&ObjAttr);
        FreeFileNameString(&PathName);
    }

    return RtlNtStatusToDosError(Status);
}

static int SaveDialog(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    if((pData->dwCreateOptions & FILE_OPEN_BY_FILE_ID) == 0)
        GetDlgItemText(hDlg, IDC_FILE_NAME1, pData->szFileName1, _maxchars(pData->szFileName1));
    GetDlgItemText(hDlg, IDC_FILE_NAME2, pData->szFileName2, _maxchars(pData->szFileName2));
    return ERROR_SUCCESS;
}


// This function enables/disables the buttons for map operations
static int UpdateDialogButtons(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    BOOL bEnable = IsHandleValid(pData->hFile) ? TRUE : FALSE;

    EnableDlgItems(hDlg, bEnable, 
                         IDC_FLUSH_FILE_BUFFERS,
                         IDC_SET_SPARSE,
                         IDC_REQUEST_OPLOCK_MENU,
                         IDC_BREAK_ACKNOWLEDGE_1,
                         IDC_REQUEST_OPLOCK_WIN7,
                         IDC_BREAK_ACKNOWLEDGE_2,
                         0);
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
        pAnchors->AddAnchor(hDlg, IDC_DELETE_DIRECTORY, akTop | akRight);

        pAnchors->AddAnchor(hDlg, IDC_FILEID_FRAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_ID, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_ID_USE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_OBJECT_ID, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_OBJECT_ID_USE, akTop | akRight);

        pAnchors->AddAnchor(hDlg, IDC_OTHERS_FRAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_NT_QUERY_ATTRIBUTES_FILE, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_GET_FILE_ATTRIBUTES, akRight | akTop);
        pAnchors->AddAnchor(hDlg, IDC_FLUSH_FILE_BUFFERS, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_SET_SPARSE, akRight | akTop);

        pAnchors->AddAnchor(hDlg, IDC_OPLOCKS_FRAME, akAll);
        pAnchors->AddAnchor(hDlg, IDC_REQUEST_OPLOCK_MENU, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_BREAK_ACKNOWLEDGE_1, akRight | akTop);
        pAnchors->AddAnchor(hDlg, IDC_REQUEST_OPLOCK_WIN7, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_BREAK_ACKNOWLEDGE_2, akRight | akTop);


        pAnchors->AddAnchor(hDlg, IDC_RESULT_FRAME, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_LAST_ERROR_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_LAST_ERROR, akLeft | akRight | akBottom);
    }

    // Initialize tooltips
    g_Tooltip.AddToolTip(hDlg, IDC_NT_QUERY_ATTRIBUTES_FILE, IDS_NT_QUERY_ATTRIBUTES_FILE_TIP);
    g_Tooltip.AddToolTip(hDlg, IDC_GET_FILE_ATTRIBUTES,      IDS_GET_FILE_ATTRIBUTES_TIP);
    g_Tooltip.AddToolTip(hDlg, IDC_FLUSH_FILE_BUFFERS,       IDS_FLUSH_FILE_BUFFERS_TIP);
    g_Tooltip.AddToolTip(hDlg, IDC_SET_SPARSE,               IDS_SET_SPARSE_TIP);

    Hex2DlgText64(hDlg, IDC_BYTE_OFFSET, 0);
    Hex2DlgText32(hDlg, IDC_LENGTH, 0x10000);
    return TRUE;
}

static int OnSetActive(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    if((pData->dwCreateOptions & FILE_OPEN_BY_FILE_ID) == 0)
    {
        SetDlgItemText(hDlg, IDC_FILE_NAME1, pData->szFileName1);
        ConvertToWin32Name(hDlg, IDC_FILE_NAME1);
    }
    else
    {
        pData->szDirName[0] = 0;
        pData->dwCreateOptions &= ~FILE_OPEN_BY_FILE_ID;
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
    int nError;

    // Get the source and target file
    GetDlgItemText(hDlg, IDC_FILE_NAME1, pData->szFileName1, _maxchars(pData->szFileName1));
    GetDlgItemText(hDlg, IDC_FILE_NAME2, pData->szFileName2, _maxchars(pData->szFileName2));

    // Run the copy file dialog
    nError = (int)CopyFileDialog(hDlg, pData);

    // Set the result
    SetResultInfo(hDlg, nError);
    return TRUE;
}

static int OnMoveFileClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    int nError = ERROR_SUCCESS;

    SaveDialog(hDlg);

    // Perform the rename
    if(!MoveFileEx(pData->szFileName1, pData->szFileName2, pData->dwMoveFileFlags))
        nError = GetLastError();

    // Set the result
    SetResultInfo(hDlg, nError);
    return TRUE;
}

static int OnCopyOptions(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    FlagsDialog(hDlg, &pData->dwCopyFileFlags, IDS_COPYFILE_FLAGS, CopyFileFlags);
    return TRUE;
}

static int OnMoveOptions(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    FlagsDialog(hDlg, &pData->dwMoveFileFlags, IDS_MOVEFILE_FLAGS, MoveFileFlags);
    return TRUE;
}

static int OnDeleteFileClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    int nError = ERROR_SUCCESS;

    // Save the dialog variables
    SaveDialog(hDlg);

    // Choose what exactly to do
    switch(FileActionDialog(hDlg))
    {
        case IDC_SIMPLE_DELETE:
            if(!DeleteFile(pData->szFileName1))
                nError = GetLastError();
            break;

        case IDC_FORCED_DELETE:
            nError = ForceRemoveFile(pData->szFileName1);
            break;

        default:
            return TRUE;
    }

    UpdateDialogButtons(hDlg);
    SetResultInfo(hDlg, nError);
    return TRUE;
}

static int OnDeleteDirectoryClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    int nError = ERROR_SUCCESS;

    // Save the dialog variables
    SaveDialog(hDlg);

    // Choose what exactly to do
    switch(DirectoryActionDialog(hDlg))
    {
        case IDC_SINGLE_DIRECTORY:
            if(!RemoveDirectory(pData->szFileName1))
                nError = GetLastError();
            break;

        case IDC_DIRECTORY_TREE:
            nError = RemoveDirectoryTree(pData->szFileName1);
            break;

        default:
            return TRUE;
    }
    
    SetResultInfo(hDlg, nError);
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
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
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
    SetResultInfo(hDlg, RtlNtStatusToDosError(Status));
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
    GetDlgItemText(hDlg, nIDEdit, szFileId, _maxchars(szFileId));
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
    int nError = ERROR_SUCCESS;

    // Ask the user for the action
    nAction = ObjectIDActionDialog(hDlg);
    if(nAction == IDCANCEL)
        return TRUE;
    SaveDialog(hDlg);
    
    // Use the proper desired access
    // Note that we also need restore privilege in order to succeed
    if(nAction == IDC_SET_OBJECT_ID)
    {
        dwFlagsAndAttributes = FILE_FLAG_BACKUP_SEMANTICS;
        dwDesiredAccess = FILE_WRITE_DATA;
    }

    // Convert the file name to the NT file name
    hFile = CreateFile(pData->szFileName1, dwDesiredAccess, 0, NULL, OPEN_EXISTING, dwFlagsAndAttributes, NULL);
    if(hFile == INVALID_HANDLE_VALUE)
        nError = GetLastError();

    // Perform an action specific to 
    if(nError == ERROR_SUCCESS)
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
                    nError = GetLastError();
                }
                break;
            
            case IDC_SET_OBJECT_ID:

                GetDlgItemText(hDlg, IDC_OBJECT_ID, szObjectID, _maxchars(szObjectID));
                nError = StringToFileID(szObjectID, NULL, ObjId.ObjectId, NULL);
                if(nError != ERROR_SUCCESS)
                    break;

                if(!DeviceIoControl(hFile, FSCTL_SET_OBJECT_ID,
                                          &ObjId,
                                           sizeof(FILE_OBJECTID_BUFFER),
                                           NULL,
                                           0,
                                          &dwBytesReturned,
                                           NULL))
                {
                    nError = GetLastError();
                }
                break;
        }
    }

    if(hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    SetResultInfo(hDlg, nError);
    return TRUE;
}

static int OnGetFileAttributes(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    TFlagInfo * pFlags = FileAttributesValues;
    TCHAR szFileAttributes[512] = _T("");
    DWORD dwAttr;
    int nError = ERROR_SUCCESS;

    SaveDialog(hDlg);
    dwAttr = GetFileAttributes(pData->szFileName1);
    if(dwAttr != INVALID_FILE_ATTRIBUTES)
    {
        for(int i = 0; pFlags->dwValue != 0; i++, pFlags++)
        {
            if(IS_FLAG_SET(pFlags, dwAttr))
            {
                if(szFileAttributes[0] != 0)
                    StringCchCat(szFileAttributes, _countof(szFileAttributes), _T("\n"));
                StringCchCat(szFileAttributes, _countof(szFileAttributes), pFlags->szFlagText);
            }
        }

        if(szFileAttributes[0] == 0)
            StringCchCopy(szFileAttributes, _countof(szFileAttributes), _T("0"));
        MessageBoxRc(hDlg, IDS_FILE_ATTRIBUTES, (UINT_PTR)szFileAttributes);
    }
    else
        nError = GetLastError();

    SetResultInfo(hDlg, nError);
    return TRUE;
}

static int OnNtQueryAttributesFile(HWND hDlg)
{
    FILE_BASIC_INFORMATION BasicInfo;
    OBJECT_ATTRIBUTES ObjAttr;
    TFileTestData * pData = GetDialogData(hDlg);
    UNICODE_STRING FileName = {0, 0, NULL};
    NTSTATUS Status;
    TCHAR szMsgText[512] = _T("");

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
            StringCchPrintf(szMsgText, _countof(szMsgText),
                                 _T("CreationTime: %08X-%08X\n")
                                 _T("LastAccessTime: %08X-%08X\n")
                                 _T("LastWriteTime: %08X-%08X\n")
                                 _T("ChangeTime: %08X-%08X\n")
                                 _T("FileAttributes: %08X"),
                                 BasicInfo.CreationTime.HighPart, BasicInfo.CreationTime.LowPart, 
                                 BasicInfo.LastAccessTime.HighPart, BasicInfo.LastAccessTime.LowPart, 
                                 BasicInfo.LastWriteTime.HighPart, BasicInfo.LastWriteTime.LowPart, 
                                 BasicInfo.ChangeTime.HighPart, BasicInfo.ChangeTime.LowPart, 
                                 BasicInfo.FileAttributes);
            MessageBoxRc(hDlg, IDS_FILE_BASIC_INFORMATION, (UINT_PTR)szMsgText);
        }
    }

    // Set the result information
    SetResultInfo(hDlg, Status);
    FreeFileNameString(&FileName);
    return TRUE;
}

static int OnFlushFile(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    int nError = ERROR_SUCCESS;

	if(!FlushFileBuffers(pData->hFile))
        nError = GetLastError();

    SetResultInfo(hDlg, nError);
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
    pApc = (TApcEntry *)CreateApcEntry(pData, APC_TYPE_FSCTL, sizeof(TApcEntry) + OutputBufferSize);
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

    SetResultInfo(hDlg, RtlNtStatusToDosError(Status));
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
        if(FlagsDialog(hDlg, &pData->dwOplockLevel, IDS_OPLOCK_FLAGS, Win7OplockFlags) != IDOK)
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
        SetResultInfo(hDlg, pApc->IoStatus.Status);
       
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

            case IDC_DELETE_FILE:
                return OnDeleteFileClick(hDlg);

            case IDC_DELETE_DIRECTORY:
                return OnDeleteDirectoryClick(hDlg);

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

            case IDC_SET_SPARSE:
                return OnSendAsynchronousFsctl(hDlg, FSCTL_SET_SPARSE);

            case IDC_REQUEST_OPLOCK_MENU:
                return ExecuteContextMenuForDlgItem(hDlg, IDC_REQUEST_OPLOCK_MENU, IDR_OPLOCK_PRE_WIN7);

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
