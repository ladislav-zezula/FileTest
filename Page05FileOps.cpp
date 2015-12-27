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

static BOOL CopyFileByHand(const TCHAR * szOrigFile, const TCHAR * szNewFile)
{
    FILETIME ft1;
    FILETIME ft2;
    FILETIME ft3;
    HANDLE hFile1 = INVALID_HANDLE_VALUE;
    HANDLE hFile2 = INVALID_HANDLE_VALUE;
    bool bHasFileTime = false;
    int nError = ERROR_SUCCESS;

    // Open the original file
    if(nError == ERROR_SUCCESS)
    {
        hFile1 = CreateFile(szOrigFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if(IsHandleInvalid(hFile1))
            nError = GetLastError();
    }

    // (Re)create the new file
    if(nError == ERROR_SUCCESS)
    {
        hFile2 = CreateFile(szNewFile, GENERIC_READ | GENERIC_WRITE | DELETE | WRITE_DAC, 0, NULL, OPEN_ALWAYS, 0, NULL);
        if(IsHandleInvalid(hFile2))
            nError = GetLastError();
    }

    // Get the file time of the original file
    // Note that the SetFileTime can fail if the second file
    // is actually a volume (\\.\GlobalRoot\Device\HarddiskVolume15)
    // Do not report the error
    if(nError == ERROR_SUCCESS)
    {
        if(GetFileTime(hFile1, &ft1, &ft2, &ft3))
            bHasFileTime = true;
    }

    // Copy the content
    if(nError == ERROR_SUCCESS)
    {
        BYTE  * pbBuffer = NULL;
        DWORD dwBufferSize = 0x10000;

        // Allocate buffer
        pbBuffer = (LPBYTE)HeapAlloc(g_hHeap, 0, dwBufferSize);
        if(pbBuffer != NULL)
        {
            // Perform the copy
            for(;;)
            {
                DWORD dwTransferred = 0;

                // Read the source file/drive
                if(!ReadFile(hFile1, pbBuffer, dwBufferSize, &dwTransferred, NULL))
                {
                    nError = GetLastError();
                    break;
                }

                // If nothing was read, stop it
                if(dwTransferred == 0)
                    break;

                if(!WriteFile(hFile2, pbBuffer, dwTransferred, &dwTransferred, NULL))
                    break;
            }

            // Free the buffer
            HeapFree(g_hHeap, 0, pbBuffer);
        }
    }

    // Set the file time of the copied file
    // Note that the SetFileTime can fail if the second file
    // is actually a volume (\\.\GlobalRoot\Device\HarddiskVolume15)
    // Do not report the error
    if(nError == ERROR_SUCCESS && bHasFileTime)
    {
        SetFileTime(hFile2, &ft1, &ft2, &ft3);
    }

    // Close both files
    if(IsHandleValid(hFile2))
        CloseHandle(hFile2);
    if(IsHandleValid(hFile1))
        CloseHandle(hFile1);
    
    if(nError != ERROR_SUCCESS)
    {
        SetLastError(nError);
        return FALSE;
    }
    return TRUE;
}

static bool IsDotDirectoryName(PFILE_DIRECTORY_INFORMATION pDirInfo)
{
    if(pDirInfo->FileNameLength == 2 && pDirInfo->FileName[0] == L'.')
        return true;
    if(pDirInfo->FileNameLength == 4 && pDirInfo->FileName[0] == L'.' && pDirInfo->FileName[1] == L'.')
        return true;

    return false;
}

static NTSTATUS NtRemoveSingleFile(PUNICODE_STRING PathName)
{
    OBJECT_ATTRIBUTES ObjAttr;
    NTSTATUS PrevStatus = 0xFFFFFFFF;
    NTSTATUS Status;

    // Initialize object attributes for the file name
    InitializeObjectAttributes(&ObjAttr, PathName, OBJ_CASE_INSENSITIVE, NULL, 0);

__TryDeleteFile:
    Status = NtDeleteFile(&ObjAttr);

    // Happens when deleting the "desktop.ini" in Windows 10 preinstallation directory
    if(Status == STATUS_IO_REPARSE_TAG_NOT_HANDLED && PrevStatus != STATUS_IO_REPARSE_TAG_NOT_HANDLED)
    {
        // Remember the previous error status
        PrevStatus = Status;

        // Delete the reparse point first
        Status = NtDeleteReparsePoint(PathName);
        if(NT_SUCCESS(Status))
            goto __TryDeleteFile;
    }

    return Status;
}

static NTSTATUS NtRemoveDirectoryTree(PUNICODE_STRING PathName)
{
    PFILE_DIRECTORY_INFORMATION pDirInfo;
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING ChildPath;
    NTSTATUS Status;
    HANDLE DirHandle = NULL;
    BYTE DirBuffer[0x300];

    // Open the directory for enumeration
    InitializeObjectAttributes(&ObjAttr, PathName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&DirHandle,
                         FILE_LIST_DIRECTORY | SYNCHRONIZE,
                        &ObjAttr,
                        &IoStatus,
                         FILE_SHARE_READ,
                         FILE_SYNCHRONOUS_IO_ALERT);
    if(NT_SUCCESS(Status))
    {
        pDirInfo = (PFILE_DIRECTORY_INFORMATION)DirBuffer;
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
                // Copy the dir to the child path
                ChildPath = *PathName;
                
                // Append the backslash
                ChildPath.Buffer[ChildPath.Length / 2] = L'\\';
                ChildPath.Length += sizeof(WCHAR);

                // Append subdir/file
                memcpy(ChildPath.Buffer + ChildPath.Length / 2, pDirInfo->FileName, pDirInfo->FileNameLength);
                ChildPath.Length = (USHORT)(ChildPath.Length + pDirInfo->FileNameLength);

                // If this is a directory, we need to delete the directory
                if(pDirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                {
                    Status = NtRemoveDirectoryTree(&ChildPath);
                }
                else
                {
                    Status = NtRemoveSingleFile(&ChildPath);
                }

                // Terminate the substring with zero, just for the sake of readability
                ChildPath.Buffer[ChildPath.Length / 2] = 0;
            }
        }

        // Close the directory handle
        NtClose(DirHandle);
    }

    // Open the directory for enumeration
    InitializeObjectAttributes(&ObjAttr, PathName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtDeleteFile(&ObjAttr);
}

static int RemoveDirectoryTree(LPCTSTR szDirName)
{
    UNICODE_STRING PathName;
    UNICODE_STRING TempName;
    NTSTATUS Status;

    // Convert to UNICODE_STRING
    Status = FileNameToUnicodeString(&TempName, szDirName);
    if(NT_SUCCESS(Status))
    {
        // Reallocate the UNICODE_STRING
        PathName.MaximumLength = 0xFFFE;
        PathName.Length = TempName.Length;
        PathName.Buffer = (PWSTR)RtlAllocateHeap(RtlProcessHeap(),
                                                 HEAP_ZERO_MEMORY,
                                                 PathName.MaximumLength);
        if(PathName.Buffer != NULL)
        {
            // Copy the string
            memcpy(PathName.Buffer, TempName.Buffer, TempName.Length);
            Status = NtRemoveDirectoryTree(&PathName);

            // Free the path name
            RtlFreeHeap(RtlProcessHeap(), 0, PathName.Buffer);
        }
        else
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }

        FreeFileNameString(&TempName);
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

    Button_SetCheck(GetDlgItem(hDlg, IDC_USE_COPYAPI), BST_CHECKED);
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
    BOOL  bUseCopyFile = FALSE;
    BOOL  bResult = FALSE;
    int nError = ERROR_SUCCESS;

    // Decide whether we have to copy by hand or not
    SaveDialog(hDlg);
    bUseCopyFile = (Button_GetCheck(GetDlgItem(hDlg, IDC_USE_COPYAPI)) == BST_CHECKED);

    // Perform the copy
    if(nError == ERROR_SUCCESS)
    {
        GetDlgItemText(hDlg, IDC_FILE_NAME1, pData->szFileName1, _maxchars(pData->szFileName1));
        GetDlgItemText(hDlg, IDC_FILE_NAME2, pData->szFileName2, _maxchars(pData->szFileName2));

        if(bUseCopyFile)
            bResult = CopyFile(pData->szFileName1, pData->szFileName2, FALSE);
        else
            bResult = CopyFileByHand(pData->szFileName1, pData->szFileName2);

        if(bResult == FALSE)
            nError = GetLastError();
    }

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

    SaveDialog(hDlg);
    if(!DeleteFile(pData->szFileName1))
        nError = GetLastError();

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
            
            // Just delete single directory as-is
            if(!RemoveDirectory(pData->szFileName1))
                nError = GetLastError();
            break;

        case IDC_DIRECTORY_TREE:

            // Delete the directory recursively
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
