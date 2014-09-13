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
    FLAG_INFO_ENTRY(MOVEFILE_REPLACE_EXISTING,      TRUE),
    FLAG_INFO_ENTRY(MOVEFILE_COPY_ALLOWED,          TRUE),
    FLAG_INFO_ENTRY(MOVEFILE_DELAY_UNTIL_REBOOT,    TRUE),
    FLAG_INFO_ENTRY(MOVEFILE_WRITE_THROUGH,         TRUE),
    FLAG_INFO_ENTRY(MOVEFILE_CREATE_HARDLINK,       TRUE),
    FLAG_INFO_ENTRY(MOVEFILE_FAIL_IF_NOT_TRACKABLE, TRUE),
    FLAG_INFO_END
};

static TFlagInfo Win7OplockFlags[] =
{
    FLAG_INFO_ENTRY(OPLOCK_LEVEL_CACHE_READ,        TRUE),
    FLAG_INFO_ENTRY(OPLOCK_LEVEL_CACHE_HANDLE,      TRUE),
    FLAG_INFO_ENTRY(OPLOCK_LEVEL_CACHE_WRITE,       TRUE),
    FLAG_INFO_END
};

//-----------------------------------------------------------------------------
// Helper functions

extern TFlagInfo FileAttributesValues[];

static BOOL CopyFileByHand(const TCHAR * szOrigFile, const TCHAR * szNewFile)
{
    FILETIME ft1;
    FILETIME ft2;
    FILETIME ft3;
    HANDLE hFile1 = INVALID_HANDLE_VALUE;
    HANDLE hFile2 = INVALID_HANDLE_VALUE;
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
    if(nError == ERROR_SUCCESS)
    {
        if(!GetFileTime(hFile1, &ft1, &ft2, &ft3))
            nError = GetLastError();
    }

    // Copy the content
    if(nError == ERROR_SUCCESS)
    {
        BYTE  * pbBuffer = NULL;
        DWORD dwBufferSize = 0x10000;
        DWORD dwTransferred = 1;

        pbBuffer = new BYTE [dwBufferSize];
        while(dwTransferred != 0)
        {
            ReadFile(hFile1, pbBuffer, dwBufferSize, &dwTransferred, NULL);
            if(dwTransferred != 0)
                WriteFile(hFile2, pbBuffer, dwTransferred, &dwTransferred, NULL);
        }
        delete pbBuffer;
    }

    // Get the file time of the original file
    if(nError == ERROR_SUCCESS)
    {
        if(!SetFileTime(hFile2, &ft1, &ft2, &ft3))
            nError = GetLastError();
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

static int RemoveDirectoryPath(LPCTSTR szDirName)
{
    LPTSTR szDirectory;
    LPTSTR szPathPart;
    LPTSTR szTemp;
    int nError = ERROR_SUCCESS;

    // Allocate copy of the directory
    szDirectory = new TCHAR[_tcslen(szDirName) + 1];
    if(szDirectory != NULL)
    {
        // Copy the directory name to the new buffer
        _tcscpy(szDirectory, szDirName);

        // Find the first part that is actually a directory
        szPathPart = FindDirectoryPathPart(szDirectory);
        if(szPathPart != NULL)
        {
            // Delete the lowest-level directory
            if(RemoveDirectory(szDirectory))
            {
                // Now delete all inner parts
                while((szTemp = _tcsrchr(szPathPart, _T('\\'))) != NULL)
                {
                    // Terminate the path part
                    *szTemp = 0;

                    // Delete that inner part
                    if(!RemoveDirectory(szDirectory))
                    {
                        nError = GetLastError();
                        break;
                    }
                }
            }
            else
            {
                nError = GetLastError();
            }
        }
        else
        {
            nError = ERROR_BAD_PATHNAME;
        }

        // Delete the allocated buffer
        delete [] szDirectory;
    }
    else
    {
        nError = ERROR_NOT_ENOUGH_MEMORY;
    }

    return nError;
}

static int SaveDialog(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    if((pData->dwCreateOptions & FILE_OPEN_BY_FILE_ID) == 0)
        GetDlgItemText(hDlg, IDC_FILE_NAME1, pData->szFileName1, _tsize(pData->szFileName1));
    GetDlgItemText(hDlg, IDC_FILE_NAME2, pData->szFileName2, _tsize(pData->szFileName2));
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
                         IDC_REQUEST_OPLOCK_1,
                         IDC_REQUEST_OPLOCK_2,
                         IDC_REQUEST_BATCH_OPLOCK,
                         IDC_REQUEST_FILTER_OPLOCK,
                         IDC_REQUEST_OPLOCK,
                         IDC_BREAK_ACK,
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
        pAnchors->AddAnchor(hDlg, IDC_REQUEST_OPLOCK_1, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_REQUEST_OPLOCK_2, akRight | akTop);
        pAnchors->AddAnchor(hDlg, IDC_REQUEST_BATCH_OPLOCK, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_REQUEST_FILTER_OPLOCK, akRight | akTop);
        pAnchors->AddAnchor(hDlg, IDC_REQUEST_OPLOCK, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_BREAK_ACK, akRight | akTop);
        

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
        GetDlgItemText(hDlg, IDC_FILE_NAME1, pData->szFileName1, _tsize(pData->szFileName1));
        GetDlgItemText(hDlg, IDC_FILE_NAME2, pData->szFileName2, _tsize(pData->szFileName2));

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

        case IDC_ENTIRE_PATH:

            // Delete the directory recursively
            nError = RemoveDirectoryPath(pData->szFileName1);
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
    GetDlgItemText(hDlg, nIDEdit, szFileId, _tsize(szFileId));
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

                GetDlgItemText(hDlg, IDC_OBJECT_ID, szObjectID, _tsize(szObjectID));
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
    TCHAR szFileAttributes[512] = _T("");
    DWORD dwAttr;
    int nError = ERROR_SUCCESS;

    SaveDialog(hDlg);
    dwAttr = GetFileAttributes(pData->szFileName1);
    if(dwAttr != INVALID_FILE_ATTRIBUTES)
    {
        for(int i = 0; FileAttributesValues[i].dwFlag != 0; i++)
        {
            if(dwAttr & FileAttributesValues[i].dwFlag)
            {
                _tcscat(szFileAttributes, FileAttributesValues[i].szFlagText);
                _tcscat(szFileAttributes, _T("\n"));
            }
        }

        if(szFileAttributes[0] == 0)
            _tcscpy(szFileAttributes, _T("0"));
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
            _stprintf(szMsgText, _T("CreationTime: %08X-%08X\n")
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

static int OnSetSparse(HWND hDlg)
{
    FILE_SET_SPARSE_BUFFER Buff;
    TFileTestData * pData = GetDialogData(hDlg);
    DWORD dwBytesReturned = 0;
    int nError = ERROR_SUCCESS;

    Buff.SetSparse = TRUE;
    if(!DeviceIoControl(pData->hFile, FSCTL_SET_SPARSE,
                                     &Buff,
                                      sizeof(FILE_SET_SPARSE_BUFFER),
                                      NULL,
                                      0,
                                     &dwBytesReturned,
                                      NULL))
    {
        nError = GetLastError();
    }

    SetResultInfo(hDlg, nError);
    return TRUE;
}

static int OnSendOplockIoctl(HWND hDlg, size_t ApcType, ULONG IoctlCode)
{
    TFileTestData * pData = GetDialogData(hDlg);
    TApcOplock * pApc;
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;

    // Create new APC entry 
    pApc = (TApcOplock *)CreateApcEntry(pData, ApcType, sizeof(TApcOplock));
    if(pApc != NULL)
    {
        // Request the oplock
        Status = NtFsControlFile(pData->hFile,
                                 pApc->hEvent,
                                 NULL,
                                 NULL,
                                &pApc->IoStatus,
                                 IoctlCode,
                                 NULL,
                                 0,
                                 NULL,
                                 0);

        // If the IOCTL returned STATUS_PENDING, it means that the oplock is active.
        // If the oplock breaks, the event becomes signalled, and we get the APC message
        if(Status == STATUS_PENDING)
        {
            pApc->dwIoctlCode = IoctlCode;
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

static int OnRequestOplockWin7(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    TApcOplock * pApc;
    NTSTATUS Status = STATUS_SUCCESS;

    // Ask the user for flags
    if(FlagsDialog(hDlg, &pData->dwOplockLevel, IDS_OPLOCK_FLAGS, Win7OplockFlags) != IDOK)
        return TRUE;

    // Create a new APC entry to hold all information
    pApc = (TApcOplock *)CreateApcEntry(pData, APC_TYPE_OPLOCK, sizeof(TApcOplock));
    if(pApc != NULL)
    {
        // Prepare the input buffer
        pApc->In.StructureLength = sizeof(REQUEST_OPLOCK_INPUT_BUFFER);
        pApc->In.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
        pApc->In.RequestedOplockLevel = pData->dwOplockLevel;
        pApc->In.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;

        // Prepare the output buffer
        pApc->Out.StructureLength = sizeof(REQUEST_OPLOCK_OUTPUT_BUFFER);
        pApc->Out.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;

        // Request the oplock
        Status = NtFsControlFile(pData->hFile,
                                 pApc->hEvent,
                                 NULL,
                                 NULL,
                                &pApc->IoStatus,
                                 FSCTL_REQUEST_OPLOCK,
                                &pApc->In,
                                 sizeof(REQUEST_OPLOCK_INPUT_BUFFER),
                                &pApc->Out,
                                 sizeof(REQUEST_OPLOCK_OUTPUT_BUFFER));

        // If the IOCTL returned STATUS_PENDING, it means that the oplock is active.
        // If the oplock breaks, the event becomes signalled, and we get the APC message
        if(Status == STATUS_PENDING)
        {
            pApc->dwIoctlCode = FSCTL_REQUEST_OPLOCK;
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
                return OnSetSparse(hDlg);

            case IDC_REQUEST_OPLOCK_1:
                return OnSendOplockIoctl(hDlg, APC_TYPE_OPLOCK, FSCTL_REQUEST_OPLOCK_LEVEL_1);

            case IDC_REQUEST_OPLOCK_2:
                return OnSendOplockIoctl(hDlg, APC_TYPE_OPLOCK, FSCTL_REQUEST_OPLOCK_LEVEL_2);

            case IDC_REQUEST_BATCH_OPLOCK:
                return OnSendOplockIoctl(hDlg, APC_TYPE_OPLOCK, FSCTL_REQUEST_BATCH_OPLOCK);

            case IDC_REQUEST_FILTER_OPLOCK:
                return OnSendOplockIoctl(hDlg, APC_TYPE_OPLOCK, FSCTL_REQUEST_FILTER_OPLOCK);

            case IDC_REQUEST_OPLOCK:
                return OnRequestOplockWin7(hDlg);

            case IDC_BREAK_ACK:
                return OnSendOplockIoctl(hDlg, APC_TYPE_OPLOCK_BREAK, FSCTL_OPLOCK_BREAK_ACKNOWLEDGE);
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
