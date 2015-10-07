/*****************************************************************************/
/* Page05NtCreate.cpp                     Copyright (c) Ladislav Zezula 2004 */
/*---------------------------------------------------------------------------*/
/* Description:                                                              */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 06.03.04  1.00  Lad  The first version of Page05NtCreate.cpp              */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

#define FILE_ID_SIZE 16

//-----------------------------------------------------------------------------
// Flags

static TFlagInfo DesiredAccessValues[] =
{
    {_T("FILE_READ_DATA/FILE_LIST_DIRECTORY"),     FILE_READ_DATA,         TRUE},
    {_T("FILE_WRITE_DATA/FILE_ADD_FILE"),          FILE_WRITE_DATA,        TRUE},
    {_T("FILE_APPEND_DATA/FILE_ADD_SUBDIRECTORY"), FILE_APPEND_DATA,       TRUE},
    {_T("FILE_READ_EA"),                           FILE_READ_EA,           TRUE},
    {_T("FILE_WRITE_EA"),                          FILE_WRITE_EA,          TRUE},
    {_T("FILE_EXECUTE/FILE_TRAVERSE"),             FILE_EXECUTE,           TRUE},
    {_T("FILE_DELETE_CHILD"),                      FILE_DELETE_CHILD,      TRUE},
    {_T("FILE_READ_ATTRIBUTES"),                   FILE_READ_ATTRIBUTES,   TRUE},
    {_T("FILE_WRITE_ATTRIBUTES"),                  FILE_WRITE_ATTRIBUTES,  TRUE},

    FLAG_INFO_ENTRY(DELETE,                 TRUE),
    FLAG_INFO_ENTRY(READ_CONTROL,           TRUE),
    FLAG_INFO_ENTRY(WRITE_DAC,              TRUE),
    FLAG_INFO_ENTRY(WRITE_OWNER,            TRUE),
    FLAG_INFO_ENTRY(SYNCHRONIZE,            TRUE),
    FLAG_INFO_ENTRY(ACCESS_SYSTEM_SECURITY, TRUE),
    FLAG_INFO_ENTRY(GENERIC_READ,           TRUE),
    FLAG_INFO_ENTRY(GENERIC_WRITE,          TRUE),
    FLAG_INFO_ENTRY(GENERIC_EXECUTE,        TRUE),
    FLAG_INFO_ENTRY(GENERIC_ALL,            TRUE),
    FLAG_INFO_ENTRY(MAXIMUM_ALLOWED,        TRUE),
    FLAG_INFO_END
};

// Also necessary in Page04FileOps.cpp
TFlagInfo FileAttributesValues[] =
{
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_READONLY,            TRUE),
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_HIDDEN,              TRUE),
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_SYSTEM,              TRUE),
    FLAG_INFO_ENTRY(OLD_DOS_VOLID,                      FALSE),
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_DIRECTORY,           TRUE),
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_ARCHIVE,             TRUE),
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_DEVICE,              TRUE),
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_NORMAL,              TRUE),
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_TEMPORARY,           TRUE),
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_SPARSE_FILE,         TRUE),
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_REPARSE_POINT,       TRUE),
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_COMPRESSED,          TRUE),
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_OFFLINE,             TRUE),
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, TRUE),
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_ENCRYPTED,           TRUE),
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_INTEGRITY_STREAM,    TRUE),
    FLAG_INFO_ENTRY(FILE_ATTRIBUTE_VIRTUAL,             TRUE),
    FLAG_INFO_END
};

static TFlagInfo ShareAccessValues[] =
{
    FLAG_INFO_ENTRY(FILE_SHARE_READ,   TRUE),
    FLAG_INFO_ENTRY(FILE_SHARE_WRITE,  TRUE),
    FLAG_INFO_ENTRY(FILE_SHARE_DELETE, TRUE),
    FLAG_INFO_END
};

static TFlagInfo CreateOptionsValues[] =
{
    FLAG_INFO_ENTRY(FILE_DIRECTORY_FILE,            TRUE),
    FLAG_INFO_ENTRY(FILE_WRITE_THROUGH,             TRUE),
    FLAG_INFO_ENTRY(FILE_SEQUENTIAL_ONLY,           TRUE),
    FLAG_INFO_ENTRY(FILE_NO_INTERMEDIATE_BUFFERING, TRUE),
    FLAG_INFO_ENTRY(FILE_SYNCHRONOUS_IO_ALERT,      TRUE),
    FLAG_INFO_ENTRY(FILE_SYNCHRONOUS_IO_NONALERT,   TRUE),
    FLAG_INFO_ENTRY(FILE_NON_DIRECTORY_FILE,        TRUE),
    FLAG_INFO_ENTRY(FILE_CREATE_TREE_CONNECTION,    TRUE),
    FLAG_INFO_ENTRY(FILE_COMPLETE_IF_OPLOCKED,      TRUE),
    FLAG_INFO_ENTRY(FILE_NO_EA_KNOWLEDGE,           TRUE),
    FLAG_INFO_ENTRY(FILE_OPEN_FOR_RECOVERY,         TRUE),
    FLAG_INFO_ENTRY(FILE_RANDOM_ACCESS,             TRUE),
    FLAG_INFO_ENTRY(FILE_DELETE_ON_CLOSE,           TRUE),
    FLAG_INFO_ENTRY(FILE_OPEN_BY_FILE_ID,           TRUE),
    FLAG_INFO_ENTRY(FILE_OPEN_FOR_BACKUP_INTENT,    TRUE),
    FLAG_INFO_ENTRY(FILE_NO_COMPRESSION,            TRUE),
    FLAG_INFO_ENTRY(FILE_OPEN_REQUIRING_OPLOCK,     TRUE),
    FLAG_INFO_ENTRY(FILE_DISALLOW_EXCLUSIVE,        TRUE),
    FLAG_INFO_ENTRY(FILE_SESSION_AWARE,             TRUE),
    FLAG_INFO_ENTRY(FILE_RESERVE_OPFILTER,          TRUE),
    FLAG_INFO_ENTRY(FILE_OPEN_REPARSE_POINT,        TRUE),
    FLAG_INFO_ENTRY(FILE_OPEN_NO_RECALL,            TRUE),
    FLAG_INFO_ENTRY(FILE_OPEN_FOR_FREE_SPACE_QUERY, TRUE),
    FLAG_INFO_END
};

static TFlagInfo ObjAttrFlagsValues[] =
{
    FLAG_INFO_ENTRY(OBJ_INHERIT,                    TRUE),
    FLAG_INFO_ENTRY(OBJ_PERMANENT,                  TRUE),
    FLAG_INFO_ENTRY(OBJ_EXCLUSIVE,                  TRUE),
    FLAG_INFO_ENTRY(OBJ_CASE_INSENSITIVE,           TRUE),    
    FLAG_INFO_ENTRY(OBJ_OPENIF,                     TRUE),
    FLAG_INFO_ENTRY(OBJ_OPENLINK,                   TRUE),
    FLAG_INFO_ENTRY(OBJ_KERNEL_HANDLE,              TRUE),
    FLAG_INFO_ENTRY(OBJ_FORCE_ACCESS_CHECK,         TRUE),
    FLAG_INFO_END
};

//-----------------------------------------------------------------------------
// Local functions

static NTSTATUS MyCreateDirectory(TFileTestData * pData, POBJECT_ATTRIBUTES pObjAttr, PIO_STATUS_BLOCK pIoStatus)
{
    NTSTATUS Status;
    HANDLE SaveTransactionHandle = NULL;
    HANDLE DirectoryHandle = NULL;

    if(pData->bUseTransaction)
    {
        SaveTransactionHandle = pfnRtlGetCurrentTransaction();
        pfnRtlSetCurrentTransaction(pData->hTransaction);
    }

    Status = NtCreateFile(&DirectoryHandle,
                           FILE_ADD_FILE,
                           pObjAttr,
                           pIoStatus,
                           NULL,
                           FILE_ATTRIBUTE_DIRECTORY,
                           FILE_SHARE_READ,
                           FILE_OPEN_IF,
                           FILE_DIRECTORY_FILE,
                           NULL,
                           0);
    
    if(DirectoryHandle != NULL)
        NtClose(DirectoryHandle);

    if(pData->bUseTransaction)
    {
        pfnRtlSetCurrentTransaction(SaveTransactionHandle);
    }

    // If the directory already exists, take it as success
    return Status;
}

static int QuickAccessSelection(HWND hDlg, DWORD dwDesiredAccess, DWORD dwShareAccess, bool bSynchronous)
{
    DWORD dwCreateOptions;

    // Retrieve the create options from the dialog
    DlgText2Hex32(hDlg, IDC_CREATE_OPTIONS, &dwCreateOptions);

    // Fix desired access according to bAsynchronous
    if(bSynchronous)
    {
        dwCreateOptions |= FILE_SYNCHRONOUS_IO_NONALERT;
        dwDesiredAccess |= SYNCHRONIZE;
    }
    else
    {
        dwCreateOptions &= ~(FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT);
        dwDesiredAccess &= ~SYNCHRONIZE;
    }

    // Set or reset DeleteOnClose flag
    if(dwDesiredAccess & DELETE)
        dwCreateOptions |= FILE_DELETE_ON_CLOSE;
    else
        dwCreateOptions &= ~FILE_DELETE_ON_CLOSE;

    // Apply the create options to the dialog controls
    Hex2DlgText32(hDlg, IDC_DESIRED_ACCESS, dwDesiredAccess);
    Hex2DlgText32(hDlg, IDC_SHARE_ACCESS, dwShareAccess);
    Hex2DlgText32(hDlg, IDC_CREATE_OPTIONS, dwCreateOptions);
    return TRUE;
}

static int SaveDialog(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    HWND hCombo = GetDlgItem(hDlg, IDC_CREATE_DISPOSITION);
    int nError;

    GetDlgItemText(hDlg, IDC_DIRECTORY_NAME, pData->szDirName, _maxchars(pData->szDirName));
    GetDlgItemText(hDlg, IDC_FILE_NAME, pData->szFileName1, _maxchars(pData->szFileName1));

    if((nError = DlgText2Hex32(hDlg, IDC_OBJ_ATTR_FLAGS, &pData->dwObjAttrFlags)) != ERROR_SUCCESS)
        return nError;
    if((nError = DlgText2Hex32(hDlg, IDC_DESIRED_ACCESS, &pData->dwDesiredAccess)) != ERROR_SUCCESS)
        return nError;
    if((nError = DlgText2Hex32(hDlg, IDC_FILE_ATTRIBUTES, &pData->dwFileAttributes)) != ERROR_SUCCESS)
        return nError;
    if((nError = DlgText2Hex32(hDlg, IDC_SHARE_ACCESS, &pData->dwShareAccess)) != ERROR_SUCCESS)
        return nError;
    if((nError = DlgText2Hex32(hDlg, IDC_CREATE_OPTIONS, &pData->dwCreateOptions)) != ERROR_SUCCESS)
        return nError;
    if((nError = DlgText2Hex64(hDlg, IDC_ALLOCATION_SIZE, &pData->AllocationSize)) != ERROR_SUCCESS)
        return nError;

    pData->dwCreateDisposition2 = ComboBox_GetCurSel(hCombo);
    pData->bUseTransaction      = (IsDlgButtonChecked(hDlg, IDC_TRANSACTED) == BST_CHECKED);
    return ERROR_SUCCESS;
}
                                                             
//-----------------------------------------------------------------------------
// Message handlers

static TAnchors * pAnchors = NULL;

static int OnNtCloseClick(HWND hDlg);

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    TFileTestData * pData;
    PROPSHEETPAGE * pPage = (PROPSHEETPAGE *)lParam;
    HWND hCombo = GetDlgItem(hDlg, IDC_CREATE_DISPOSITION);

    SetDialogData(hDlg, pPage->lParam);
    pData = (TFileTestData *)pPage->lParam;

    // Configure dialog resizing
    if(pData->bEnableResizing)
    {
        pAnchors = new TAnchors();
        pAnchors->AddAnchor(hDlg, IDC_MAIN_FRAME, akAll);
        pAnchors->AddAnchor(hDlg, IDC_DIRECTORY_NAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_DIRECTORY_NAME_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_NAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_NAME_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_OBJ_ATTR_FLAGS, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_OBJ_ATTR_FLAGS_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_DESIRED_ACCESS, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_DESIRED_ACCESS_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_ALLOCATION_SIZE, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_ALLOCATION_SIZE_UPDOWN, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_ATTRIBUTES, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_ATTRIBUTES_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SHARE_ACCESS, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SHARE_ACCESS_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_CREATE_DISPOSITION, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_CREATE_OPTIONS, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_CREATE_OPTIONS_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_EXTENDED_ATTRIBUTES, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_EXTENDED_ATTRIBUTES_EDIT, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_TRANSACTED, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_VIRTUALIZATION, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_BREAKPOINT, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_PRIVILEGES, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_MAKE_DIRECTORY, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_CREATE_FILE, akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_CLOSE_HANDLE, akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_FRAME, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_STATUS_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_STATUS, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_HANDLE_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_HANDLE, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_NTCREATE_RESULT_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_NTCREATE_RESULT, akLeft | akRight | akBottom);
    }

    // Initialize the "Relative File" hyperlink
    InitURLButton(hDlg, IDC_RELATIVE_FILE_HELP, FALSE);

    // Initialize the combo box
    InitDialogControls(hDlg, MAKEINTRESOURCE(IDD_PAGE02_NTCREATE));
    if(hCombo != NULL)
        ComboBox_SetCurSel(hCombo, pData->dwCreateDisposition2);

    // If we have a tooltip window, init tooltips 
    g_Tooltip.AddToolTip(hDlg, IDC_OBJ_ATTR_FLAGS, ObjAttrFlagsValues);
    g_Tooltip.AddToolTip(hDlg, IDC_DESIRED_ACCESS, DesiredAccessValues);
    g_Tooltip.AddToolTip(hDlg, IDC_FILE_ATTRIBUTES, FileAttributesValues);
    g_Tooltip.AddToolTip(hDlg, IDC_SHARE_ACCESS, ShareAccessValues);
    g_Tooltip.AddToolTip(hDlg, IDC_CREATE_OPTIONS, CreateOptionsValues);

    // On post-Vista, enable the virtualization button
    if(GetVirtualizationFlags(NULL))
        EnableDlgItems(hDlg, TRUE, IDC_VIRTUALIZATION, 0);

    return TRUE;
}

static int OnSetActive(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    TCHAR szEaInfo[128];
    DWORD dwVirtFlags = 0;
    BOOL bEnabled;
    int nChecked;

    // Set directory name and file name
    SetDlgItemText(hDlg, IDC_DIRECTORY_NAME, pData->szDirName);
    SetDlgItemText(hDlg, IDC_FILE_NAME, pData->szFileName1);

    // Convert both to NT name.
    if(GetWindowTextLength(GetDlgItem(hDlg, IDC_DIRECTORY_NAME)) == 0)
        ConvertToNtName(hDlg, IDC_FILE_NAME);
    ConvertToNtName(hDlg, IDC_DIRECTORY_NAME);

    // Set the various create options
    Hex2DlgText32(hDlg, IDC_OBJ_ATTR_FLAGS, pData->dwObjAttrFlags);
    Hex2DlgText32(hDlg, IDC_DESIRED_ACCESS, pData->dwDesiredAccess);
    Hex2DlgText64(hDlg, IDC_ALLOCATION_SIZE, pData->AllocationSize);
    Hex2DlgText32(hDlg, IDC_FILE_ATTRIBUTES, pData->dwFileAttributes);
    Hex2DlgText32(hDlg, IDC_SHARE_ACCESS, pData->dwShareAccess);
    Hex2DlgText32(hDlg, IDC_CREATE_OPTIONS, pData->dwCreateOptions);

    // Update the info about extended attributes
    rsprintf(szEaInfo, _maxchars(szEaInfo), IDS_EA_INFO, pData->pFileEa, pData->dwEaSize);
    SetDlgItemText(hDlg, IDC_EXTENDED_ATTRIBUTES, szEaInfo);

    // Enable/disable transaction
    bEnabled = (pfnRtlSetCurrentTransaction != NULL && IsHandleValid(pData->hTransaction));
    EnableDlgItems(hDlg, bEnabled, IDC_TRANSACTED, 0);
    nChecked = (bEnabled && pData->bUseTransaction) ? BST_CHECKED : BST_UNCHECKED;
    CheckDlgButton(hDlg, IDC_TRANSACTED, nChecked);

    // Check/uncheck virtualization
    nChecked = (GetVirtualizationFlags(&dwVirtFlags) && dwVirtFlags) ? BST_CHECKED : BST_UNCHECKED;
    CheckDlgButton(hDlg, IDC_VIRTUALIZATION, nChecked);

    // Enable/disable "NtClose"
    bEnabled = IsHandleValid(pData->hFile) ? TRUE : FALSE;
    EnableDlgItems(hDlg, bEnabled, IDC_CLOSE_HANDLE, 0);
    return TRUE;
}

static int OnKillActive(HWND hDlg)
{
    SaveDialog(hDlg);
    return TRUE;
}

static int OnRelativeFileHelp(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    TCHAR szMsgBuff[512];
    LPTSTR szBuffer = szMsgBuff;
    int nLength = 0;

    // Load both parts of the message
    nLength += LoadString(g_hInst, IDS_RELATIVE_FILE1, szBuffer + nLength, _maxchars(szMsgBuff) - nLength);
    nLength += LoadString(g_hInst, IDS_RELATIVE_FILE2, szBuffer + nLength, _maxchars(szMsgBuff) - nLength);
    nLength += rsprintf(szBuffer + nLength, IDS_RELATIVE_FILE3, pData->dwDesiredAccessRF,
                                                                pData->dwOpenOptionsRF,
                                                                pData->dwShareAccessRF);
    // Show the message
    MessageBoxRc(hDlg, IDS_RELATIVE_FILE_TITLE, (UINT_PTR)szMsgBuff);
    return TRUE;
}

static int OnBrowseDirClick(HWND hDlg)
{
    BrowseForDirectory(hDlg, MAKEINTRESOURCE(IDC_DIRECTORY_NAME), IDS_SELECT_DIRECTORY);
    ConvertToNtName(hDlg, IDC_DIRECTORY_NAME);
    return TRUE;
}

static int OnBrowseFileClick(HWND hDlg)
{
    OPENFILENAME ofn;

    InitOpenFileName(&ofn);
    ofn.lpstrFile = MAKEINTRESOURCE(IDC_FILE_NAME);
    ofn.lpstrTitle = MAKEINTRESOURCE(IDS_SELECT_FILE);
    ofn.lpstrFilter = MAKEINTRESOURCE(IDS_FILTER_ALL);
     
    if(GetOpenFileNameRc(hDlg, &ofn))
    {
        SetDlgItemText(hDlg, IDC_DIRECTORY_NAME, _T(""));
        ConvertToNtName(hDlg, IDC_FILE_NAME);
    }
    return TRUE;
}

static int OnObjAtributesFlags(HWND hDlg)
{
    FlagsDialog(hDlg, IDC_OBJ_ATTR_FLAGS, IDS_OBJECT_ATTRIBUTES_FLAGS, ObjAttrFlagsValues);
    return TRUE;
}

static int OnDesiredAccessClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    bool bRelativeFile = (GetAsyncKeyState(VK_SHIFT) < 0);

    // Shall we edit desired access for relative file?
    if(bRelativeFile)
    {
        FlagsDialog(hDlg, &pData->dwDesiredAccessRF, IDS_DESIRED_ACCESS_RF, DesiredAccessValues);
        return TRUE;
    }

    // Show the dialog for desired access
    FlagsDialog(hDlg, IDC_DESIRED_ACCESS, IDS_DESIRED_ACCESS, DesiredAccessValues);
    return TRUE;
}

static int OnFileAttributesClick(HWND hDlg)
{
    FlagsDialog(hDlg, IDC_FILE_ATTRIBUTES, IDS_FILE_ATTRIBUTES, FileAttributesValues);
    return TRUE;
}

static int OnShareAccessClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    bool bRelativeFile = (GetAsyncKeyState(VK_SHIFT) < 0);

    // Shall we edit desired access for relative file?
    if(bRelativeFile)
    {
        FlagsDialog(hDlg, &pData->dwShareAccessRF, IDS_SHARE_ACCESS_RF, ShareAccessValues);
        return TRUE;
    }

    // Show the dialog for desired access
    FlagsDialog(hDlg, IDC_SHARE_ACCESS, IDS_SHARE_ACCESS, ShareAccessValues);
    return TRUE;
}

static int OnCreateOptionsClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    bool bRelativeFile = (GetAsyncKeyState(VK_SHIFT) < 0);

    // Shall we edit desired access for relative file?
    if(bRelativeFile)
    {
        FlagsDialog(hDlg, &pData->dwOpenOptionsRF, IDS_OPEN_OPTIONS_RF, CreateOptionsValues);
        return TRUE;
    }

    // Show the dialog for desired access
    FlagsDialog(hDlg, IDC_CREATE_OPTIONS, IDS_CREATE_OPTIONS, CreateOptionsValues);
    return TRUE;
}

static int OnEditEaClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    TCHAR szEaInfo[128];

    // Invoke the editor of the extended attributes
    if(ExtendedAtributesEditorDialog(hDlg, pData) == IDOK)
    {
        // Update the info about extended attributes
        rsprintf(szEaInfo, _maxchars(szEaInfo), IDS_EA_INFO, pData->pFileEa, pData->dwEaSize);
        SetDlgItemText(hDlg, IDC_EXTENDED_ATTRIBUTES, szEaInfo);
    }

    return TRUE;
}

static int OnVirtualization(HWND hDlg)
{
    DWORD dwNewValue = (IsDlgButtonChecked(hDlg, IDC_VIRTUALIZATION) == BST_CHECKED) ? 1 : 0;

    SetVirtualizationFlags(dwNewValue);
    return TRUE;
}

static int OnMakeDirectoryClick(HWND hDlg)
{
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus = {0, 0};
    UNICODE_STRING FileName;
    TFileTestData * pData = GetDialogData(hDlg);
    NTSTATUS Status = STATUS_SUCCESS;
    LPTSTR szDirectory = pData->szDirName;
    LPTSTR szPathPart = pData->szDirName;
    LPTSTR szTemp;
    USHORT SaveLength;

    // Get the values from dialog controls to the dialog data
    if(SaveDialog(hDlg) != ERROR_SUCCESS)
        return FALSE;

    // Initialize object attributes and the unicode string
    InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&FileName, pData->szDirName);
    SaveLength = FileName.Length;

    // Now parse the directory as-is, create every sub-directory
    if(szDirectory[0] != 0)
    {
        // Now find the begin of the first directory part
        szPathPart = FindDirectoryPathPart(szDirectory);
        if(szPathPart != NULL)
        {
            while(szPathPart[0] != 0)
            {
                // Find either next backslash or end of string
                szTemp = FindNextPathSeparator(szPathPart);
                
                // Create the directory part
                FileName.Length = (USHORT)((szTemp - szDirectory) * sizeof(WCHAR));
                Status = MyCreateDirectory(pData, &ObjAttr, &IoStatus);
                if(!NT_SUCCESS(Status))
                    break;

                // Go to the next part of the path
                FileName.Length = SaveLength;
                szPathPart = szTemp;
            }
        }
        else
        {
            Status = MyCreateDirectory(pData, &ObjAttr, &IoStatus);
        }
    }
    else
    {
        Status = MyCreateDirectory(pData, &ObjAttr, &IoStatus);
    }

    SetResultInfo(hDlg, Status, NULL, IoStatus.Information);
    return TRUE;
}

static int OnCreateFileClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING FileName;
    UNICODE_STRING DirName;
    LARGE_INTEGER AllocationSize;
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE SaveTransactionHandle = NULL;
    TCHAR szFileName[MAX_NT_PATH];
    TCHAR szDirName[MAX_NT_PATH];
    DWORD cbObjectID = 0;
    BYTE ObjectID[0x10];

    // Close the handle, if already open
    if(IsHandleValid(pData->hDirectory) || IsHandleValid(pData->hFile))
        OnNtCloseClick(hDlg);

    // Get the various create options
    if(SaveDialog(hDlg) != ERROR_SUCCESS)
        return FALSE;

    if(pData->bUseTransaction && pfnRtlSetCurrentTransaction != NULL)
    {
        SaveTransactionHandle = pfnRtlGetCurrentTransaction();
        pfnRtlSetCurrentTransaction(pData->hTransaction);
    }

    // Get the directory name from the dialog data
    _tcscpy(szDirName, pData->szDirName);
    _tcscpy(szFileName, pData->szFileName1);

    // If we are about to open a file by ID, and we have no relative directory,
    // try to take the directory from the file name
    if(szDirName[0] == 0 && (pData->dwCreateOptions & FILE_OPEN_BY_FILE_ID))
    {
        LPTSTR szFullName = pData->szFileName1;
        LPTSTR szFileId = _tcsrchr(szFullName, _T('\\'));
        size_t nLength = szFileId - szFullName + 1;

        if(szFileId != NULL)
        {
            _tcsncpy(szDirName, szFullName, nLength);
            szDirName[nLength] = 0;
            _tcscpy(szFileName, szFileId + 1);
        }
    }

    // Open the relative file (if any)
    if(szDirName[0] != 0)
    {
        RtlInitUnicodeString(&DirName, szDirName);
        InitializeObjectAttributes(&ObjAttr, &DirName, pData->dwObjAttrFlags, 0, NULL);
        Status = NtOpenFile(&pData->hDirectory,
                             pData->dwDesiredAccessRF,
                            &ObjAttr,
                            &IoStatus,
                             pData->dwShareAccessRF,
                             pData->dwOpenOptionsRF);

        if(!NT_SUCCESS(Status))
        {
            SetResultInfo(hDlg, Status, NULL, IoStatus.Information);
            return TRUE;
        }
    }

    // Prepare the file open
    if(NT_SUCCESS(Status))
    {
        RtlInitUnicodeString(&FileName, szFileName);

        // If open by ID required, set the ID to the string
        if(pData->dwCreateOptions & FILE_OPEN_BY_FILE_ID)
        {
            // Convert object ID to binary value
            if(StringToFileID(szFileName, NULL, ObjectID, &cbObjectID) != ERROR_SUCCESS)
                return TRUE;

            // Set the object ID to the UNICODE_STRING
            FileName.MaximumLength = 
            FileName.Length = (USHORT)cbObjectID;
            FileName.Buffer = (PWSTR)ObjectID;
        }

        ZeroMemory(&IoStatus, sizeof(IO_STATUS_BLOCK));
        InitializeObjectAttributes(&ObjAttr, &FileName, pData->dwObjAttrFlags, pData->hDirectory, NULL);
        AllocationSize.QuadPart = (LONGLONG)pData->AllocationSize;
           
        // Invoke breakpoint if the user wants to
        if(IsDlgButtonChecked(hDlg, IDC_BREAKPOINT) == BST_CHECKED)
            DebugBreak();

        Status = NtCreateFile(&pData->hFile,
                               pData->dwDesiredAccess,
                              &ObjAttr,
                              &IoStatus,
                              &AllocationSize,
                               pData->dwFileAttributes,
                               pData->dwShareAccess,
                               pData->dwCreateDisposition2,
                               pData->dwCreateOptions,
                               pData->pFileEa,
                               pData->dwEaSize);
        SetResultInfo(hDlg, Status, pData->hFile, IoStatus.Information);

        // If this operation failed, we close the directory as well
        if(!NT_SUCCESS(Status) && pData->hDirectory != NULL)
        {
            NtClose(pData->hDirectory);
            pData->hDirectory = NULL;
        }
    }

    if(pData->bUseTransaction && pfnRtlSetCurrentTransaction != NULL)
    {
        pfnRtlSetCurrentTransaction(SaveTransactionHandle);
        SaveTransactionHandle = NULL;
    }

    return TRUE;
}

static int OnNtCloseClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    NTSTATUS Status = STATUS_SUCCESS;

    // Invoke breakpoint if the user wants to
    if(IsDlgButtonChecked(hDlg, IDC_BREAKPOINT) == BST_CHECKED)
        DebugBreak();

    // Close file handle first
    if(IsHandleValid(pData->hFile))
        Status = NtClose(pData->hFile);
    pData->hFile = NULL;
    
    // Close directory handle last
    if(IsHandleValid(pData->hDirectory))
        NtClose(pData->hDirectory);
    pData->hDirectory = NULL;

    SetResultInfo(hDlg, Status, NULL, 0xFFFFFFFF);
    return TRUE;
}

static int OnDeltaPos(HWND hDlg, NMUPDOWN * pNMUpDown)
{
    LONGLONG AllocationSize;

    DlgText2Hex64(hDlg, IDC_ALLOCATION_SIZE, &AllocationSize);
    AllocationSize -= pNMUpDown->iDelta * 0x100;
    if(AllocationSize < 0)
        AllocationSize = 0;
    Hex2DlgText64(hDlg, IDC_ALLOCATION_SIZE, AllocationSize);
    return TRUE;
}

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    if(nNotify == BN_CLICKED)
    {
        switch(nIDCtrl)
        {
            case IDC_RELATIVE_FILE_HELP:
                return OnRelativeFileHelp(hDlg);

            case IDC_DIRECTORY_NAME_BROWSE:
                return OnBrowseDirClick(hDlg);

            case IDC_FILE_NAME_BROWSE:
                return OnBrowseFileClick(hDlg);

            case IDC_OBJ_ATTR_FLAGS_BROWSE:
                return OnObjAtributesFlags(hDlg);

            case IDC_DESIRED_ACCESS_BROWSE:
                return OnDesiredAccessClick(hDlg);

            case IDC_FILE_ATTRIBUTES_BROWSE:
                return OnFileAttributesClick(hDlg);
        
            case IDC_SHARE_ACCESS_BROWSE:
                return OnShareAccessClick(hDlg);

            case IDC_CREATE_OPTIONS_BROWSE:
                return OnCreateOptionsClick(hDlg);

            case IDC_EXTENDED_ATTRIBUTES_EDIT:
                return OnEditEaClick(hDlg);

            case IDC_VIRTUALIZATION:
                return OnVirtualization(hDlg);

            case IDC_PRIVILEGES:
                PrivilegesDialog(hDlg);
                return TRUE;

            case IDC_MAKE_DIRECTORY:
                return OnMakeDirectoryClick(hDlg);

            case IDC_RDWR_ASYNC:
                return QuickAccessSelection(hDlg, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, false);

            case IDC_RDWR_SYNC:
                return QuickAccessSelection(hDlg, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, true);

            case IDC_READ_ASYNC:
                return QuickAccessSelection(hDlg, GENERIC_READ, FILE_SHARE_READ, false);

            case IDC_READ_SYNC:
                return QuickAccessSelection(hDlg, GENERIC_READ, FILE_SHARE_READ, true);

            case IDC_QUERY_INFO_ASYNC:
                return QuickAccessSelection(hDlg, FILE_READ_ATTRIBUTES, 0, false);

            case IDC_QUERY_INFO_SYNC:
                return QuickAccessSelection(hDlg, FILE_READ_ATTRIBUTES, 0, true);

            case IDC_DELETE_ON_CLOSE:
                return QuickAccessSelection(hDlg, DELETE, 0, false);

            case IDC_CREATE_FILE:
                return OnCreateFileClick(hDlg);

            case IDC_CLOSE_HANDLE:
                return OnNtCloseClick(hDlg);
        }
    }

    // Convert the directory/file name to the NT name, if needed
    // Removed: Keep it as it is. We want to test NtCreateFile
    // with whatever the user entered.
//  if(nNotify == EN_KILLFOCUS)
//  {
//      if(nIDCtrl == IDC_DIRECTORY_NAME)
//          ConvertToNtName(hDlg, nIDCtrl);
//      if(nIDCtrl == IDC_FILE_NAME && GetWindowTextLength(GetDlgItem(hDlg, IDC_DIRECTORY_NAME)) == 0)
//          ConvertToNtName(hDlg, nIDCtrl);
//      return TRUE;
//  }

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

INT_PTR CALLBACK PageProc02(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // Call tooltip to handle messages
    g_Tooltip.HandleMessages(hDlg, uMsg, wParam, lParam, NULL);

    // Handle other messages
    switch(uMsg)
    {
        case WM_INITDIALOG:
            return OnInitDialog(hDlg, lParam);

        case WM_SIZE:
            if(pAnchors != NULL)
                pAnchors->OnSize();
            return FALSE;

        case WM_DRAWITEM:
            if(wParam == IDC_RELATIVE_FILE_HELP)
                DrawURLButton(hDlg, (LPDRAWITEMSTRUCT)lParam, FALSE);
            return TRUE;

        case WM_CONTEXTMENU:
            return ExecuteContextMenu(hDlg, IDR_QUICK_ACCESS_SELECTION, lParam);

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
