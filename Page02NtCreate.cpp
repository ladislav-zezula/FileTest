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

//-----------------------------------------------------------------------------
// Flags

TFlagInfo AccessMaskValues[] =
{
    {{"FILE_READ_DATA/FILE_LIST_DIRECTORY"},     FILE_READ_DATA,        FILE_READ_DATA},
    {{"FILE_WRITE_DATA/FILE_ADD_FILE"},          FILE_WRITE_DATA,       FILE_WRITE_DATA},
    {{"FILE_APPEND_DATA/FILE_ADD_SUBDIRECTORY"}, FILE_APPEND_DATA,      FILE_APPEND_DATA},
    {{"FILE_READ_EA"},                           FILE_READ_EA,          FILE_READ_EA},
    {{"FILE_WRITE_EA"},                          FILE_WRITE_EA,         FILE_WRITE_EA},
    {{"FILE_EXECUTE/FILE_TRAVERSE"},             FILE_EXECUTE,          FILE_EXECUTE},
    {{"FILE_DELETE_CHILD"},                      FILE_DELETE_CHILD,     FILE_DELETE_CHILD},
    {{"FILE_READ_ATTRIBUTES"},                   FILE_READ_ATTRIBUTES,  FILE_READ_ATTRIBUTES},
    {{"FILE_WRITE_ATTRIBUTES"},                  FILE_WRITE_ATTRIBUTES, FILE_WRITE_ATTRIBUTES},

    FLAGINFO_BITV(DELETE),
    FLAGINFO_BITV(READ_CONTROL),
    FLAGINFO_BITV(WRITE_DAC),
    FLAGINFO_BITV(WRITE_OWNER),
    FLAGINFO_BITV(SYNCHRONIZE),
    FLAGINFO_BITV(ACCESS_SYSTEM_SECURITY),
    FLAGINFO_BITV(GENERIC_READ),
    FLAGINFO_BITV(GENERIC_WRITE),
    FLAGINFO_BITV(GENERIC_EXECUTE),
    FLAGINFO_BITV(GENERIC_ALL),
    FLAGINFO_BITV(MAXIMUM_ALLOWED),
    FLAGINFO_END()
};

// Also necessary in Page04FileOps.cpp
TFlagInfo FileAttributesValues[] =
{
    FLAGINFO_BITV(FILE_ATTRIBUTE_READONLY),
    FLAGINFO_BITV(FILE_ATTRIBUTE_HIDDEN),
    FLAGINFO_BITV(FILE_ATTRIBUTE_SYSTEM),
    FLAGINFO_BITV(OLD_DOS_VOLID),
    FLAGINFO_BITV(FILE_ATTRIBUTE_DIRECTORY),
    FLAGINFO_BITV(FILE_ATTRIBUTE_ARCHIVE),
    FLAGINFO_BITV(FILE_ATTRIBUTE_DEVICE),
    FLAGINFO_BITV(FILE_ATTRIBUTE_NORMAL),
    FLAGINFO_BITV(FILE_ATTRIBUTE_TEMPORARY),
    FLAGINFO_BITV(FILE_ATTRIBUTE_SPARSE_FILE),
    FLAGINFO_BITV(FILE_ATTRIBUTE_REPARSE_POINT),
    FLAGINFO_BITV(FILE_ATTRIBUTE_COMPRESSED),
    FLAGINFO_BITV(FILE_ATTRIBUTE_OFFLINE),
    FLAGINFO_BITV(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED),
    FLAGINFO_BITV(FILE_ATTRIBUTE_ENCRYPTED),
    FLAGINFO_BITV(FILE_ATTRIBUTE_INTEGRITY_STREAM),
    FLAGINFO_BITV(FILE_ATTRIBUTE_VIRTUAL),
    FLAGINFO_BITV(FILE_ATTRIBUTE_NO_SCRUB_DATA),
    FLAGINFO_BITV(FILE_ATTRIBUTE_RECALL_ON_OPEN),
    FLAGINFO_BITV(FILE_ATTRIBUTE_PINNED),
    FLAGINFO_BITV(FILE_ATTRIBUTE_UNPINNED),
    FLAGINFO_BITV(FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS),
    FLAGINFO_BITV(FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL),
    FLAGINFO_END()
};

TFlagInfo CreateOptionsValues[] =
{
    FLAGINFO_BITV(FILE_DIRECTORY_FILE),
    FLAGINFO_BITV(FILE_WRITE_THROUGH),
    FLAGINFO_BITV(FILE_SEQUENTIAL_ONLY),
    FLAGINFO_BITV(FILE_NO_INTERMEDIATE_BUFFERING),
    FLAGINFO_BITV(FILE_SYNCHRONOUS_IO_ALERT),
    FLAGINFO_BITV(FILE_SYNCHRONOUS_IO_NONALERT),
    FLAGINFO_BITV(FILE_NON_DIRECTORY_FILE),
    FLAGINFO_BITV(FILE_CREATE_TREE_CONNECTION),
    FLAGINFO_BITV(FILE_COMPLETE_IF_OPLOCKED),
    FLAGINFO_BITV(FILE_NO_EA_KNOWLEDGE),
    FLAGINFO_BITV(FILE_OPEN_FOR_RECOVERY),
    FLAGINFO_BITV(FILE_RANDOM_ACCESS),
    FLAGINFO_BITV(FILE_DELETE_ON_CLOSE),
    FLAGINFO_BITV(FILE_OPEN_BY_FILE_ID),
    FLAGINFO_BITV(FILE_OPEN_FOR_BACKUP_INTENT),
    FLAGINFO_BITV(FILE_NO_COMPRESSION),
    FLAGINFO_BITV(FILE_OPEN_REQUIRING_OPLOCK),
    FLAGINFO_BITV(FILE_DISALLOW_EXCLUSIVE),
    FLAGINFO_BITV(FILE_SESSION_AWARE),
    FLAGINFO_BITV(FILE_RESERVE_OPFILTER),
    FLAGINFO_BITV(FILE_OPEN_REPARSE_POINT),
    FLAGINFO_BITV(FILE_OPEN_NO_RECALL),
    FLAGINFO_BITV(FILE_OPEN_FOR_FREE_SPACE_QUERY),
    FLAGINFO_END()
};

static TFlagInfo ObjAttrFlagsValues[] =
{
    FLAGINFO_BITV(OBJ_PROTECT_CLOSE),
    FLAGINFO_BITV(OBJ_INHERIT),
    FLAGINFO_BITV(OBJ_AUDIT_OBJECT_CLOSE),
    FLAGINFO_BITV(OBJ_NO_RIGHTS_UPGRADE),
    FLAGINFO_BITV(OBJ_PERMANENT),
    FLAGINFO_BITV(OBJ_EXCLUSIVE),
    FLAGINFO_BITV(OBJ_CASE_INSENSITIVE),    
    FLAGINFO_BITV(OBJ_OPENIF),
    FLAGINFO_BITV(OBJ_OPENLINK),
    FLAGINFO_BITV(OBJ_KERNEL_HANDLE),
    FLAGINFO_BITV(OBJ_FORCE_ACCESS_CHECK),
    FLAGINFO_BITV(OBJ_IGNORE_IMPERSONATED_DEVICEMAP),
    FLAGINFO_BITV(OBJ_DONT_REPARSE),
    FLAGINFO_BITV(OBJ_KERNEL_EXCLUSIVE),
    FLAGINFO_END()
};

//-----------------------------------------------------------------------------
// Local functions

static bool ShallEditRelativeFile()
{
    return (GetAsyncKeyState(VK_SHIFT) < 0);
}

static TFileTestData * IsPropSheetPageDialog(HWND hDlg)
{
    TFileTestData * pData;

    if((pData = GetDialogData(hDlg)) != NULL)
    {
        return (pData->pOP == &pData->OpenFile) ? pData : NULL;
    }
    return NULL;
}

static TAnchors * GetDialogAnchors(HWND hDlg)
{
    TFileTestData * pData;

    if((pData = GetDialogData(hDlg)) != NULL)
    {
        return pData->pAnchors;
    }
    return NULL;
}

static void SetDialogAnchors(HWND hDlg, TAnchors * pAnchors)
{
    TFileTestData * pData;

    if((pData = GetDialogData(hDlg)) != NULL)
    {
        // Free old anchors, if any
        if(pData->pAnchors != NULL)
            delete pData->pAnchors;
        pData->pAnchors = pAnchors;
    }
}

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
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
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

static void EAttr2DlgText(HWND hDlg, UINT nIDCtrl, TOpenPacket * pOP)
{
    TCHAR szEaInfo[128];

    // Update the info about extended attributes
    rsprintf(szEaInfo, _countof(szEaInfo), IDS_EA_INFO, pOP->pvFileEa, pOP->cbFileEa);
    SetDlgItemText(hDlg, nIDCtrl, szEaInfo);
}

static BOOL UpdateRelativeFileHint(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    HWND hWndChild;
    UINT nID;

    // Does the "relative file" edit field exist?
    if((hWndChild = GetDlgItem(hDlg, IDC_DIRECTORY_NAME)) != NULL)
    {
        // Is there no text?
        if(GetWindowTextLength(hWndChild) == 0)
        {
            nID = (pData->UseRelativeFile) ? IDS_EMPTY_RELATIVE_FILE_NAME : IDS_NO_RELATIVE_FILE;
            SetEditCueBanner(hWndChild, nID);
        }
    }
    return TRUE;
}

static BOOL UpdateUseRelativeFile(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    HWND hWndChild;

    if((hWndChild = GetDlgItem(hDlg, IDC_USE_RELATIVE_FILE)) != NULL)
        pData->UseRelativeFile = (Button_GetCheck(hWndChild) == BST_CHECKED);
    return UpdateRelativeFileHint(hDlg);
}

static void LoadDialog(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    TOpenPacket * pOP = pData->pOP;
    HWND hWndChild = GetDlgItem(hDlg, IDC_CREATE_DISPOSITION);

    // Load the file names into the dialog edit fields
    SetDlgItemText(hDlg, IDC_DIRECTORY_NAME, pData->szDirName);
    SetDlgItemText(hDlg, IDC_FILE_NAME, pData->szFileName1);

    // Convert both to NT name.
    if(pData->szDirName[0] == 0)
        ConvertToNtName(hDlg, IDC_FILE_NAME);
    ConvertToNtName(hDlg, IDC_DIRECTORY_NAME);

    // Set the create disposition
    if(hWndChild != NULL)
        ComboBox_SetCurSel(hWndChild, pOP->dwCreateDisposition2);

    // Init the various flags from the open packet
    Hex2DlgText32(hDlg, IDC_OBJ_ATTR_FLAGS, pOP->dwOA_Attributes);
    Hex2DlgText32(hDlg, IDC_DESIRED_ACCESS, pOP->dwDesiredAccess);
    Hex2DlgText64(hDlg, IDC_ALLOCATION_SIZE, pOP->AllocationSize.QuadPart);
    Hex2DlgText32(hDlg, IDC_FILE_ATTRIBUTES, pOP->dwFlagsAndAttributes);
    Hex2DlgText32(hDlg, IDC_SHARE_ACCESS, pOP->dwShareAccess);
    Hex2DlgText32(hDlg, IDC_CREATE_OPTIONS, pOP->dwCreateOptions);
    EAttr2DlgText(hDlg, IDC_EXTENDED_ATTRIBUTES, pOP);

    // (Un)check the "use relative file" button
    if((hWndChild = GetDlgItem(hDlg, IDC_USE_RELATIVE_FILE)) != NULL)
        Button_SetCheck(hWndChild, pData->UseRelativeFile ? BST_CHECKED : BST_UNCHECKED);
    UpdateUseRelativeFile(hDlg);
}

static DWORD SaveDialog(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    TOpenPacket * pOP = pData->pOP;
    HWND hWndChild;
    DWORD dwErrCode;

    // Save both file names to the TFileTestData
    GetDlgItemText(hDlg, IDC_DIRECTORY_NAME, pData->szDirName, MAX_NT_PATH);
    GetDlgItemText(hDlg, IDC_FILE_NAME, pData->szFileName1, MAX_NT_PATH);
    assert(pOP == &pData->OpenFile || pOP == &pData->RelaFile);

    if((dwErrCode = DlgText2Hex32(hDlg, IDC_OBJ_ATTR_FLAGS,  &pOP->dwOA_Attributes)) != ERROR_SUCCESS)
        return dwErrCode;
    if((dwErrCode = DlgText2Hex32(hDlg, IDC_DESIRED_ACCESS,  &pOP->dwDesiredAccess)) != ERROR_SUCCESS)
        return dwErrCode;
    if((dwErrCode = DlgText2Hex32(hDlg, IDC_FILE_ATTRIBUTES, &pOP->dwFlagsAndAttributes)) != ERROR_SUCCESS)
        return dwErrCode;
    if((dwErrCode = DlgText2Hex32(hDlg, IDC_SHARE_ACCESS,    &pOP->dwShareAccess)) != ERROR_SUCCESS)
        return dwErrCode;
    if((dwErrCode = DlgText2Hex32(hDlg, IDC_CREATE_OPTIONS,  &pOP->dwCreateOptions)) != ERROR_SUCCESS)
        return dwErrCode;
    if((dwErrCode = DlgText2Hex64(hDlg, IDC_ALLOCATION_SIZE, &pOP->AllocationSize.QuadPart)) != ERROR_SUCCESS)
        return dwErrCode;

    if((hWndChild = GetDlgItem(hDlg, IDC_CREATE_DISPOSITION)) != NULL)
        pOP->dwCreateDisposition2 = ComboBox_GetCurSel(hWndChild);
    if((hWndChild = GetDlgItem(hDlg, IDC_TRANSACTED)) != NULL)
        pData->bUseTransaction = (Button_GetCheck(hWndChild) == BST_CHECKED);
    UpdateUseRelativeFile(hDlg);
    return ERROR_SUCCESS;
}
                                                             
//-----------------------------------------------------------------------------
// Message handlers

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    PROPSHEETPAGE * pPage = (PROPSHEETPAGE *)lParam;
    TFileTestData * pData = (TFileTestData *)pPage->lParam;
    TAnchors * pAnchors;

    // Save the data pointer to the dialog
    assert(pData->MagicHeader == FILETEST_DATA_MAGIC);
    SetDialogData(hDlg, pPage->lParam);

    // Initialize the combo box
    InitDialogControls(hDlg, MAKEINTRESOURCE(IDD_PAGE02_NTCREATE));

    // Initialize the "Relative File" hyperlink
    InitURLButton(hDlg, IDC_RELATIVE_FILE, FALSE);

    // Configure dialog resizing
    if(pData->bEnableResizing)
    {
        if((pAnchors = new TAnchors()) != NULL)
        {
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
            pAnchors->AddAnchor(hDlg, IDC_USE_RELATIVE_FILE, akLeft | akTop | akRight);
            pAnchors->AddAnchor(hDlg, IDC_TRANSACTED, akLeft | akRight | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_VIRTUALIZATION, akLeft | akRight | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_BREAKPOINT, akLeft | akRight | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_PRIVILEGES, akLeft | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_MAKE_DIRECTORY, akLeft | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_CREATE_FILE, akRight | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_CLOSE_HANDLE, akRight | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_RESULT_FRAME, akLeft | akRight | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE_TITLE, akLeft | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE, akLeft | akRight | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_HANDLE_TITLE, akLeft | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_HANDLE, akLeft | akRight | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_INFORMATION_TITLE, akLeft | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_INFORMATION, akLeft | akRight | akBottom);
            pAnchors->AddAnchor(hDlg, IDOK, akRightBottom);
            pAnchors->AddAnchor(hDlg, IDCANCEL, akRightBottom);
            assert(pData->pAnchors == NULL);
            SetDialogAnchors(hDlg, pAnchors);
        }
    }

    // If we have a tooltip window, init tooltips 
    if(IsPropSheetPageDialog(hDlg))
    {
        g_Tooltip.AddToolTip(hDlg, IDC_OBJ_ATTR_FLAGS, ObjAttrFlagsValues);
        g_Tooltip.AddToolTip(hDlg, IDC_DESIRED_ACCESS, AccessMaskValues);
        g_Tooltip.AddToolTip(hDlg, IDC_FILE_ATTRIBUTES, FileAttributesValues);
        g_Tooltip.AddToolTip(hDlg, IDC_SHARE_ACCESS, ShareAccessValues);
        g_Tooltip.AddToolTip(hDlg, IDC_CREATE_OPTIONS, CreateOptionsValues);
    }
    else
    {
        // If this is not the propsheet, we need to explicitly call the OnSetActive
        LoadDialog(hDlg);
    }

    // On post-Vista, enable the virtualization button
    if(GetTokenVirtualizationEnabled(NULL))
        EnableDlgItems(hDlg, TRUE, IDC_VIRTUALIZATION, 0);
    return TRUE;
}

static BOOL OnSize(HWND hDlg)
{
    TAnchors * pAnchors;

    if((pAnchors = GetDialogAnchors(hDlg)) != NULL)
        pAnchors->OnSize();
    return TRUE;
}

static BOOL OnGetMinMaxInfo(HWND hDlg, LPARAM lParam)
{
    TAnchors * pAnchors;

    if((pAnchors = GetDialogAnchors(hDlg)) != NULL)
        pAnchors->OnGetMinMaxInfo(lParam);
    return TRUE;
}

static int OnSetActive(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    BOOL bEnabled;
    int nChecked;

    // Load the directory controls from TFileTestData structure
    LoadDialog(hDlg);

    // Enable/disable transaction
    bEnabled = (pfnRtlSetCurrentTransaction != NULL && IsHandleValid(pData->hTransaction));
    EnableDlgItems(hDlg, bEnabled, IDC_TRANSACTED, 0);
    nChecked = (bEnabled && pData->bUseTransaction) ? BST_CHECKED : BST_UNCHECKED;
    CheckDlgButton(hDlg, IDC_TRANSACTED, nChecked);

    // Check/uncheck virtualization
    nChecked = (GetTokenVirtualizationEnabled(&bEnabled) && bEnabled) ? BST_CHECKED : BST_UNCHECKED;
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

static int OnRelativeFileClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    PROPSHEETPAGE Page = {0};
    TOpenPacket * pSaveOP = pData->pOP;
    TAnchors * pSaveAnchors = pData->pAnchors;

    // Only invoke the sub-dialog if it's not invoked already
    if(IsPropSheetPageDialog(hDlg))
    {
        // Switch to the relative file open packet
        GetDlgItemText(hDlg, IDC_DIRECTORY_NAME, pData->szDirName, MAX_NT_PATH);
        pData->pAnchors = NULL;
        pData->pOP = &pData->RelaFile;
        pData->UseRelativeFile = TRUE;

        // Execute the dialog box. The InitDialog dialog expects pointer to PROPSHEETPAGE as LPARAM
        Page.lParam = (LPARAM)(pData);
        DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_PAGE02_NTCREATE_RELFILE), hDlg, PageProc02, (LPARAM)(&Page));

        // Restore the original open packet
        pData->pAnchors = pSaveAnchors;
        pData->pOP = pSaveOP;
        SetDlgItemText(hDlg, IDC_DIRECTORY_NAME, pData->szDirName);
        UpdateRelativeFileHint(hDlg);
    }
    return TRUE;
}

static int OnBrowseDirClick(HWND hDlg)
{
    BrowseForDirectory(hDlg, MAKEINTRESOURCE(IDC_DIRECTORY_NAME), IDS_SELECT_DIRECTORY, MAX_PATH);
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

static BOOL OnEditRelativeOrMainFileFlags(
    HWND hDlg,                  // Owner dialog
    UINT nIDTitle1,             // Dialog title for relative file flags
    UINT nIDTitle2,             // Dialog title for main file flags
    TFlagInfo * pFlagsInfos,    // List of flags
    ULONG & RefFlags,           // Value of the flags (in/out)
    UINT nIDCtrl)               // ID of the dialog control to modify
{
    // Is this the main property sheet dialog?
    if(IsPropSheetPageDialog(hDlg))
    {
        // Take Shift key into account
        if(GetAsyncKeyState(VK_SHIFT) < 0)
            FlagsDialog(hDlg, nIDTitle1, pFlagsInfos, RefFlags);
        else
            FlagsDialog_OnControl(hDlg, nIDTitle2, pFlagsInfos, nIDCtrl);
    }
    else
    {
        FlagsDialog_OnControl(hDlg, nIDTitle1, pFlagsInfos, nIDCtrl);
    }
    return TRUE;
}

static BOOL OnObjAtributesFlags(HWND hDlg)
{
    return OnEditRelativeOrMainFileFlags(hDlg,
                                         IDS_OBJECT_ATTRIBUTES_FLAGS_RF,
                                         IDS_OBJECT_ATTRIBUTES_FLAGS,
                                         ObjAttrFlagsValues,
                                         GetDialogData(hDlg)->RelaFile.dwOA_Attributes,
                                         IDC_OBJ_ATTR_FLAGS);
}

static int OnDesiredAccessClick(HWND hDlg)
{
    return OnEditRelativeOrMainFileFlags(hDlg,
                                         IDS_DESIRED_ACCESS_RF,
                                         IDS_DESIRED_ACCESS,
                                         AccessMaskValues,
                                         GetDialogData(hDlg)->RelaFile.dwDesiredAccess,
                                         IDC_DESIRED_ACCESS);
}

static int OnFileAttributesClick(HWND hDlg)
{
    return OnEditRelativeOrMainFileFlags(hDlg,
                                         IDS_FILE_ATTRIBUTES_RF,
                                         IDS_FILE_ATTRIBUTES,
                                         FileAttributesValues,
                                         GetDialogData(hDlg)->RelaFile.dwFlagsAndAttributes,
                                         IDC_FILE_ATTRIBUTES);
}

static int OnShareAccessClick(HWND hDlg)
{
    return OnEditRelativeOrMainFileFlags(hDlg,
                                         IDS_SHARE_ACCESS_RF,
                                         IDS_SHARE_ACCESS,
                                         ShareAccessValues,
                                         GetDialogData(hDlg)->RelaFile.dwShareAccess,
                                         IDC_SHARE_ACCESS);
}

static int OnCreateOptionsClick(HWND hDlg)
{
    return OnEditRelativeOrMainFileFlags(hDlg,
                                         IDS_CREATE_OPTIONS_RF,
                                         IDS_CREATE_OPTIONS,
                                         CreateOptionsValues,
                                         GetDialogData(hDlg)->RelaFile.dwCreateOptions,
                                         IDC_CREATE_OPTIONS);
}

static int OnEditEaClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    TOpenPacket * pOP = pData->pOP;

    // Always take relative file on property sheet, if Shift is pressed
    if(IsPropSheetPageDialog(hDlg) && ShallEditRelativeFile())
        pOP = &pData->RelaFile;

    // Invoke the editor of the extended attributes
    if(ExtendedAtributesEditorDialog(hDlg, pOP) == IDOK)
        EAttr2DlgText(hDlg, IDC_EXTENDED_ATTRIBUTES, pOP);
    return TRUE;
}

static int OnVirtualization(HWND hDlg)
{
    BOOL bEnabled = (IsDlgButtonChecked(hDlg, IDC_VIRTUALIZATION) == BST_CHECKED) ? TRUE : FALSE;

    SetTokenVirtualizationEnabled(bEnabled);
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

    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_NTCREATE, Status, &IoStatus);
    return TRUE;
}

static int OnNtCreateFileClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus = {0};
    UNICODE_STRING FileName;
    UNICODE_STRING DirName;
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE SaveTransactionHandle = NULL;
    TCHAR szRelativeFile[MAX_NT_PATH];
    TCHAR szFileName[MAX_NT_PATH];
    DWORD cbObjectID = 0;
    BYTE ObjectID[0x10];

    // Close the handle, if already open
    if(IsHandleValid(pData->hDirectory) || IsHandleValid(pData->hFile))
        SendMessage(hDlg, WM_COMMAND, MAKEWPARAM(IDC_CLOSE_HANDLE, BN_CLICKED), 0);

    // Get the various create options
    if(SaveDialog(hDlg) != ERROR_SUCCESS)
        return FALSE;

    if(pData->bUseTransaction && pfnRtlSetCurrentTransaction != NULL)
    {
        SaveTransactionHandle = pfnRtlGetCurrentTransaction();
        pfnRtlSetCurrentTransaction(pData->hTransaction);
    }

    // Get the directory name from the dialog data
    StringCchCopy(szRelativeFile, _countof(szRelativeFile), pData->szDirName);
    StringCchCopy(szFileName, _countof(szFileName), pData->szFileName1);

    // If we are about to open a file by ID, and we have no relative directory,
    // try to take the directory from the file name
    if((szRelativeFile[0] == 0) && (pData->OpenFile.dwCreateOptions & FILE_OPEN_BY_FILE_ID))
    {
        LPTSTR szFullName = pData->szFileName1;
        LPTSTR szFileId = _tcsrchr(szFullName, _T('\\'));
        size_t nLength = szFileId - szFullName + 1;

        if(szFileId != NULL)
        {
            StringCchCopy(szRelativeFile, nLength, szFullName);
            StringCchCopy(szFileName, _countof(szFileName), szFileId + 1);
        }
    }

    // Open the relative file (if any)
    if(szRelativeFile[0] || pData->UseRelativeFile)
    {
        InitializeObjectAttributes(&ObjAttr, &DirName, pData->RelaFile.dwOA_Attributes, 0, NULL);
        RtlInitUnicodeString(&DirName, szRelativeFile);
        Status = NtCreateFile(&pData->hDirectory,
                               pData->RelaFile.dwDesiredAccess,
                              &ObjAttr,
                              &IoStatus,
                              &pData->RelaFile.AllocationSize,
                               pData->RelaFile.dwFlagsAndAttributes,
                               pData->RelaFile.dwShareAccess,
                               pData->RelaFile.dwCreateDisposition2,
                               pData->RelaFile.dwCreateOptions,
                               pData->RelaFile.pvFileEa,
                               pData->RelaFile.cbFileEa);
        if(!NT_SUCCESS(Status))
        {
            SetResultInfo(hDlg, RSI_NTSTATUS | RSI_HANDLE, Status, pData->hDirectory);
            return TRUE;
        }
    }

    // Prepare the file open
    if(NT_SUCCESS(Status))
    {
        RtlInitUnicodeString(&FileName, szFileName);

        // If open by ID required, set the ID to the string
        if(pData->OpenFile.dwCreateOptions & FILE_OPEN_BY_FILE_ID)
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
        InitializeObjectAttributes(&ObjAttr, &FileName, pData->OpenFile.dwOA_Attributes, pData->hDirectory, NULL);
           
        // Invoke breakpoint if the user wants to
        if(IsDlgButtonChecked(hDlg, IDC_BREAKPOINT) == BST_CHECKED)
        {
            __debugbreak();
        }

        Status = NtCreateFile(&pData->hFile,
                               pData->OpenFile.dwDesiredAccess,
                              &ObjAttr,
                              &IoStatus,
                              &pData->OpenFile.AllocationSize,
                               pData->OpenFile.dwFlagsAndAttributes,
                               pData->OpenFile.dwShareAccess,
                               pData->OpenFile.dwCreateDisposition2,
                               pData->OpenFile.dwCreateOptions,
                               pData->OpenFile.pvFileEa,
                               pData->OpenFile.cbFileEa);
        SetResultInfo(hDlg, RSI_NTSTATUS | RSI_HANDLE | RSI_NTCREATE, Status, pData->hFile, &IoStatus);

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
    {
        __debugbreak();
    }

    // Close file handle first
    if(IsHandleValid(pData->hFile))
        Status = NtClose(pData->hFile);
    pData->hFile = NULL;
    
    // Close directory handle last
    if(IsHandleValid(pData->hDirectory))
        NtClose(pData->hDirectory);
    pData->hDirectory = NULL;

    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_HANDLE, Status, pData->hFile);
    return TRUE;
}

static BOOL OnEndDialogButtonClick(HWND hDlg, UINT nIDCtrl)
{
    // Is this a modal dialog?
    if(!IsPropSheetPageDialog(hDlg))
    {
        if(nIDCtrl == IDOK)
            SaveDialog(hDlg);
        EndDialog(hDlg, nIDCtrl);
    }
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
            case IDC_RELATIVE_FILE:
                return OnRelativeFileClick(hDlg);

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
                return OnNtCreateFileClick(hDlg);

            case IDC_CLOSE_HANDLE:
                return OnNtCloseClick(hDlg);

            case IDC_USE_RELATIVE_FILE:
                return UpdateUseRelativeFile(hDlg);

            case IDOK:
            case IDCANCEL:
                return OnEndDialogButtonClick(hDlg, nIDCtrl);
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
            return OnSize(hDlg);

        case WM_GETMINMAXINFO:
            return OnGetMinMaxInfo(hDlg, lParam);

        case WM_DRAWITEM:
            if(wParam == IDC_RELATIVE_FILE)
                DrawURLButton(hDlg, (LPDRAWITEMSTRUCT)lParam);
            return TRUE;

        case WM_CONTEXTMENU:
            return ExecuteContextMenu(hDlg, FindContextMenu(IDR_NTCREATE_MENU), lParam);

        case WM_COMMAND:
            return OnCommand(hDlg, HIWORD(wParam), LOWORD(wParam));

        case WM_NOTIFY:
            return OnNotify(hDlg, (NMHDR *)lParam);

        case WM_DESTROY:
            SetDialogAnchors(hDlg, NULL);
            return FALSE;
    }
    return FALSE;
}

#ifdef _DEBUG
void DebugCode_TEST()
{
    //DWORD dwBitMask = 0x80030080;

    //FlagsDialog(NULL,
    //            IDS_FLAGS_AND_ATTRIBUTES,
    //            FileAttributesValues,
    //            dwBitMask);
    //ExitProcess(3);
}
#endif
