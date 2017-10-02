/*****************************************************************************/
/* Page01Create.cpp                       Copyright (c) Ladislav Zezula 2004 */
/*---------------------------------------------------------------------------*/
/* Description:                                                              */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 06.03.04  1.00  Lad  The first version of Page01Create.cpp                */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Flags

static TFlagInfo DesiredAccessValues[] =
{
    {{_T("FILE_READ_DATA/FILE_LIST_DIRECTORY")},     FILE_READ_DATA,        FILE_READ_DATA},
    {{_T("FILE_WRITE_DATA/FILE_ADD_FILE")},          FILE_WRITE_DATA,       FILE_WRITE_DATA},
    {{_T("FILE_APPEND_DATA/FILE_ADD_SUBDIRECTORY")}, FILE_APPEND_DATA,      FILE_APPEND_DATA},
    {{_T("FILE_READ_EA")},                           FILE_READ_EA,          FILE_READ_EA},
    {{_T("FILE_WRITE_EA")},                          FILE_WRITE_EA,         FILE_WRITE_EA},
    {{_T("FILE_EXECUTE/FILE_TRAVERSE")},             FILE_EXECUTE,          FILE_EXECUTE},
    {{_T("FILE_DELETE_CHILD")},                      FILE_DELETE_CHILD,     FILE_DELETE_CHILD},
    {{_T("FILE_READ_ATTRIBUTES")},                   FILE_READ_ATTRIBUTES,  FILE_READ_ATTRIBUTES},
    {{_T("FILE_WRITE_ATTRIBUTES")},                  FILE_WRITE_ATTRIBUTES, FILE_WRITE_ATTRIBUTES},

    FLAG_INFO_ENTRY(DELETE),
    FLAG_INFO_ENTRY(READ_CONTROL),
    FLAG_INFO_ENTRY(WRITE_DAC),
    FLAG_INFO_ENTRY(WRITE_OWNER),
    FLAG_INFO_ENTRY(SYNCHRONIZE),
    FLAG_INFO_ENTRY(ACCESS_SYSTEM_SECURITY),
    FLAG_INFO_ENTRY(GENERIC_READ),
    FLAG_INFO_ENTRY(GENERIC_WRITE),
    FLAG_INFO_ENTRY(GENERIC_EXECUTE),
    FLAG_INFO_ENTRY(GENERIC_ALL),
    FLAG_INFO_ENTRY(MAXIMUM_ALLOWED),
    FLAG_INFO_END
};

static TFlagInfo FileAttributesValues_CreateFile[] =
{
    FLAG_INFO_CTRLID(FILE_ATTRIBUTE_READONLY),                  // 0x00000001
    FLAG_INFO_CTRLID(FILE_ATTRIBUTE_HIDDEN),                    // 0x00000002
    FLAG_INFO_CTRLID(FILE_ATTRIBUTE_SYSTEM),                    // 0x00000004
    FLAG_INFO_CTRLID(OLD_DOS_VOLID),                            // 0x00000008
    FLAG_INFO_CTRLID(FILE_ATTRIBUTE_DIRECTORY),                 // 0x00000010
    FLAG_INFO_CTRLID(FILE_ATTRIBUTE_ARCHIVE),                   // 0x00000020
    FLAG_INFO_CTRLID(FILE_ATTRIBUTE_DEVICE),                    // 0x00000040
    FLAG_INFO_CTRLID(FILE_ATTRIBUTE_NORMAL),                    // 0x00000080
    FLAG_INFO_CTRLID(FILE_ATTRIBUTE_TEMPORARY),                 // 0x00000100
    FLAG_INFO_CTRLID(FILE_ATTRIBUTE_SPARSE_FILE),               // 0x00000200
    FLAG_INFO_CTRLID(FILE_ATTRIBUTE_REPARSE_POINT),             // 0x00000400
    FLAG_INFO_CTRLID(FILE_ATTRIBUTE_COMPRESSED),                // 0x00000800
    FLAG_INFO_CTRLID(FILE_ATTRIBUTE_OFFLINE),                   // 0x00001000
    FLAG_INFO_CTRLID(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED),       // 0x00002000
    FLAG_INFO_CTRLID(FILE_ATTRIBUTE_ENCRYPTED),                 // 0x00004000
    FLAG_INFO_CTRLID(FILE_ATTRIBUTE_INTEGRITY_STREAM),          // 0x00008000

    FLAG_INFO_CTRLID(SECURITY_SQOS_PRESENT),                    // 0x00100000
    FLAG_INFO_CTRLID(SECURITY_EFFECTIVE_ONLY),                  // 0x00080000
    FLAG_INFO_CTRLID(SECURITY_CONTEXT_TRACKING),                // 0x00040000
    FLAG_INFO_MASK(SECURITY_VALUE_MASK,SECURITY_ANONYMOUS),     // 0x00000000
    FLAG_INFO_MASK(SECURITY_VALUE_MASK,SECURITY_IDENTIFICATION),// 0x00010000
    FLAG_INFO_MASK(SECURITY_VALUE_MASK,SECURITY_IMPERSONATION), // 0x00020000
    FLAG_INFO_MASK(SECURITY_VALUE_MASK,SECURITY_DELEGATION),    // 0x00030000

    FLAG_INFO_CTRLID(FILE_FLAG_OPEN_REPARSE_POINT),             // 0x00200000
    FLAG_INFO_CTRLID(FILE_FLAG_POSIX_SEMANTICS),                // 0x01000000
    FLAG_INFO_CTRLID(FILE_FLAG_BACKUP_SEMANTICS),               // 0x02000000
    FLAG_INFO_CTRLID(FILE_FLAG_DELETE_ON_CLOSE),                // 0x04000000
    FLAG_INFO_CTRLID(FILE_FLAG_SEQUENTIAL_SCAN),                // 0x08000000
    FLAG_INFO_CTRLID(FILE_FLAG_RANDOM_ACCESS),                  // 0x10000000
    FLAG_INFO_CTRLID(FILE_FLAG_NO_BUFFERING),                   // 0x20000000
    FLAG_INFO_CTRLID(FILE_FLAG_OVERLAPPED),                     // 0x40000000
    FLAG_INFO_CTRLID(FILE_FLAG_WRITE_THROUGH),                  // 0x80000000
    FLAG_INFO_END
};

static TFlagInfo ShareAccessValues[] =
{
    FLAG_INFO_ENTRY(FILE_SHARE_READ),
    FLAG_INFO_ENTRY(FILE_SHARE_WRITE),
    FLAG_INFO_ENTRY(FILE_SHARE_DELETE),
    FLAG_INFO_END
};

//-----------------------------------------------------------------------------
// Helper functions

static int SaveDialog(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    HWND hCombo = GetDlgItem(hDlg, IDC_CREATE_DISPOSITION);
    int nError = ERROR_SUCCESS;

    GetDlgItemText(hDlg, IDC_DIRECTORY_NAME, pData->szDirName, _maxchars(pData->szDirName));
    GetDlgItemText(hDlg, IDC_FILE_NAME, pData->szFileName1, _maxchars(pData->szFileName1));
    GetDlgItemText(hDlg, IDC_TEMPLATE_FILE, pData->szTemplate, _maxchars(pData->szTemplate));

    if((nError = DlgText2Hex32(hDlg, IDC_DESIRED_ACCESS, &pData->dwDesiredAccess)) != ERROR_SUCCESS)
        return nError;
    if((nError = DlgText2Hex32(hDlg, IDC_SHARE_ACCESS, &pData->dwShareAccess)) != ERROR_SUCCESS)
        return nError;
    if((nError = DlgText2Hex32(hDlg, IDC_FILE_ATTRIBUTES, &pData->dwFileAttributes)) != ERROR_SUCCESS)
        return nError;

    pData->dwCreateDisposition1 = ComboBox_GetCurSel(hCombo) + 1;
    pData->bUseTransaction      = (IsDlgButtonChecked(hDlg, IDC_TRANSACTED) == BST_CHECKED);
    return ERROR_SUCCESS;
}

static int MyCreateDirectory(TFileTestData * pData, LPCTSTR szDirectory)
{
    int nError = ERROR_SUCCESS;

    if(pData->bUseTransaction)
    {
        // If the transacted version doesn't exist, do nothing
        if(pfnCreateDirectoryTransacted == NULL)
            return ERROR_NOT_SUPPORTED;

        if(!pfnCreateDirectoryTransacted(NULL, szDirectory, NULL, pData->hTransaction))
            nError = GetLastError();
    }
    else
    {
        if(!CreateDirectory(szDirectory, NULL))
            nError = GetLastError();
    }

    // If the directory already exists, take it as success
    if(nError == ERROR_ALREADY_EXISTS)
        nError = ERROR_SUCCESS;
    return nError;
}

//-----------------------------------------------------------------------------
// Message handlers

static TAnchors * pAnchors = NULL;

static int OnCloseHandleClick(HWND hDlg);

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    PROPSHEETPAGE * pPage = (PROPSHEETPAGE *)lParam;
    TFileTestData * pData = (TFileTestData *)pPage->lParam;
    HWND hCombo = GetDlgItem(hDlg, IDC_CREATE_DISPOSITION);

    // Remember the global window data
    SetDialogData(hDlg, pPage->lParam);

    // Configure dialog resizing
    if(pData->bEnableResizing)
    {
        pAnchors = new TAnchors();
        pAnchors->AddAnchor(hDlg, IDC_MAIN_FRAME, akAll);
        pAnchors->AddAnchor(hDlg, IDC_DIRECTORY_NAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_DIRECTORY_NAME_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_NAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_NAME_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_DESIRED_ACCESS, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_DESIRED_ACCESS_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SHARE_ACCESS, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SHARE_ACCESS_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_CREATE_DISPOSITION, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_ATTRIBUTES, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_ATTRIBUTES_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_TEMPLATE_FILE, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_TEMPLATE_FILE_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_TRANSACTED, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_VIRTUALIZATION, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_BREAKPOINT, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_PRIVILEGES, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_MAKE_DIRECTORY, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_CREATE_FILE, akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_CLOSE_HANDLE, akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_FRAME, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_LAST_ERROR_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_LAST_ERROR, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_HANDLE_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_HANDLE, akLeft | akRight | akBottom);
    }

    // Initialize the combo box with operations
    InitDialogControls(hDlg, MAKEINTRESOURCE(IDD_PAGE01_CREATE));
    if(hCombo != NULL)
        ComboBox_SetCurSel(hCombo, pData->dwCreateDisposition1 - 1);

    // If we have a tooltip window, init tooltips 
    g_Tooltip.AddToolTip(hDlg, IDC_DESIRED_ACCESS, DesiredAccessValues);
    g_Tooltip.AddToolTip(hDlg, IDC_SHARE_ACCESS, ShareAccessValues);
    g_Tooltip.AddToolTip(hDlg, IDC_FILE_ATTRIBUTES, (TFlagInfo *)NULL);

    // On pre-Vista, disable the virtualization button
    if(GetTokenVirtualizationEnabled(NULL))
        EnableDlgItems(hDlg, TRUE, IDC_VIRTUALIZATION, 0);
    return TRUE;
}

static int OnSetActive(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    BOOL bEnabled;
    int nChecked;

    // Set directory name
    SetDlgItemText(hDlg, IDC_DIRECTORY_NAME, pData->szDirName);
    ConvertToWin32Name(hDlg, IDC_DIRECTORY_NAME);
    
    // Set file name
    if((pData->dwCreateOptions & FILE_OPEN_BY_FILE_ID) == 0)
    {
        SetDlgItemText(hDlg, IDC_FILE_NAME, pData->szFileName1);
        ConvertToWin32Name(hDlg, IDC_FILE_NAME);
    }

    // Set template file
    SetDlgItemText(hDlg, IDC_TEMPLATE_FILE, pData->szTemplate);
    ConvertToWin32Name(hDlg, IDC_TEMPLATE_FILE);

    // Set the various create options
    Hex2DlgText32(hDlg, IDC_DESIRED_ACCESS, pData->dwDesiredAccess);
    Hex2DlgText32(hDlg, IDC_FILE_ATTRIBUTES, pData->dwFileAttributes);
    Hex2DlgText32(hDlg, IDC_SHARE_ACCESS, pData->dwShareAccess);

    // Enable/disable transaction
    bEnabled = (pfnCreateFileTransacted != NULL && IsHandleValid(pData->hTransaction));
    EnableDlgItems(hDlg, bEnabled, IDC_TRANSACTED, 0);
    nChecked = (bEnabled && pData->bUseTransaction) ? BST_CHECKED : BST_UNCHECKED;
    CheckDlgButton(hDlg, IDC_TRANSACTED, nChecked);

    // Check/uncheck virtualization
    nChecked = (GetTokenVirtualizationEnabled(&bEnabled) && bEnabled) ? BST_CHECKED : BST_UNCHECKED;
    CheckDlgButton(hDlg, IDC_VIRTUALIZATION, nChecked);

    // Enable/disable "CloseHandle"
    bEnabled = IsHandleValid(pData->hFile) ? TRUE : FALSE;
    EnableDlgItems(hDlg, bEnabled, IDC_CLOSE_HANDLE, 0);
    return TRUE;
}

static int OnKillActive(HWND hDlg)
{
    SaveDialog(hDlg);
    return TRUE;
}

static int OnBrowseDirClick(HWND hDlg)
{
    return BrowseForDirectory(hDlg, MAKEINTRESOURCE(IDC_DIRECTORY_NAME), IDS_SELECT_DIRECTORY, MAX_PATH);
}

static int OnBrowseFileClick(HWND hDlg)
{
    OPENFILENAME ofn;

    InitOpenFileName(&ofn);
    ofn.lpstrFile = MAKEINTRESOURCE(IDC_FILE_NAME);
    ofn.lpstrTitle = MAKEINTRESOURCE(IDS_SELECT_FILE);
    ofn.lpstrFilter = MAKEINTRESOURCE(IDS_FILTER_ALL);
    GetOpenFileNameRc(hDlg, &ofn); 

    return TRUE;
}

static int OnBrowseTemplateClick(HWND hDlg)
{
    OPENFILENAME ofn;

    InitOpenFileName(&ofn);
    ofn.lpstrFile = MAKEINTRESOURCE(IDC_TEMPLATE_FILE);
    ofn.lpstrTitle = MAKEINTRESOURCE(IDS_SELECT_FILE);
    ofn.lpstrFilter = MAKEINTRESOURCE(IDS_FILTER_ALL);
    GetOpenFileNameRc(hDlg, &ofn); 

    return TRUE;
}

static int OnDesiredAccessClick(HWND hDlg)
{
    FlagsDialog_OnControl(hDlg, IDC_DESIRED_ACCESS, IDS_DESIRED_ACCESS, DesiredAccessValues);
    return TRUE;
}

static int OnFileAttributesClick(HWND hDlg)
{
    FlagsDialog_PreArranged(hDlg, IDD_FLAGS_AND_ATTRS, IDC_FILE_ATTRIBUTES, FileAttributesValues_CreateFile);
    return TRUE;
}

static int OnShareAccessClick(HWND hDlg)
{
    FlagsDialog_OnControl(hDlg, IDC_SHARE_ACCESS, IDS_SHARE_ACCESS, ShareAccessValues);
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
    TFileTestData * pData = GetDialogData(hDlg);
    LPTSTR szDirectory = pData->szDirName;
    LPTSTR szPathPart = pData->szDirName;
    LPTSTR szTemp;
    TCHAR chSaveChar;
    int nError = ERROR_SUCCESS;

    // Get the values from dialog controls to the dialog data
    if(SaveDialog(hDlg) != ERROR_SUCCESS)
        return FALSE;

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
                chSaveChar = szTemp[0];
                szTemp[0] = 0;
                nError = MyCreateDirectory(pData, szDirectory);
                if(nError != ERROR_SUCCESS)
                    break;

                // Go to the next part of the path
                szPathPart = szTemp;
                szTemp[0] = chSaveChar;
            }
        }
        else
        {
            nError = MyCreateDirectory(pData, szDirectory);
        }
    }
    else
    {
        nError = MyCreateDirectory(pData, szDirectory);
    }

    SetResultInfo(hDlg, nError, pData->hFile);
    return TRUE;
}

static int OnCreateFileClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    HANDLE hTemplateFile = NULL;
    int nError = ERROR_SUCCESS;

    // Close the handle, if already open
    if(IsHandleValid(pData->hFile))
        OnCloseHandleClick(hDlg);

    // Get the values from dialog controls to the dialog data
    if(SaveDialog(hDlg) != ERROR_SUCCESS)
        return FALSE;

    // Change the directory (If any)
    if(pData->szDirName[0] != 0)
    {
        if(!SetCurrentDirectory(pData->szDirName))
        {
            nError = GetLastError();
            SetResultInfo(hDlg, nError, INVALID_HANDLE_VALUE);
            return TRUE;
        }
    }

    // Prepare the template file
    if(nError == ERROR_SUCCESS && pData->szTemplate[0] != 0)
    {
        hTemplateFile = CreateFile(pData->szTemplate,
                                   FILE_READ_EA,
                                   FILE_SHARE_READ,
                                   NULL,
                                   OPEN_EXISTING,
                                   0,
                                   NULL);
        if(hTemplateFile == INVALID_HANDLE_VALUE)
            nError = GetLastError();
    }

    // Prepare the file open
    if(nError == ERROR_SUCCESS)
    {
        if(pData->bUseTransaction == FALSE)
        {
            // Invoke breakpoint if the user wants to
            if(IsDlgButtonChecked(hDlg, IDC_BREAKPOINT) == BST_CHECKED)
                DebugBreak();

            pData->hFile = CreateFile(pData->szFileName1,
                                      pData->dwDesiredAccess,
                                      pData->dwShareAccess,
                                      NULL,
                                      pData->dwCreateDisposition1,
                                      pData->dwFileAttributes,
                                      hTemplateFile);
        }
        else
        {
            // Invoke breakpoint if the user wants to
            if(IsDlgButtonChecked(hDlg, IDC_BREAKPOINT) == BST_CHECKED)
                DebugBreak();

            pData->hFile = pfnCreateFileTransacted(pData->szFileName1,
                                                   pData->dwDesiredAccess,
                                                   pData->dwShareAccess,
                                                   NULL,
                                                   pData->dwCreateDisposition1,
                                                   pData->dwFileAttributes,
                                                   hTemplateFile,
                                                   pData->hTransaction,
                                                   NULL,
                                                   NULL);
        }

        if(IsHandleInvalid(pData->hFile))
            nError = GetLastError();
    }

    if(IsHandleValid(hTemplateFile))
        CloseHandle(hTemplateFile);
    SetResultInfo(hDlg, nError, pData->hFile);
    return TRUE;
}

static int OnCloseHandleClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    int nError = ERROR_SUCCESS;

    if(IsHandleValid(pData->hFile))
    {
        // If directory has been changed, set it back to initial
        if(pData->szDirName[0] != 0)
            SetCurrentDirectory(g_szInitialDirectory);

        // Invoke breakpoint if the user wants to
        if(IsDlgButtonChecked(hDlg, IDC_BREAKPOINT) == BST_CHECKED)
            DebugBreak();

        if(!CloseHandle(pData->hFile))
            nError = GetLastError();
    }

    pData->hFile = NULL;
    SetResultInfo(hDlg, nError, pData->hFile);
    return TRUE;
}

//-----------------------------------------------------------------------------
// Dialog procedure

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    if(nNotify == BN_CLICKED)
    {
        switch(nIDCtrl)
        {
            case IDC_DIRECTORY_NAME_BROWSE:
                OnBrowseDirClick(hDlg);
                return TRUE;

            case IDC_FILE_NAME_BROWSE:
                OnBrowseFileClick(hDlg);
                return TRUE;

            case IDC_DESIRED_ACCESS_BROWSE:
                return OnDesiredAccessClick(hDlg);

            case IDC_FILE_ATTRIBUTES_BROWSE:
                return OnFileAttributesClick(hDlg);
        
            case IDC_SHARE_ACCESS_BROWSE:
                return OnShareAccessClick(hDlg);

            case IDC_TEMPLATE_FILE_BROWSE:
                OnBrowseTemplateClick(hDlg);
                return TRUE;

            case IDC_VIRTUALIZATION:
                return OnVirtualization(hDlg);

            case IDC_PRIVILEGES:
                PrivilegesDialog(hDlg);
                return TRUE;

            case IDC_MAKE_DIRECTORY:
                return OnMakeDirectoryClick(hDlg);

            case IDC_CREATE_FILE:
                return OnCreateFileClick(hDlg);

            case IDC_CLOSE_HANDLE:
                return OnCloseHandleClick(hDlg);
        }
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
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// Public page callback

INT_PTR CALLBACK PageProc01(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
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
