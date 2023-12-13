/*****************************************************************************/
/* DlgPrivileges.cpp                      Copyright (c) Ladislav Zezula 2009 */
/*---------------------------------------------------------------------------*/
/* Description :                                                             */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 19.05.09  1.00  Lad  Created                                              */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local defines

template <DWORD Count>
struct TTokenPrivileges
{
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[Count];
};

struct TPrivilegeAndCtrl
{
    LPCTSTR szPrivName;
    UINT    nCtrlID;
};

struct TDialogData
{
    PTOKEN_PRIVILEGES pTokenPrivs;

    DWORD dwIntegrityLevel;
    DWORD dwSaveIntLevel;
    
    BOOL bLongPathsSupported;
    BOOL bLongPathsEnabled;

    DWORD bFirstInit:1;                         // If TRUE, the dialog never received WM_INITDIALOG
};

//-----------------------------------------------------------------------------
// Local variables

static TPrivilegeAndCtrl PrivCtrlList[] =
{
    {SE_TAKE_OWNERSHIP_NAME, IDC_TAKE_OWNERSHIP_NAME},
    {SE_CHANGE_NOTIFY_NAME, IDC_CHANGE_NOTIFY_NAME},
    {SE_MANAGE_VOLUME_NAME, IDC_MANAGE_VOLUME_NAME},
    {SE_SECURITY_NAME, IDC_SECURITY_NAME},
    {SE_RESTORE_NAME, IDC_RESTORE_NAME},
    {SE_BACKUP_NAME, IDC_BACKUP_NAME},
    {SE_TCB_NAME, IDC_TCB_NAME}
};

static LPCTSTR szKeyName = _T("SYSTEM\\CurrentControlSet\\Control\\FileSystem");
static LPCTSTR szValName = _T("LongPathsEnabled");

//-----------------------------------------------------------------------------
// Local functions

static TDialogData * GetData(HWND hDlg)
{
    return (TDialogData *)GetWindowLongPtr(hDlg, DWLP_USER);
}

static void LoadSystemSettings(TDialogData & Data)
{
    PTOKEN_MANDATORY_LABEL pMandatoryLabel = NULL;
    PTOKEN_PRIVILEGES pTokenPrivs = NULL;
    HANDLE hToken;
    HKEY  hSubKey;
    DWORD cbMandatoryLabel = 0;
    DWORD cbTokenPrivs = 0;
    DWORD cbValue = sizeof(DWORD);
    DWORD dwValue = 0;
    DWORD dwType = 0;

    // Set the default values
    Data.dwIntegrityLevel = INTEGRITY_LEVEL_NONE;

    // Open current thread/process token
    hToken = OpenCurrentToken(TOKEN_QUERY);
    if(hToken != NULL)
    {
        // Query the token privileges
        GetTokenInformation(hToken, TokenPrivileges, pTokenPrivs, cbTokenPrivs, &cbTokenPrivs);
        if(cbTokenPrivs != 0)
        {
            pTokenPrivs = (PTOKEN_PRIVILEGES)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, cbTokenPrivs);
            if(pTokenPrivs != NULL)
            {
                GetTokenInformation(hToken, TokenPrivileges, pTokenPrivs, cbTokenPrivs, &cbTokenPrivs);
                Data.pTokenPrivs = pTokenPrivs;
            }
        }

        // Query the token mandatory label. Supported on Vista or newer.
        GetTokenInformation(hToken, TokenIntegrityLevel, pMandatoryLabel, cbMandatoryLabel, &cbMandatoryLabel);
        if(cbMandatoryLabel != 0)
        {
            pMandatoryLabel = (PTOKEN_MANDATORY_LABEL)HeapAlloc(GetProcessHeap(), 0, cbMandatoryLabel);
            if(pMandatoryLabel != NULL)
            {
                if(GetTokenInformation(hToken, TokenIntegrityLevel, pMandatoryLabel, cbMandatoryLabel, &cbMandatoryLabel))
                {
                    SID_IDENTIFIER_AUTHORITY SiaMandatoryLabel = SECURITY_MANDATORY_LABEL_AUTHORITY;
                    PSID pSid = pMandatoryLabel->Label.Sid;
                    UCHAR dwSubAuthCount = *GetSidSubAuthorityCount(pSid);

                    GetTokenInformation(hToken, TokenIntegrityLevel, pMandatoryLabel, cbMandatoryLabel, &cbMandatoryLabel);
                    Data.dwIntegrityLevel = SECURITY_MANDATORY_MEDIUM_RID;

                    // Is that a mandatory label SID ?
                    if(!memcmp(GetSidIdentifierAuthority(pSid), &SiaMandatoryLabel, sizeof(SID_IDENTIFIER_AUTHORITY)))
                    {
                        Data.dwIntegrityLevel = *GetSidSubAuthority(pSid, dwSubAuthCount - 1);
                    }
                }
                HeapFree(g_hHeap, 0, pMandatoryLabel);
            }
        }

        CloseHandle(hToken);
    }

    // Query the option "Enable long path names"
    // Windows build must be at least 14393
    if(g_dwWinBuild >= 14393)
    {
        // The feature is supported
        Data.bLongPathsSupported = TRUE;
        
        // Let's get whether it's enabled
        if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKeyName, 0, KEY_QUERY_VALUE, &hSubKey) == ERROR_SUCCESS)
        {
            if(RegQueryValueEx(hSubKey, szValName, NULL, &dwType, (LPBYTE)(&dwValue), &cbValue) == ERROR_SUCCESS && dwType == REG_DWORD)
                Data.bLongPathsEnabled = (dwValue != 0) ? TRUE : FALSE;
            RegCloseKey(hSubKey);
        }
    }

    // Save the original integrity level
    Data.dwSaveIntLevel = Data.dwIntegrityLevel;
}

static void SetIntegrityLevelText(HWND hDlg)
{
    LPCTSTR szIntLevel = _T("");
    DWORD dwIntLevel;

    DlgText2Hex32(hDlg, IDC_INTLEVEL_VALUE, &dwIntLevel);
    switch(dwIntLevel)
    {
        case SECURITY_MANDATORY_UNTRUSTED_RID:
            szIntLevel = _T("SECURITY_MANDATORY_UNTRUSTED_RID");
            break;

        case SECURITY_MANDATORY_LOW_RID:
            szIntLevel = _T("SECURITY_MANDATORY_LOW_RID");
            break;

        case SECURITY_MANDATORY_MEDIUM_RID:
            szIntLevel = _T("SECURITY_MANDATORY_MEDIUM_RID");
            break;

        case SECURITY_MANDATORY_HIGH_RID:
            szIntLevel = _T("SECURITY_MANDATORY_HIGH_RID");
            break;

        case SECURITY_MANDATORY_SYSTEM_RID:
            szIntLevel = _T("SECURITY_MANDATORY_SYSTEM_RID");
            break;

        case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:
            szIntLevel = _T("SECURITY_MANDATORY_PROTECTED_PROCESS_RID");
            break;
    }

    SetDlgItemText(hDlg, IDC_INTLEVEL_TEXT, szIntLevel);
}

static void InitDialog_Privileges(TDialogData * pData, HWND hDlg)
{
    PTOKEN_PRIVILEGES pTokenPrivs;
    HWND hWndChild;

    // If query token succeeded, parse them
    if((pTokenPrivs = pData->pTokenPrivs) != NULL)
    {
        for(DWORD i = 0; i < pTokenPrivs->PrivilegeCount; i++)
        {
            PLUID_AND_ATTRIBUTES pLuid = pTokenPrivs->Privileges + i;
            TCHAR szPrivName[0x80];
            DWORD cchName = _countof(szPrivName);

            LookupPrivilegeName(NULL, &pLuid->Luid, szPrivName, &cchName);

            // Find the appropriate check box. If found, reflect the privilege to it
            for(size_t j = 0; j < _countof(PrivCtrlList); j++)
            {
                if(!_tcsicmp(PrivCtrlList[j].szPrivName, szPrivName))
                {
                    // Is the checkbox there ?
                    if((hWndChild = GetDlgItem(hDlg, PrivCtrlList[j].nCtrlID)) != NULL)
                    {
                        Button_SetCheck(hWndChild, (pLuid->Attributes & SE_PRIVILEGE_ENABLED) ? BST_CHECKED : BST_UNCHECKED);
                        EnableWindow(hWndChild, TRUE);
                        break;
                    }
                }
            }
        }
    }
}

static DWORD SaveDialog_Privileges(TDialogData * /* pData */, HWND hDlg)
{
    TTokenPrivileges<_countof(PrivCtrlList)> tkp = {0};
    HANDLE hToken;
    DWORD dwErrCode = ERROR_SUCCESS;
    DWORD dwEnabled;
    HWND hWndChild;

    // Open current thread/process token
    hToken = OpenCurrentToken(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY);
    if(hToken != NULL)
    {
        // Parse all checkboxes and update privilege
        for(size_t i = 0; i < _countof(PrivCtrlList); i++)
        {
            // Retrieve the check box
            if((hWndChild = GetDlgItem(hDlg, PrivCtrlList[i].nCtrlID)) != NULL)
            {
                // If the check box is disabled, it means that the privilege is not granted
                if(IsWindowEnabled(hWndChild))
                {
                    // Is the privilege enabled?
                    dwEnabled = (Button_GetCheck(hWndChild) == BST_CHECKED) ? SE_PRIVILEGE_ENABLED : 0;

                    // Get the LUID for the privilege.
                    if(LookupPrivilegeValue(NULL, PrivCtrlList[i].szPrivName, &tkp.Privileges[tkp.PrivilegeCount].Luid))
                    {
                        tkp.Privileges[tkp.PrivilegeCount].Attributes = dwEnabled;
                        tkp.PrivilegeCount++;
                    }
                    else
                    {
                        dwErrCode = GetLastError();
                        break;
                    }
                }
            }
        }

        // If there is at least one privilege to set, do it
        if(dwErrCode == ERROR_SUCCESS && tkp.PrivilegeCount != 0)
        {
            if(!AdjustTokenPrivileges(hToken, FALSE, (PTOKEN_PRIVILEGES)(&tkp), 0, NULL, NULL))
                dwErrCode = GetLastError();
        }

        // Close the token handle
        CloseHandle(hToken);
    }
    else
    {
        dwErrCode = GetLastError();
    }

    return dwErrCode;
}

static void InitDialog_IntegrityLevel(TDialogData * pData, HWND hDlg, HWND hWndChild)
{
    TCHAR szText[0x20] = _T("<not supported>");
    BOOL bEnable = FALSE;

    if(pData->dwIntegrityLevel != INTEGRITY_LEVEL_NONE)
    {
        StringCchPrintf(szText, _countof(szText), _T("%08lX"), pData->dwIntegrityLevel);
        bEnable = TRUE;
    }

    // Update the edit control
    EnableDlgItems(hDlg, bEnable, IDC_INTLEVEL_VALUE, IDC_INTLEVEL_UPDOWN, 0);
    SetWindowText(hWndChild, szText);
    Edit_LimitText(hWndChild, 12);

    // Update the up-down control
    if((hWndChild = GetDlgItem(hDlg, IDC_INTLEVEL_UPDOWN)) != NULL)
    {
        SendMessage(hWndChild, UDM_SETRANGE32, 0, 0x7FFFFFFF);
        SendMessage(hWndChild, UDM_SETPOS32, 0, 0x40000000);
    }
}

static DWORD SaveDialog_IntegrityLevel(TDialogData * pData, HWND hDlg, HWND hWndChild)
{
    SID_IDENTIFIER_AUTHORITY Sia = SECURITY_MANDATORY_LABEL_AUTHORITY;
    TOKEN_MANDATORY_LABEL tml;
    HANDLE hToken = NULL;
    DWORD dwIntLevel = 0;
    DWORD dwErrCode = ERROR_SUCCESS;
    PSID pMandatorySid = NULL;

    // Retrieve the integrity level
    DlgText2Hex32(hDlg, IDC_INTLEVEL_VALUE, &dwIntLevel);

    // Did we change the integrity level?
    if(IsWindowEnabled(hWndChild) && (dwIntLevel != pData->dwSaveIntLevel))
    {
        // Open current thread/process token
        if((hToken = OpenCurrentToken(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT)) != NULL)
        {
            // Creae a new SID for mandatory label
            if(AllocateAndInitializeSid(&Sia, 1, dwIntLevel, 0, 0, 0, 0, 0, 0, 0, &pMandatorySid))
            {
                tml.Label.Attributes = SE_GROUP_INTEGRITY;
                tml.Label.Sid = pMandatorySid;

                // Apply the integrity level to the token
                if(!SetTokenInformation(hToken, TokenIntegrityLevel, &tml, sizeof(TOKEN_MANDATORY_LABEL)))
                    dwErrCode = GetLastError();
                FreeSid(pMandatorySid);
            }
            else
            {
                dwErrCode = GetLastError();
            }

            // Close the token handle
            CloseHandle(hToken);
        }
        else
        {
            dwErrCode = GetLastError();
        }
    }

    return dwErrCode;
}

static void InitDialog_LongPaths(TDialogData * pData, HWND hWndChild)
{
    EnableWindow(hWndChild, pData->bLongPathsSupported);
    Button_SetCheck(hWndChild, pData->bLongPathsEnabled ? BST_CHECKED : BST_UNCHECKED);
}

static DWORD SaveDialog_LongPaths(TDialogData * /* pData */, HWND hWndChild)
{
    HKEY hSubKey = NULL;
    DWORD dwErrCode = ERROR_SUCCESS;
    DWORD dwValue = 0;

    // Is the feature supported at all?
    if(IsWindowEnabled(hWndChild))
    {
        // Retrieve the state
        dwValue = (Button_GetCheck(hWndChild) == BST_CHECKED) ? 1 : 0;

        // Let's get whether it's enabled
        dwErrCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKeyName, 0, KEY_SET_VALUE, &hSubKey);
        if(dwErrCode == ERROR_SUCCESS)
        {
            dwErrCode = RegSetValueEx(hSubKey, szValName, 0, REG_DWORD, (LPBYTE)(&dwValue), sizeof(DWORD));
            RegCloseKey(hSubKey);
        }
    }

    return dwErrCode;
}

//-----------------------------------------------------------------------------
// Dialog handlers

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    LPPROPSHEETPAGE psp = (LPPROPSHEETPAGE)lParam;
    TDialogData * pData = (TDialogData *)(psp->lParam);
    HWND hWndChild;

    // Set the dialog data
    SetWindowLongPtr(hDlg, DWLP_USER, psp->lParam);

    // Save the pointer to the dialog data to the dialog
    if(pData->bFirstInit == FALSE)
    {
        CenterWindowToParent(GetParent(hDlg));
        pData->bFirstInit = TRUE;
    }

    // Configure the privileges, if present
    if((hWndChild = GetDlgItem(hDlg, IDC_TAKE_OWNERSHIP_NAME)) != NULL)
        InitDialog_Privileges(pData, hDlg);

    // Configure the integrity level, if present
    if((hWndChild = GetDlgItem(hDlg, IDC_INTLEVEL_VALUE)) != NULL)
        InitDialog_IntegrityLevel(pData, hDlg, hWndChild);

    // Configure the long path settings
    if((hWndChild = GetDlgItem(hDlg, IDC_ENABLE_LONG_PATH_NAME)) != NULL)
        InitDialog_LongPaths(pData, hWndChild);

    // Update the privileges and LongPath settings
    return TRUE;
}

static bool OnApply(HWND hDlg)
{
    TDialogData * pData = GetData(hDlg);
    LPCTSTR szCategory = NULL;
    LPTSTR szErrorText = NULL;
    DWORD dwErrCode = ERROR_SUCCESS;
    HWND hWndChild;

    // Configure the privileges, if present
    if(dwErrCode == ERROR_SUCCESS)
    {
        if((hWndChild = GetDlgItem(hDlg, IDC_TAKE_OWNERSHIP_NAME)) != NULL)
        {
            dwErrCode = SaveDialog_Privileges(pData, hDlg);
            szCategory = _T("privileges");
        }
    }

    // Configure the integrity level, if present
    if(dwErrCode == ERROR_SUCCESS)
    {
        if((hWndChild = GetDlgItem(hDlg, IDC_INTLEVEL_VALUE)) != NULL)
        {
            dwErrCode = SaveDialog_IntegrityLevel(pData, hDlg, hWndChild);
            szCategory = _T("integrity level");
        }
    }

    // Configure the long path settings
    if(dwErrCode == ERROR_SUCCESS)
    {
        if((hWndChild = GetDlgItem(hDlg, IDC_ENABLE_LONG_PATH_NAME)) != NULL)
        {
            dwErrCode = SaveDialog_LongPaths(pData, hWndChild);
            szCategory = _T("long paths");
        }
    }

    // Show an error message
    if(dwErrCode != ERROR_SUCCESS)
    {
        if((szErrorText = GetErrorText(GetLastError())) != NULL)
        {
            MessageBoxRc(hDlg, IDS_ERROR, IDS_E_APPLY_SETTINGS, szCategory, szErrorText);
            delete [] szErrorText;
        }
    }

    return (bool)(dwErrCode == ERROR_SUCCESS);
}

static int OnSelectAllCheckBoxes(HWND hDlg, int nChecked)
{
    TCHAR szClassName[100];
    HWND hWndChild = GetFirstChild(hDlg);
    DWORD dwStyles;

    // Enumerate all children
    while(hWndChild != NULL)
    {
        GetClassName(hWndChild, szClassName, _countof(szClassName));
        dwStyles = (DWORD)GetWindowLong(hWndChild, GWL_STYLE);
        if(!_tcsicmp(szClassName, WC_BUTTON) && (dwStyles & BS_AUTOCHECKBOX))
        {
            if(IsWindowEnabled(hWndChild))
            {
                Button_SetCheck(hWndChild, nChecked);
            }
        }
        hWndChild = GetNextSibling(hWndChild);
    }
    return TRUE;
}

static int OnDeltaPos(HWND hDlg, NMUPDOWN * pNMUpDown)
{
    DWORD dwSaveIntLevel;
    DWORD dwIntLevel = 0;

    // Retrieve the integrity level
    DlgText2Hex32(hDlg, IDC_INTLEVEL_VALUE, &dwIntLevel);
    dwSaveIntLevel = dwIntLevel;

    // Move the integrity level
    if(pNMUpDown->iDelta > 0)
    {
        if(dwIntLevel <= 0x0000E000)
            dwIntLevel += 0x00001000;
        else
            dwIntLevel = 0x0000F000;
    }
    else
    {
        if(dwIntLevel >= 0x1000)
            dwIntLevel -= 0x00001000;
        else
            dwIntLevel = 0;
    }

    // Update the integrity level
    if(dwIntLevel != dwSaveIntLevel)
        Hex2DlgText32(hDlg, IDC_INTLEVEL_VALUE, dwIntLevel);
    return TRUE;
}

static void OnCommand(HWND hDlg, UINT nNotifyCode, UINT nCtrlID)
{
    switch(nNotifyCode)
    {
        case BN_CLICKED:

            if(nCtrlID == IDC_SELECT_ALL)
            {
                OnSelectAllCheckBoxes(hDlg, BST_CHECKED);
                break;
            }

            if(nCtrlID == IDC_CLEAR_ALL)
            {
                OnSelectAllCheckBoxes(hDlg, BST_UNCHECKED);
                break;
            }

            break;

        case EN_CHANGE:

            if(nCtrlID == IDC_INTLEVEL_VALUE)
                SetIntegrityLevelText(hDlg);
            break;
    }
}

static INT_PTR OnNotify(HWND hDlg, LPNMHDR pNMHdr)
{
    switch(pNMHdr->code)
    {
        case UDN_DELTAPOS:
            OnDeltaPos(hDlg, (NMUPDOWN *)pNMHdr);
            break;

        case PSN_APPLY:
            if(!OnApply(hDlg))
                SetWindowLongPtr(hDlg, DWLP_MSGRESULT, PSNRET_INVALID_NOCHANGEPAGE);
            break;
    }

    return TRUE;
}

static INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
        case WM_INITDIALOG:
            return OnInitDialog(hDlg, lParam);

        case WM_COMMAND:
            OnCommand(hDlg, HIWORD(wParam), LOWORD(wParam));
            break;

        case WM_NOTIFY:
            return OnNotify(hDlg, (LPNMHDR)lParam);
    }

    return FALSE;
}

INT_PTR PrivilegesDialog(HWND hParent)
{
    PROPSHEETHEADER psh = {0};      // Defines the property sheet
    PROPSHEETPAGE   psp = {0};      // Defines the property sheet pages
    HPROPSHEETPAGE  hPsp[5] = {0};  // An array to hold the page's HPROPSHEETPAGE handles
    TDialogData Data = {0};
    int nPages = 0;

    // Load the current system settings
    LoadSystemSettings(Data);    

    // Create the "Privileges" page
    psp.dwSize      = sizeof(PROPSHEETPAGE);
    psp.pszTemplate = MAKEINTRESOURCE(IDD_SETTINGS01);
    psp.hInstance   = g_hInst;
    psp.pfnDlgProc  = DialogProc;
    psp.dwFlags     = PSP_DEFAULT;
    psp.lParam      = (LPARAM)(&Data);
    hPsp[nPages++]  = CreatePropertySheetPage(&psp);

    // Create the "Integrity Level" page
    psp.dwSize      = sizeof(PROPSHEETPAGE);
    psp.pszTemplate = MAKEINTRESOURCE(IDD_SETTINGS02);
    psp.hInstance   = g_hInst;
    psp.pfnDlgProc  = DialogProc;
    psp.dwFlags     = PSP_DEFAULT;
    psp.lParam      = (LPARAM)(&Data);
    hPsp[nPages++]  = CreatePropertySheetPage(&psp);

    // Create the "Long Path Names" page
    psp.dwSize      = sizeof(PROPSHEETPAGE);
    psp.pszTemplate = MAKEINTRESOURCE(IDD_SETTINGS03);
    psp.hInstance   = g_hInst;
    psp.pfnDlgProc  = DialogProc;
    psp.dwFlags     = PSP_DEFAULT;
    psp.lParam      = (LPARAM)(&Data);
    hPsp[nPages++]  = CreatePropertySheetPage(&psp);

    // Create the property sheet
    psh.dwSize      = sizeof(PROPSHEETHEADER);
    psh.hInstance   = g_hInst;
    psh.hwndParent  = hParent;
    psh.pszIcon     = MAKEINTRESOURCE(IDI_FILE_TEST);
    psh.pszCaption  = MAKEINTRESOURCE(IDS_SETTINGS);
    psh.phpage      = hPsp;
    psh.dwFlags     = PSH_USEICONID | PSH_NOAPPLYNOW;
    psh.nStartPage  = 0;
    psh.nPages      = nPages;

    // Run the wizard and return the error code
    return PropertySheet(&psh);
}
