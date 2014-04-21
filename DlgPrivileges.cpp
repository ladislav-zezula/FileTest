/*****************************************************************************/
/* DlgPrivileges.cpp                      Copyright (c) Ladislav Zezula 2009 */
/*---------------------------------------------------------------------------*/
/* Description :                                                             */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 19.05.09  1.00  Lad  The first version of DlgPrivileges.cpp               */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local functions

static HANDLE OpenCurrentToken(DWORD dwDesiredAccess)
{
    HANDLE hToken = NULL;

    // Open process or thread token
    if(!OpenThreadToken(GetCurrentThread(), dwDesiredAccess, TRUE, &hToken))
    {
        if(GetLastError() == ERROR_NO_TOKEN)
            OpenProcessToken(GetCurrentProcess(), dwDesiredAccess, &hToken);
    }

    return hToken;
}

static void SetIntegrityLevelAsTest(HWND hDlg)
{
    LPCTSTR szIntLevel = _T("");
    DWORD dwIntLevel;

    DlgText2Hex32(hDlg, IDC_INTLEVEL_VALUE, &dwIntLevel);
    switch(dwIntLevel)
    {
        case SECURITY_MANDATORY_UNTRUSTED_RID:
            szIntLevel = _T("(Untrusted)");
            break;

        case SECURITY_MANDATORY_LOW_RID:
            szIntLevel = _T("(Low)");
            break;

        case SECURITY_MANDATORY_MEDIUM_RID:
            szIntLevel = _T("(Medium)");
            break;

        case SECURITY_MANDATORY_HIGH_RID:
            szIntLevel = _T("(High)");
            break;

        case SECURITY_MANDATORY_SYSTEM_RID:
            szIntLevel = _T("(System)");
            break;

        case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:
            szIntLevel = _T("(Protected Process)");
            break;
    }

    SetDlgItemText(hDlg, IDC_INTLEVEL_TEXT, szIntLevel);
}


static void SetPrivilegeCheckBox(
    HWND hDlg,
    UINT nIDCheckBox,
    LPCTSTR szCheckedPrivName,
    LPCTSTR szPrivName,
    DWORD dwPrivilegeState)
{
    HWND hCheck;

    // Is it the searched privilege name ?
    if(!_tcsicmp(szPrivName, szCheckedPrivName))
    {
        // Is the checkbox there ?
        hCheck = GetDlgItem(hDlg, nIDCheckBox);
        if(hCheck != NULL)
        {
            // Enable the check box
            EnableWindow(hCheck, TRUE);
            
            // If the privilege is granted, check the checkbox
            if(dwPrivilegeState & SE_PRIVILEGE_ENABLED)
                Button_SetCheck(hCheck, BST_CHECKED);
        }
    }
}

static int UpdateProcessPrivilege(HWND hDlg, HANDLE hToken, UINT nIDCtrl, LPCTSTR szPrivName)
{
    TOKEN_PRIVILEGES tkp;
    HWND hCheck;
    BOOL bEnabled = (IsDlgButtonChecked(hDlg, nIDCtrl) == BST_CHECKED);

    // Token handle is expected to be valid
    assert(hToken != NULL);

    // Get the handle to the checkbox window
    hCheck = GetDlgItem(hDlg, nIDCtrl);
    if(IsWindowEnabled(hCheck))
    {
        // Determine if the privilege should be enabled or not
        bEnabled = (Button_GetCheck(hCheck) == BST_CHECKED);

        // Get the LUID for the privilege.
        if(LookupPrivilegeValue(NULL, szPrivName, &tkp.Privileges[0].Luid))
        {
            tkp.PrivilegeCount = 1;  // one privilege to set
            tkp.Privileges[0].Attributes = bEnabled ? SE_PRIVILEGE_ENABLED : 0;
            AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
        }
    }

    return TRUE;
}

static void UpdateDialogFromToken(HWND hDlg)
{
    PTOKEN_MANDATORY_LABEL pMandatoryLabel = NULL;
    PTOKEN_PRIVILEGES pTokenPrivs = NULL;
    LPTSTR szErrorText;
    HANDLE hToken;
    DWORD cbMandatoryLabel = 0;
    DWORD cbTokenPrivs = 0;
    int nError = ERROR_SUCCESS;

    // Open current thread/process token
    hToken = OpenCurrentToken(TOKEN_QUERY);
    if(hToken == NULL)
    {
        szErrorText = GetErrorText(GetLastError());
        MessageBoxRc(hDlg, IDS_ERROR, IDS_E_OPEN_TOKEN, szErrorText);
        delete [] szErrorText;
        return;
    }

    // Query the token privileges
    if(!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivs, cbTokenPrivs, &cbTokenPrivs))
        nError = GetLastError();
    if(nError == ERROR_INSUFFICIENT_BUFFER && cbTokenPrivs != 0)
    {
        pTokenPrivs = (PTOKEN_PRIVILEGES)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, cbTokenPrivs);
        GetTokenInformation(hToken, TokenPrivileges, pTokenPrivs, cbTokenPrivs, &cbTokenPrivs);
    }

    // Query the token mandatory label. Supported on Vista or newer.
    if(!GetTokenInformation(hToken, TokenIntegrityLevel, pMandatoryLabel, cbMandatoryLabel, &cbMandatoryLabel))
        nError = GetLastError();
    if(nError == ERROR_INSUFFICIENT_BUFFER && cbMandatoryLabel != 0)
    {
        pMandatoryLabel = (PTOKEN_MANDATORY_LABEL)HeapAlloc(GetProcessHeap(), 0, cbMandatoryLabel);
        GetTokenInformation(hToken, TokenIntegrityLevel, pMandatoryLabel, cbMandatoryLabel, &cbMandatoryLabel);
    }

    // If query token succeeded, parse them
    if(pTokenPrivs != NULL)
    {
        for(DWORD i = 0; i < pTokenPrivs->PrivilegeCount; i++)
        {
            PLUID_AND_ATTRIBUTES pLuid = pTokenPrivs->Privileges + i;
            TCHAR szPrivName[128];
            DWORD cchName = _tsize(szPrivName);

            LookupPrivilegeName(NULL, &pLuid->Luid, szPrivName, &cchName);
            SetPrivilegeCheckBox(hDlg, IDC_TAKE_OWNERSHIP_NAME, SE_TAKE_OWNERSHIP_NAME, szPrivName, pLuid->Attributes);
            SetPrivilegeCheckBox(hDlg, IDC_CHANGE_NOTIFY_NAME, SE_CHANGE_NOTIFY_NAME, szPrivName, pLuid->Attributes);
            SetPrivilegeCheckBox(hDlg, IDC_MANAGE_VOLUME_NAME, SE_MANAGE_VOLUME_NAME, szPrivName, pLuid->Attributes);
            SetPrivilegeCheckBox(hDlg, IDC_SECURITY_NAME, SE_SECURITY_NAME, szPrivName, pLuid->Attributes);
            SetPrivilegeCheckBox(hDlg, IDC_RESTORE_NAME, SE_RESTORE_NAME, szPrivName, pLuid->Attributes);
            SetPrivilegeCheckBox(hDlg, IDC_BACKUP_NAME, SE_BACKUP_NAME, szPrivName, pLuid->Attributes);
            SetPrivilegeCheckBox(hDlg, IDC_TCB_NAME, SE_TCB_NAME, szPrivName, pLuid->Attributes);
        }

        HeapFree(g_hHeap, 0, pTokenPrivs);
    }

    // If any token privileges found, pass them to dialog.
    // Otherwise, disable all parts for integrity levels
    if(pMandatoryLabel != NULL)
    {
        SID_IDENTIFIER_AUTHORITY SiaMandatoryLabel = SECURITY_MANDATORY_LABEL_AUTHORITY;
        PSID pSid = pMandatoryLabel->Label.Sid;
        DWORD dwIntegrityLevel = SECURITY_MANDATORY_MEDIUM_RID;
        TCHAR szText[0x20];
        UCHAR dwSubAuthCount = *GetSidSubAuthorityCount(pSid);

        // Is that a mandatory label SID ?
        if(!memcmp(GetSidIdentifierAuthority(pSid), &SiaMandatoryLabel, sizeof(SID_IDENTIFIER_AUTHORITY)))
            dwIntegrityLevel = *GetSidSubAuthority(pSid, dwSubAuthCount - 1);

        _stprintf(szText, _T("%08lX"), dwIntegrityLevel);
        SetDlgItemText(hDlg, IDC_INTLEVEL_VALUE, szText);
        HeapFree(g_hHeap, 0, pMandatoryLabel);
    }
    else
    {
        EnableDlgItems(hDlg, FALSE, IDC_INTLEVEL_FRAME,
                                    IDC_INTLEVEL_TITLE,
                                    IDC_INTLEVEL_VALUE,
                                    IDC_INTLEVEL_UPDOWN,
                                    IDC_INTLEVEL_EXPLAIN,
                                    IDC_INTLEVEL_EXPLAIN2,
                                    0);
    }

    // Close the token handle
    CloseHandle(hToken);
}

static int UpdateTokenFromDialog(HWND hDlg)
{
    SID_IDENTIFIER_AUTHORITY Sia = SECURITY_MANDATORY_LABEL_AUTHORITY;
    TOKEN_MANDATORY_LABEL tml;
    LPTSTR szErrorText;
    HANDLE hToken = NULL;
    DWORD dwDesiredAccess = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY;
    DWORD dwIntLevel;
    HWND hEdit;
    PSID pMandatorySid = NULL;
    BOOL bLevelChanged;
    BOOL bResult = TRUE;

    // Determine if we changed integrity level
    bLevelChanged = (BOOL)GetWindowLongPtr(hDlg, DWLP_USER);
    if(bLevelChanged)
        dwDesiredAccess |= TOKEN_ADJUST_DEFAULT;

    // Open current thread/process token
    hToken = OpenCurrentToken(dwDesiredAccess);
    if(hToken == NULL)
    {
        szErrorText = GetErrorText(GetLastError());
        MessageBoxRc(hDlg, IDS_ERROR, IDS_E_OPEN_TOKEN, szErrorText);
        delete [] szErrorText;
        return FALSE;
    }

    // Update the privileges
    UpdateProcessPrivilege(hDlg, hToken, IDC_TAKE_OWNERSHIP_NAME, SE_TAKE_OWNERSHIP_NAME);
    UpdateProcessPrivilege(hDlg, hToken, IDC_CHANGE_NOTIFY_NAME, SE_CHANGE_NOTIFY_NAME);
    UpdateProcessPrivilege(hDlg, hToken, IDC_MANAGE_VOLUME_NAME, SE_MANAGE_VOLUME_NAME);
    UpdateProcessPrivilege(hDlg, hToken, IDC_SECURITY_NAME, SE_SECURITY_NAME);
    UpdateProcessPrivilege(hDlg, hToken, IDC_RESTORE_NAME, SE_RESTORE_NAME);
    UpdateProcessPrivilege(hDlg, hToken, IDC_BACKUP_NAME, SE_BACKUP_NAME);
    UpdateProcessPrivilege(hDlg, hToken, IDC_TCB_NAME, SE_TCB_NAME);

    // Update process integrity level
    hEdit = GetDlgItem(hDlg, IDC_INTLEVEL_VALUE);
    if(bLevelChanged && hEdit != NULL && IsWindowEnabled(hEdit))
    {
        // Create the SID containing integrity level
        DlgText2Hex32(hDlg, IDC_INTLEVEL_VALUE, &dwIntLevel);
        if(AllocateAndInitializeSid(&Sia, 1, dwIntLevel, 0, 0, 0, 0, 0, 0, 0, &pMandatorySid))
        {
            tml.Label.Attributes = SE_GROUP_INTEGRITY;
            tml.Label.Sid = pMandatorySid;

            // Apply the integrity level to the token
            bResult = SetTokenInformation(hToken,
                                          TokenIntegrityLevel,
                                         &tml,
                                          sizeof(TOKEN_MANDATORY_LABEL));
            if(bResult == FALSE)
            {
                szErrorText = GetErrorText(GetLastError());
                MessageBoxRc(hDlg, IDS_ERROR, IDS_FAILED_TO_SET_ILEVEL, szErrorText);
                delete [] szErrorText;
            }

            FreeSid(pMandatorySid);
        }
    }

    // Close the token
    CloseHandle(hToken);
    return bResult;
}

//-----------------------------------------------------------------------------
// Dialog handlers

static int OnInitDialog(HWND hDlg)
{
    HWND hUpDown;
    HWND hEdit;

    // Configure the dialog
    SetDialogIcon(hDlg, IDI_FILE_TEST);
    UpdateDialogFromToken(hDlg);

    // Set parameters of the Integrity value edit box
    hEdit = GetDlgItem(hDlg, IDC_INTLEVEL_VALUE);
    if(hEdit != NULL)
        Edit_LimitText(hEdit, 12);

    // Set the parameters of the UpDown box
    hUpDown = GetDlgItem(hDlg, IDC_INTLEVEL_UPDOWN);
    if(hUpDown != NULL)
    {
        SendMessage(hUpDown, UDM_SETRANGE32, 0, 0x7FFFFFFF);
        SendMessage(hUpDown, UDM_SETPOS32, 0, 0x40000000);
    }

    SetWindowLongPtr(hDlg, DWLP_USER, 0);
    CenterWindowToParent(hDlg);
    return TRUE;
}

static int SelectAllCheckBoxes(HWND hDlg, int nChecked)
{
    HWND hCheck;
    UINT nIDs[] = 
    {
        IDC_TAKE_OWNERSHIP_NAME,
        IDC_CHANGE_NOTIFY_NAME,
        IDC_MANAGE_VOLUME_NAME,
        IDC_SECURITY_NAME,
        IDC_RESTORE_NAME,
        IDC_BACKUP_NAME,
        IDC_TCB_NAME,
        0
    };

    // Go through all checkboxes
    for(int i = 0; nIDs[i] != 0; i++)
    {
        hCheck = GetDlgItem(hDlg, nIDs[i]);
        if(IsWindowEnabled(hCheck))
            Button_SetCheck(hCheck, nChecked);
    }

    return TRUE;
}

static int OnDeltaPos(HWND hDlg, NMUPDOWN * pNMUpDown)
{
    DWORD dwIntLevel = 0;

    DlgText2Hex32(hDlg, IDC_INTLEVEL_VALUE, &dwIntLevel);
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

    Hex2DlgText32(hDlg, IDC_INTLEVEL_VALUE, dwIntLevel);
    return TRUE;
}

static INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // Dialog initialization
    if(uMsg == WM_INITDIALOG)
        return OnInitDialog(hDlg);

    if(uMsg == WM_COMMAND)
    {
        if(HIWORD(wParam) == BN_CLICKED)
        {
            switch(LOWORD(wParam))
            {
                case IDC_SELECT_ALL:
                    SelectAllCheckBoxes(hDlg, BST_CHECKED);
                    break;

                case IDC_CLEAR_ALL:
                    SelectAllCheckBoxes(hDlg, BST_UNCHECKED);
                    break;

                case IDOK:
                    if(UpdateTokenFromDialog(hDlg) == FALSE)
                        break;
                    // No break here !!

                case IDCANCEL:
                    EndDialog(hDlg, LOWORD(wParam));
                    break;
            }
        }

        if(HIWORD(wParam) == EN_CHANGE)
        {
            // Remember that we modified the integrity level
            SetIntegrityLevelAsTest(hDlg);
            SetWindowLongPtr(hDlg, DWLP_USER, TRUE);
        }
    }

    if(uMsg == WM_NOTIFY)
    {
        NMHDR * pNMHDR = (NMHDR *)lParam;

        if(pNMHDR->code == UDN_DELTAPOS)
        {
            OnDeltaPos(hDlg, (NMUPDOWN *)pNMHDR);
        }
    }

    return FALSE;
}
                                 
INT_PTR PrivilegesDialog(HWND hParent)
{
    return DialogBox(g_hInst, MAKEINTRESOURCE(IDD_PRIVILEGES), hParent, DialogProc);
}
