/*****************************************************************************/
/* DlgSimple.cpp                          Copyright (c) Ladislav Zezula 2014 */
/*---------------------------------------------------------------------------*/
/* Description: Common module for a few simple dialogs                       */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 18.03.14  1.00  Lad  The first version of DlgSimple.cpp                   */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local functions

static void SetWindowModuleVersion(HWND hWndChild, LPCTSTR szModuleName)
{
    ULARGE_INTEGER Version;
    TCHAR szFormat[255];
    TCHAR szText[255];

    // Is such window really there ?
    if(hWndChild != NULL)
    {
        GetWindowText(hWndChild, szFormat, _maxchars(szFormat));
        GetModuleVersion(szModuleName, &Version);
        StringCchPrintf(szText, _countof(szText), szFormat,
                                                  HIWORD(Version.HighPart),
                                                  LOWORD(Version.HighPart),
                                                  HIWORD(Version.LowPart),
                                                  LOWORD(Version.LowPart));
        SetWindowText(hWndChild, szText);
    }
}

//-----------------------------------------------------------------------------
// Event handlers

static int OnInitDialog(HWND hDlg, LPARAM /* lParam */)
{
    TCHAR szMyName[MAX_PATH + 1];
    HWND hWndChild;

    // Set the dialog icon
    SetDialogIcon(hDlg, IDI_FILE_TEST);

    // Parse all child windows
    // If there is IDC_VERSION static text, supply the 4-digit version from resources
    hWndChild = GetDlgItem(hDlg, IDC_FILETEST_WEB);
    if(hWndChild != NULL)
        InitURLButton(hDlg, IDC_FILETEST_WEB, FALSE);

    // If there is IDC_VERSION static text, supply the 4-digit version from resources
    hWndChild = GetDlgItem(hDlg, IDC_VERSION);
    if(hWndChild != NULL)
    {
        GetModuleFileName(NULL, szMyName, MAX_PATH);
        SetWindowModuleVersion(hWndChild, szMyName);
    }

    return TRUE;
}

static BOOL OnCommand(HWND hDlg, HWND hWndFrom, UINT nNotifyCode, UINT nCtrlID)
{
    if(nNotifyCode == BN_CLICKED)
    {
        // An URL button leads to opening its WWW page
        if(IsURLButton(hWndFrom))
        {
            ClickURLButton(hWndFrom);
            return TRUE;
        }

        // Any other button closes the dialog
        EndDialog(hDlg, nCtrlID);
        return TRUE;
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// Message handler

static INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
        case WM_INITDIALOG:
            return OnInitDialog(hDlg, lParam);

        case WM_DRAWITEM:
            DrawURLButton(hDlg, (LPDRAWITEMSTRUCT)lParam);
            return FALSE;

        case WM_COMMAND:
            return OnCommand(hDlg, (HWND)lParam, HIWORD(wParam), LOWORD(wParam));
    }

    return FALSE;
}

//-----------------------------------------------------------------------------
// Dialog functions

INT_PTR HelpAboutDialog(HWND hParent)
{
    return DialogBox(g_hInst, MAKEINTRESOURCE(IDD_HELP_ABOUT), hParent, DialogProc);
}

INT_PTR ObjectIDActionDialog(HWND hParent)
{
    return DialogBox(g_hInst, MAKEINTRESOURCE(IDD_OBJECT_ID_MORE), hParent, DialogProc);
}

INT_PTR FileActionDialog(HWND hParent)
{
    return DialogBox(g_hInst, MAKEINTRESOURCE(IDD_FILE_ACTION), hParent, DialogProc);
}

INT_PTR ObjectGuidHelpDialog(HWND hParent)
{
    return DialogBox(g_hInst, MAKEINTRESOURCE(IDD_OBJECT_GUID_HELP), hParent, DialogProc);
}
