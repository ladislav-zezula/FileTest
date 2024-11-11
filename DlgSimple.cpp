/*****************************************************************************/
/* DlgSimple.cpp                          Copyright (c) Ladislav Zezula 2014 */
/*---------------------------------------------------------------------------*/
/* Description: Common module for a few simple dialogs                       */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 18.03.14  1.00  Lad  Created                                              */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local functions

static void SetWindowTextModuleVersion(HWND hWndChild, HMODULE hMod)
{
    ULARGE_INTEGER Version;
    TCHAR szModName[MAX_PATH + 1];
    TCHAR szFormat[255];
    TCHAR szText[255];

    if(GetModuleFileName(hMod, szModName, MAX_PATH))
    {
        // Is such window really there ?
        if(hWndChild != NULL)
        {
            GetWindowText(hWndChild, szFormat, _countof(szFormat));
            GetModuleVersion(szModName, &Version);
            StringCchPrintf(szText, _countof(szText), szFormat,
                                                      HIWORD(Version.HighPart),
                                                      LOWORD(Version.HighPart),
                                                      HIWORD(Version.LowPart),
                                                      LOWORD(Version.LowPart));
            SetWindowText(hWndChild, szText);
        }
    }
}

static void SetWindowTextFileTime(HWND hWndChild, LARGE_INTEGER & FileTime)
{
    TCHAR szText[0x80] = {0};

    if(FileTimeToText(szText, &szText[_countof(szText) - 1], (PFILETIME)(&FileTime), FALSE))
    {
        SetWindowText(hWndChild, szText);
    }
}

static void SetWindowTextFileAttributes(HWND hWndChild, DWORD dwAttributes)
{
    TFlagString fs(FileAttributesValues, dwAttributes, GetNewLineSeparator());

    SetWindowText(hWndChild, fs);
}

//-----------------------------------------------------------------------------
// Event handlers

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    PFILE_BASIC_INFORMATION pBasicInfo = (PFILE_BASIC_INFORMATION)lParam;
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
        SetWindowTextModuleVersion(hWndChild, NULL);

    // Last write time
    if(pBasicInfo != NULL)
    {
        if((hWndChild = GetDlgItem(hDlg, IDC_CREATION_TIME)) != NULL)
            SetWindowTextFileTime(hWndChild, pBasicInfo->CreationTime);
        if((hWndChild = GetDlgItem(hDlg, IDC_LAST_ACCESS_TIME)) != NULL)
            SetWindowTextFileTime(hWndChild, pBasicInfo->LastAccessTime);
        if((hWndChild = GetDlgItem(hDlg, IDC_LAST_WRITE_TIME)) != NULL)
            SetWindowTextFileTime(hWndChild, pBasicInfo->LastWriteTime);
        if((hWndChild = GetDlgItem(hDlg, IDC_CHANGE_TIME)) != NULL)
            SetWindowTextFileTime(hWndChild, pBasicInfo->ChangeTime);
        if((hWndChild = GetDlgItem(hDlg, IDC_FILE_ATTRIBUTES)) != NULL)
            SetWindowTextFileAttributes(hWndChild, pBasicInfo->FileAttributes);
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

INT_PTR HelpAboutDialog(HWND hWndParent)
{
    return DialogBox(g_hInst, MAKEINTRESOURCE(IDD_HELP_ABOUT), hWndParent, DialogProc);
}

INT_PTR HelpCommandLineDialog(HWND hWndParent)
{
    return DialogBox(g_hInst, MAKEINTRESOURCE(IDD_HELP_COMMAND_LINE), hWndParent, DialogProc);
}

INT_PTR ObjectIDActionDialog(HWND hWndParent)
{
    return DialogBox(g_hInst, MAKEINTRESOURCE(IDD_OBJECT_ID_MORE), hWndParent, DialogProc);
}

INT_PTR ObjectGuidHelpDialog(HWND hWndParent)
{
    return DialogBox(g_hInst, MAKEINTRESOURCE(IDD_OBJECT_GUID_HELP), hWndParent, DialogProc);
}

INT_PTR FileAttributesDialog(HWND hWndParent, PFILE_BASIC_INFORMATION pBasicInfo)
{
    return DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_FILE_ATTRIBUTES), hWndParent, DialogProc, (LPARAM)(pBasicInfo));
}

INT_PTR NtAttributesDialog(HWND hWndParent, PFILE_BASIC_INFORMATION pBasicInfo)
{
    return DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_NT_ATTRIBUTES), hWndParent, DialogProc, (LPARAM)(pBasicInfo));
}
