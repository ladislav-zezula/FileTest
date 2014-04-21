/*****************************************************************************/
/* DlgFlags.cpp                           Copyright (c) Ladislav Zezula 2004 */
/*---------------------------------------------------------------------------*/
/* Description:                                                              */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 06.01.04  1.00  Lad  The first version of DlgFlags.cpp                    */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local structures

struct TFlagDialogData
{
    TFlagInfo * pFlags;                     // Flags (structure array)
    HWND        hParent;                    // Parent of the dialog
    UINT        nIDTitle;                   // String ID of the dialog title
    DWORD       dwFlags;                    // Flag value (in/out)
};

//-----------------------------------------------------------------------------
// Local functions

static void ArrangeDialogLayout(
    TFlagDialogData * pData,
    HWND hDlg,
    HWND hWndGroup,
    HWND hWndCheck,
    HWND hCheckAll,
    HWND hClearAll)
{
    TFlagInfo * pFlagInfo;
    HFONT hFont;
    DWORD dwExStyle;
    DWORD dwStyle;
    HWND hWndParent;
    HWND hOkButton = GetDlgItem(hDlg, IDOK);
    HWND hPrevCheck = hWndCheck;
    RECT DialogRect;                        // Rectangle of the dialog (screen-relative)
    RECT ParentRect;                        // Rectangle of the dialog's parent (screen-relative)
    RECT ClientRect;                        // Rectangle of the dialog client area (screen-relative)
    RECT GroupRect;                         // Rectangle of the group box
    RECT CheckBoxRect;                      // Rectangle of the checkbox
    RECT CheckAllRect;                      // Distance of "Check All" from left-bottom corner of the dialog
    RECT ClearAllRect;                      // Distance of "Clear All" from left-bottom corner of the dialog
    RECT OkButtonRect;                      // Distance of "OK" from right-bottom corner of the dialog
    int nChecked = BST_UNCHECKED;
    int nIDCtrl = IDC_CHECKBOX;             // ID of the check box
    int nDeltaY = 0;                        // Delta dialog size
    int x, y, cx, cy;

    // Get the size of the parent
    hWndParent = GetParent(hDlg);
    if(hWndParent != NULL)
        GetWindowRect(hWndParent, &ParentRect);
    else
        SystemParametersInfo(SPI_GETWORKAREA, 0, &ParentRect, FALSE);

    // Get the size of the dialog and the "master" settings
    GetWindowRect(hDlg, &DialogRect);
    GetClientRect(hDlg, &ClientRect);
    hFont = (HFONT)SendMessage(hWndCheck, WM_GETFONT, 0, 0);

    // Get the position of the children
    GetWindowRect(hWndGroup, &GroupRect);
    ScreenRectToClientRect(hDlg, &GroupRect);
    GetWindowRect(hWndCheck, &CheckBoxRect);
    ScreenRectToClientRect(hDlg, &CheckBoxRect);
    GetWindowRect(hCheckAll, &CheckAllRect);
    ScreenRectToClientRect(hDlg, &CheckAllRect);
    GetWindowRect(hClearAll, &ClearAllRect);
    ScreenRectToClientRect(hDlg, &ClearAllRect);
    GetWindowRect(hOkButton, &OkButtonRect);
    ScreenRectToClientRect(hDlg, &OkButtonRect);

    // Get the settings of the "master" checkbox
    dwExStyle = (DWORD)GetWindowLongPtr(hWndCheck, GWL_EXSTYLE);
    dwStyle   = (DWORD)GetWindowLongPtr(hWndCheck, GWL_STYLE) & ~(WS_TABSTOP | WS_GROUP);

    // Calculate width and height of the check box
    cx = (CheckBoxRect.right - CheckBoxRect.left);
    cy = (CheckBoxRect.bottom - CheckBoxRect.top);

    // Arrange all checkboxes
    // Create all check boxes
    for(pFlagInfo = pData->pFlags; pFlagInfo->szFlagText != NULL; pFlagInfo++, nIDCtrl++)
    {
        if(hWndCheck == NULL)
        {
            // Increment the dialog height
            nDeltaY = nDeltaY + cy + 6;

            // Create the checkbox
            hWndCheck = CreateWindowEx(dwExStyle,
                                       WC_BUTTON,
                                       NULL,
                                       dwStyle | WS_VISIBLE,
                                       CheckBoxRect.left,
                                       CheckBoxRect.top + nDeltaY,
                                       cx,
                                       cy,
                                       hDlg,
                       (HMENU)(INT_PTR)nIDCtrl,
                                       g_hInst,
                                       NULL);
            SendMessage(hWndCheck, WM_SETFONT, (WPARAM)hFont, FALSE);

            // Set the checkbox's Z-order after the previous one
            SetWindowPos(hWndCheck, hPrevCheck, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            hPrevCheck = hWndCheck;
        }

        // Set the window text
        SetWindowText(hWndCheck, pFlagInfo->szFlagText);

        // Enable/disable check box
        EnableWindow(hWndCheck, pFlagInfo->bEnabled);

        // Check/uncheck the box
        nChecked = (pData->dwFlags & pFlagInfo->dwFlag) ? BST_CHECKED : BST_UNCHECKED;
        Button_SetCheck(hWndCheck, nChecked);
        hWndCheck = NULL;
    }

    // Now we have to resize the group box
    cx = (GroupRect.right - GroupRect.left);
    cy = (GroupRect.bottom - GroupRect.top) + nDeltaY;
    SetWindowPos(hWndGroup, NULL, 0, 0, cx, cy, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);

    // Move the buttons
    y = (ClientRect.bottom - ClientRect.top) + nDeltaY - (ClientRect.bottom - CheckAllRect.top);
    SetWindowPos(hCheckAll, NULL, CheckAllRect.left, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    SetWindowPos(hClearAll, NULL, ClearAllRect.left, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    SetWindowPos(hOkButton, NULL, OkButtonRect.left, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);

    // Center the dialog to parent
    cx = (DialogRect.right - DialogRect.left);
    cy = (DialogRect.bottom - DialogRect.top) + nDeltaY;
    x = ParentRect.left + ((ParentRect.right - ParentRect.left) - cx) / 2;
    y = ParentRect.top + ((ParentRect.bottom - ParentRect.top) - cy) / 2;
    SetWindowPos(hDlg, NULL, x, y, cx, cy, SWP_NOZORDER | SWP_NOACTIVATE);
}

//-----------------------------------------------------------------------------
// Dialog handlers

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    TFlagDialogData * pData = (TFlagDialogData *)lParam;
    HWND hWndGroup = GetDlgItem(hDlg, IDC_GROUPBOX);
    HWND hWndCheck = GetDlgItem(hDlg, IDC_CHECKBOX);
    HWND hCheckAll = GetDlgItem(hDlg, IDC_SELECT_ALL);
    HWND hClearAll = GetDlgItem(hDlg, IDC_CLEAR_ALL);

    // Configure the dialog
    SetDialogData(hDlg, lParam);
    SetDialogIcon(hDlg, IDI_FILE_TEST);
    SetWindowTextRc(hDlg, pData->nIDTitle);

    // Arrange the checkbox group
    ArrangeDialogLayout(pData, hDlg, hWndGroup, hWndCheck, hCheckAll, hClearAll);
    return TRUE;
}

static void SelectAllCheckboxes(HWND hDlg, int nCheck)
{
    UINT nIDCtrl = IDC_CHECKBOX;
    HWND hCheck = GetDlgItem(hDlg, nIDCtrl);

    while(hCheck != NULL)
    {
        DWORD_PTR dwStyle = (DWORD_PTR)GetWindowLongPtr(hCheck, GWL_STYLE);

        // If not a checkbox, do nothing
        if((dwStyle & 0x0F) != BS_AUTOCHECKBOX)
            break;

        // Check or uncheck the button
        if(IsWindowEnabled(hCheck))
            Button_SetCheck(hCheck, nCheck);

        // Move to the next checkbox
        hCheck = GetDlgItem(hDlg, ++nIDCtrl);
    }
}

static int OnSaveDialog(HWND hDlg)
{
    TFlagDialogData * pData = (TFlagDialogData *)GetWindowLongPtr(hDlg, DWLP_USER);
    UINT nIDCtrl = IDC_CHECKBOX;
    HWND hCheck = GetDlgItem(hDlg, nIDCtrl);
    int nIndex = 0;

    pData->dwFlags = 0;
    while(hCheck != NULL)
    {
        DWORD_PTR dwStyle = (DWORD_PTR)GetWindowLongPtr(hCheck, GWL_STYLE);

        // If not a checkbox, do nothing
        if((dwStyle & 0x0F) != BS_AUTOCHECKBOX)
            break;

        if(Button_GetCheck(hCheck) == BST_CHECKED)
            pData->dwFlags |= pData->pFlags[nIndex].dwFlag;

        // Move to the next checkbox
        hCheck = GetDlgItem(hDlg, ++nIDCtrl);
        nIndex++;
    }
    return TRUE;
}


static INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // Dialog initialization
    if(uMsg == WM_INITDIALOG)
        return OnInitDialog(hDlg, lParam);

    if(uMsg == WM_COMMAND)
    {
        if(HIWORD(wParam) == BN_CLICKED)
        {
            switch(LOWORD(wParam))
            {
                case IDC_SELECT_ALL:
                    SelectAllCheckboxes(hDlg, BST_CHECKED);
                    break;
            
                case IDC_CLEAR_ALL:
                    SelectAllCheckboxes(hDlg, BST_UNCHECKED);
                    break;

                case IDOK:
                    OnSaveDialog(hDlg);
                    // No break here !!

                case IDCANCEL:
                    EndDialog(hDlg, LOWORD(wParam));
                    break;
            }
        }
    }

    return FALSE;
}

INT_PTR FlagsDialog(HWND hWndParent, LPDWORD pdwFlags, UINT nIDTitle, TFlagInfo * pFlags)
{
    TFlagDialogData fdd;
    INT_PTR Result = IDCANCEL;

    // Prepare the structure that gives parameters to the Flags dialog
    ZeroMemory(&fdd, sizeof(TFlagDialogData));
    fdd.pFlags   = pFlags;
    fdd.hParent  = hWndParent;
    fdd.nIDTitle = nIDTitle;
    fdd.dwFlags  = *pdwFlags;

    // Invoke the flags dialog
    Result = DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_FLAGS_DIALOG), hWndParent, DialogProc, (LPARAM)&fdd);
    if(Result == IDOK)
        *pdwFlags = fdd.dwFlags;

    return Result;
}

INT_PTR FlagsDialog(HWND hWndParent, UINT nIDCtrl, UINT nIDTitle, TFlagInfo * pFlags)
{
    INT_PTR Result = IDCANCEL;
    DWORD dwFlags = 0;

    // Read the flags from the item
    if(DlgText2Hex32(hWndParent, nIDCtrl, &dwFlags) != ERROR_SUCCESS)
        return IDCANCEL;

    // Invoke the dialog
    Result = FlagsDialog(hWndParent, &dwFlags, nIDTitle, pFlags);
    if(Result == IDOK)
        Hex2DlgText32(hWndParent, nIDCtrl, dwFlags);
    return Result;
}
