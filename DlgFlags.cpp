/*****************************************************************************/
/* DlgFlags.cpp                           Copyright (c) Ladislav Zezula 2004 */
/*---------------------------------------------------------------------------*/
/* Each entry in the dialog is defined by the structure:                     */
/*                                                                           */
/*  struct TFlagInfo                                                         */
/*  {                                                                        */
/*      union                                                                */
/*      {                                                                    */
/*          LPCTSTR szItemText; // Text of the checkbox/radio button         */
/*          UINT    nIDCtrl;    // ID of the checkbox/radio button           */
/*      };                                                                   */
/*                                                                           */
/*      DWORD   dwMask;         // Item is checked when                      */
/*      DWORD   dwValue;        // (dwFlags & dwMask) == dwValue             */
/*  };                                                                       */
/*                                                                           */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 06.01.04  1.00  Lad  The first version of DlgFlags.cpp                    */
/* 22.10.15  1.00  Lad  Flag info extended to contain mask as well           */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local structures

struct TFlagDialogData
{
    TFlagInfo * pFlags;                     // Flags (structure array)
    HWND        hWndParent;                 // Parent of the dialog
    HWND        hDlg;                       // The dialog itself
    UINT        nIDTitle;                   // String ID of the dialog title
    DWORD       dwFlags;                    // Flag value (in/out)
    DWORD       IsPreArranged:1;            // If TRUE, then the dialog is already pre-arranged
    DWORD       SpareBits:31;
};

typedef void (*CHILD_WINDOW_CALLBACK)(TFlagDialogData * pData, TFlagInfo * pFlags, HWND hWndChild, DWORD dwStyles);

//-----------------------------------------------------------------------------
// Local functions

// Arranging the dialog layout for pre-arranged dialogs
static void CreateDialogLayout_PreArranged(TFlagDialogData * pData)
{
    TFlagInfo * pFlags;
    HWND hWndChild;
    UINT nChecked;

    // Parse all flags and setup every child item
    for(pFlags = pData->pFlags; pFlags->nIDCtrl != 0; pFlags++)
    {
        // Retrieve the child window belonging to this flag
        hWndChild = GetDlgItem(pData->hDlg, pFlags->nIDCtrl);
        assert(hWndChild != NULL);

        // Set the pointer to flag info structure to the child's window data
        SetWindowLongPtr(hWndChild, GWLP_USERDATA, (LONG_PTR)pFlags);

        // If the flag is set, we need to check that item
        nChecked = IS_FLAG_SET(pFlags, pData->dwFlags);
        Button_SetCheck(hWndChild, nChecked);
    }
}

// Arranging the dialog layout for empty dialogs, where the controls need to be created
static void CreateDialogLayout_Empty(TFlagDialogData * pData)
{
    TFlagInfo * pFlags;
    TCHAR szItemText[MAX_PATH+1];
    HFONT hFont;
    DWORD dwExStyle;
    DWORD dwStyle;
    HWND hPrevChild = NULL;
    HWND hWndGroup = GetDlgItem(pData->hDlg, IDC_GROUPBOX);
    HWND hCheckAll = GetDlgItem(pData->hDlg, IDC_SELECT_ALL);
    HWND hClearAll = GetDlgItem(pData->hDlg, IDC_CLEAR_ALL);
    HWND hOkButton = GetDlgItem(pData->hDlg, IDOK);
    HWND hWndChild = GetDlgItem(pData->hDlg, IDC_CHECKBOX);
    RECT DialogRect;                        // Rectangle of the dialog (screen-relative)
    RECT ParentRect;                        // Rectangle of the dialog's parent (screen-relative)
    RECT ClientRect;                        // Rectangle of the dialog client area (screen-relative)
    RECT GroupRect;                         // Rectangle of the group box
    RECT CheckBoxRect;                      // Rectangle of the checkbox
    RECT CheckAllRect;                      // Distance of "Check All" from left-bottom corner of the dialog
    RECT ClearAllRect;                      // Distance of "Clear All" from left-bottom corner of the dialog
    RECT OkButtonRect;                      // Distance of "OK" from right-bottom corner of the dialog
    int nChecked = BST_UNCHECKED;
    int nDeltaY = 0;                        // Delta dialog size
    int x, y, cx, cy;

    // Get the size of the parent
    if(pData->hWndParent != NULL)
        GetWindowRect(pData->hWndParent, &ParentRect);
    else
        SystemParametersInfo(SPI_GETWORKAREA, 0, &ParentRect, FALSE);

    // Get the size of the dialog and the "master" settings
    GetWindowRect(pData->hDlg, &DialogRect);
    GetClientRect(pData->hDlg, &ClientRect);
    hFont = (HFONT)SendMessage(hWndChild, WM_GETFONT, 0, 0);

    // Get the position of the children
    GetWindowRect(hWndGroup, &GroupRect);
    ScreenRectToClientRect(pData->hDlg, &GroupRect);
    GetWindowRect(hWndChild, &CheckBoxRect);
    ScreenRectToClientRect(pData->hDlg, &CheckBoxRect);
    GetWindowRect(hCheckAll, &CheckAllRect);
    ScreenRectToClientRect(pData->hDlg, &CheckAllRect);
    GetWindowRect(hClearAll, &ClearAllRect);
    ScreenRectToClientRect(pData->hDlg, &ClearAllRect);
    GetWindowRect(hOkButton, &OkButtonRect);
    ScreenRectToClientRect(pData->hDlg, &OkButtonRect);

    // Get the settings of the "master" checkbox
    dwExStyle = GetWindowLong(hWndChild, GWL_EXSTYLE);
    dwStyle   = GetWindowLong(hWndChild, GWL_STYLE) & ~(WS_TABSTOP | WS_GROUP);

    // Calculate width and height of the check box
    cx = (CheckBoxRect.right - CheckBoxRect.left);
    cy = (CheckBoxRect.bottom - CheckBoxRect.top);

    // Arrange all checkboxes
    // Create all check boxes
    for(pFlags = pData->pFlags; pFlags->szFlagText != NULL; pFlags++)
    {
        if(hWndChild == NULL)
        {
            // Increment the dialog height
            nDeltaY = nDeltaY + cy + 6;

            // Create the checkbox
            hWndChild = CreateWindowEx(dwExStyle,
                                       WC_BUTTON,
                                       NULL,
                                       dwStyle | WS_VISIBLE,
                                       CheckBoxRect.left,
                                       CheckBoxRect.top + nDeltaY,
                                       cx,
                                       cy,
                                       pData->hDlg,
                                       0,
                                       g_hInst,
                                       NULL);
            SendMessage(hWndChild, WM_SETFONT, (WPARAM)hFont, FALSE);

            // Set the checkbox's Z-order after the previous one
            SetWindowPos(hWndChild, hPrevChild, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            hPrevChild = hWndChild;
        }

        // Set the window text
        _stprintf(szItemText, _T("(%08X) %s"), pFlags->dwValue, pFlags->szFlagText);
        SetWindowText(hWndChild, szItemText);

        // Set the parametert to the flag pointer
        SetWindowLongPtr(hWndChild, GWLP_USERDATA, (LONG_PTR)pFlags);

        // Check/uncheck the box
        nChecked = IS_FLAG_SET(pFlags, pData->dwFlags) ? BST_CHECKED : BST_UNCHECKED;
        Button_SetCheck(hWndChild, nChecked);
        hWndChild = NULL;
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
    SetWindowPos(pData->hDlg, NULL, x, y, cx, cy, SWP_NOZORDER | SWP_NOACTIVATE);
}

static void ForEachChildWindow(HWND hDlg, CHILD_WINDOW_CALLBACK ChildCallback)
{
    TFlagDialogData * pData = (TFlagDialogData *)GetWindowLongPtr(hDlg, DWLP_USER);
    TFlagInfo * pFlags;
    DWORD dwStyles;
    HWND hWndChild;

    // Enumerate all children. For checkboxes and radio buttons,
    // get their value and add them to the summary flag value
    for(hWndChild = GetWindow(hDlg, GW_CHILD); hWndChild != NULL; hWndChild = GetWindow(hWndChild, GW_HWNDNEXT))
    {
        // Is that a check box or a radio button?
        dwStyles = GetWindowLong(hWndChild, GWL_STYLE);
        if((dwStyles & BS_TYPEMASK) == BS_AUTOCHECKBOX || (dwStyles & BS_TYPEMASK) == BS_AUTORADIOBUTTON)
        {
            // Retrieve flag info structure the button
            pFlags = (TFlagInfo *)GetWindowLongPtr(hWndChild, GWLP_USERDATA);
            if(pFlags != NULL)
            {
                // Call the for-each callback
                ChildCallback(pData, pFlags, hWndChild, dwStyles);
            }
        }
    }
}

// Only do checkboxes. Ignore radio buttons
static void Callback_SetCheck(TFlagDialogData * /* pData */, TFlagInfo * /* pFlags */, HWND hWndChild, DWORD dwStyles)
{
    if((dwStyles & BS_TYPEMASK) == BS_AUTOCHECKBOX)
        Button_SetCheck(hWndChild, BST_CHECKED);
}

// Only do checkboxes. Ignore radio buttons
static void Callback_ClearCheck(TFlagDialogData * /* pData */, TFlagInfo * /* pFlags */, HWND hWndChild, DWORD dwStyles)
{
    if((dwStyles & BS_TYPEMASK) == BS_AUTOCHECKBOX)
        Button_SetCheck(hWndChild, BST_UNCHECKED);
}

// If the button is checked, add the flag to the flags
static void Callback_SaveFlag(TFlagDialogData * pData, TFlagInfo * pFlags, HWND hWndChild, DWORD /* dwStyles */)
{
    if(Button_GetCheck(hWndChild) == BST_CHECKED)
        pData->dwFlags |= pFlags->dwValue;
}

//-----------------------------------------------------------------------------
// Dialog handlers

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    TFlagDialogData * pData = (TFlagDialogData *)lParam;

    // Configure the dialog
    SetDialogData(hDlg, lParam);
    SetDialogIcon(hDlg, IDI_FILE_TEST);

    // Remember the dialog handle
    pData->hDlg = hDlg;

    // Is the dialog pre-arranged?
    if(pData->IsPreArranged)
    {
        CreateDialogLayout_PreArranged(pData);
    }
    else
    {
        SetWindowTextRc(hDlg, pData->nIDTitle);
        CreateDialogLayout_Empty(pData);
    }

    // Clear the dialog flags
    pData->dwFlags = 0;
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
                    ForEachChildWindow(hDlg, Callback_SetCheck);
                    break;
            
                case IDC_CLEAR_ALL:
                    ForEachChildWindow(hDlg, Callback_ClearCheck);
                    break;

                case IDOK:
                    ForEachChildWindow(hDlg, Callback_SaveFlag);
                    // No break here !!

                case IDCANCEL:
                    EndDialog(hDlg, LOWORD(wParam));
                    break;
            }
        }
    }

    return FALSE;
}

//-----------------------------------------------------------------------------
// Public functions

INT_PTR FlagsDialog(HWND hWndParent, LPDWORD pdwFlags, UINT nIDTitle, TFlagInfo * pFlags)
{
    TFlagDialogData fdd;
    INT_PTR Result = IDCANCEL;

    // Prepare the structure that gives parameters to the Flags dialog
    ZeroMemory(&fdd, sizeof(TFlagDialogData));
    fdd.pFlags   = pFlags;
    fdd.hWndParent = hWndParent;
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

INT_PTR FlagsDialog2(HWND hWndParent, UINT nIDDialog, UINT nIDCtrl, TFlagInfo * pFlags)
{
    TFlagDialogData fdd;
    INT_PTR Result;

    // Retrieve the flags
    ZeroMemory(&fdd, sizeof(TFlagDialogData));
    fdd.pFlags   = pFlags;
    fdd.hWndParent = hWndParent;
    fdd.IsPreArranged = TRUE;
    DlgText2Hex32(hWndParent, nIDCtrl, &fdd.dwFlags);

    // Execute the dialog
    Result = DialogBoxParam(g_hInst, MAKEINTRESOURCE(nIDDialog), hWndParent, DialogProc, (LPARAM)&fdd);
    if(Result == IDOK)
        Hex2DlgText32(hWndParent, nIDCtrl, fdd.dwFlags);

    return Result;
}
