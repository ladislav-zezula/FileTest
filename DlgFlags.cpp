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

typedef std::vector<TDlgFlagInfo> TFlagList;

struct TFlagDialogData
{
    TFlagDialogData()
    {
        ZeroMemory(&pFlags, sizeof(TFlagDialogData) - FIELD_OFFSET(TFlagDialogData, pFlags));
    }

    TFlagList   FlagList;
    TFlagInfo * pFlags;                     // Flags (structure array)
    HWND        hWndParent;                 // Parent of the dialog
    HWND        hWndPrev;                   // The previous window
    HWND        hDlg;                       // The dialog itself
    UINT        nIDTitle;                   // String ID of the dialog title
    size_t      nColumns;                   // Number of columns in the dialog
    size_t      nColumn1;                   // Number of bits in the first column
    DWORD       dwBitMask;                  // Flag value (in/out)

    // Dialog layout
    HFONT       hFont;                      // DialogFont
    RECT        RectInner;                  // Space between dialog and checkbox/radiobutton
    RECT        RectButton;                 // Size of the checkbox/radiobutton
    DWORD       dwExStyle;
    DWORD       dwStyle;
    int         xGroup;                     // Distance of the group from the left-top corner of the client
    int         yGroup;                     // Distance of the group from the left-top corner of the client
    int         xButton;                    // Distance of the button from the left border of the dialog
    int         yButton;                    // Distance of the button from the top border of the dialog
    int         cxButton;                   // Vertical distance between two buttons
    int         cyButton;                   // Vertical distance between two buttons
    int         cxSpace;                    // Column space (for multi-column dialogs)
    int         cySpace;                    // Column space (for multi-column dialogs)
    bool        bIsValuesDialog;            // True = this is list of radio buttons

    char        szCustomValue[0x40];        // String container for the extra check box, containing a custom value
};

typedef void (*CHILD_WINDOW_CALLBACK)(TFlagDialogData * pData, TFlagInfo * pFlags, HWND hWndChild, DWORD dwStyles);

//-----------------------------------------------------------------------------
// Local functions

static size_t BuildFlagList(TFlagDialogData * pData)
{
    TFlagList & FlagList = pData->FlagList;
    TFlagInfo * pFlags = pData->pFlags;
    DWORD dwCustomValue = pData->dwBitMask;
    DWORD dwPrevMask = 0xF0F0F0F0;
    DWORD i = 0;

    // Initialize the flag about values dialog
    pData->bIsValuesDialog = true;

    // Parse all flags. Determine their count, types, and whether we are values dialog of flag dialog
    for(pFlags = pData->pFlags; !pFlags->IsTerminator(); i++, pFlags++)
    {
        // By default, it's check box
        TDlgFlagInfo FlagInfo(pFlags->szFlagText, pFlags->dwValue, pFlags->dwMask, BS_AUTOCHECKBOX);

        // Exclude separators
        if(!pFlags->IsSeparator())
        {
            // If the flag value has the same mask like the previous one, set both to radio-button
            if(i > 0)
            {
                if(pFlags->dwMask == dwPrevMask)
                {
                    FlagList[i-1].dwButtonType = BS_AUTORADIOBUTTON;
                    FlagInfo.dwButtonType = BS_AUTORADIOBUTTON;
                }
                else
                {
                    pData->bIsValuesDialog = false;
                }
            }

            // Remember the previous mask
            dwCustomValue = dwCustomValue & ~pFlags->dwMask;
            dwPrevMask = pFlags->dwMask;
        }
        else
        {
            FlagInfo.dwButtonType = BS_TYPEMASK;
        }

        // Insert the flag into the list
        FlagList.push_back(FlagInfo);
    }

    // If flags dialog, we can also have a custom value
    if(pData->bIsValuesDialog == false && dwCustomValue != 0)
    {
        FlagList.push_back(TDlgFlagInfo(pData->szCustomValue, dwCustomValue, dwCustomValue, BS_AUTOCHECKBOX));
        LoadStringA(g_hInst, IDS_CUSTOM_VALUE, pData->szCustomValue, _countof(pData->szCustomValue));
    }

    return FlagList.size();
}

static HWND CreateButtonItem(
    TFlagDialogData * pData,
    TDlgFlagInfo & FlagInfo,
    size_t nButton,
    HWND hWndChild)
{
    // Calculate position of the button
    int x = pData->xButton + (int)((nButton / pData->nColumn1) * (pData->cxButton + pData->cxSpace));
    int y = pData->yButton + (int)((nButton % pData->nColumn1) * (pData->cyButton + pData->cySpace));

    // Do we already have a child?
    if(hWndChild == NULL)
    {
        // Shall we create a separator?
        if(!FlagInfo.IsSeparator())
        {
            // Create the checkbox
            hWndChild = CreateWindowEx(pData->dwExStyle,
                                       WC_BUTTON,
                                       NULL,
                                       pData->dwStyle | FlagInfo.dwButtonType | WS_VISIBLE,
                                       x,
                                       y,
                                       pData->cxButton,
                                       pData->cyButton,
                                       pData->hDlg,
                                       0,
                                       g_hInst,
                                       NULL);
        }
        else
        {
            hWndChild = CreateWindowEx(WS_EX_LEFT | WS_EX_NOPARENTNOTIFY,
                                       WC_STATIC,
                                       NULL,
                                       WS_CHILD | WS_VISIBLE | SS_SUNKEN,
                                       x,
                                       y + (pData->cyButton - 3) / 2,
                                       pData->cxButton,
                                       3,
                                       pData->hDlg,
                                       0,
                                       g_hInst,
                                       NULL);
        }

        // Set the checkbox's Z-order after the previous one
        SetWindowPos(hWndChild, pData->hWndPrev, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        SendMessage(hWndChild, WM_SETFONT, (WPARAM)pData->hFont, FALSE);
    }
    else
    {
        // Set the child type to radio button, if needed
        SetWindowLong(hWndChild, GWL_STYLE, pData->dwStyle | FlagInfo.dwButtonType | WS_VISIBLE | WS_GROUP | WS_TABSTOP);
    }

    // Set the button text and user data, if not a separator
    if(!FlagInfo.IsSeparator())
    {
        char szItemText[256];

        // Set the pointer to the flag info
        SetWindowLongPtr(hWndChild, GWLP_USERDATA, (LONG_PTR)(&FlagInfo));

        // Set the window text
        StringCchPrintfA(szItemText, _countof(szItemText), "(%08X) %s", FlagInfo.dwValue, FlagInfo.szFlagText);
        SetWindowTextA(hWndChild, szItemText);
    }

    // Remember the child window for the next time
    pData->hWndPrev = hWndChild;
    return hWndChild;
}

static void ArrangeDialogButton(TFlagDialogData * pData, UINT nIDButton, int y, int width)
{
    HWND hWndChild;
    HWND hDlg = pData->hDlg;
    RECT rect;
    UINT uFlags = SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE;
    int x;

    // Retrieve handle to the child window
    if((hWndChild = GetDlgItem(hDlg, nIDButton)) != NULL)
    {
        // Retrieve the child rect of the button
        GetWindowRect(hWndChild, &rect);
        ScreenRectToClientRect(hDlg, &rect);
        x = rect.left;

        // OK button is always visible and on the right side of the dialog
        if(nIDButton == IDOK)
            x = width - (rect.right - rect.left);
        if(pData->bIsValuesDialog)
            uFlags = uFlags | ((nIDButton != IDOK) ? SWP_HIDEWINDOW : 0);

        // Move the button
        SetWindowPos(hWndChild, NULL, x, y, 0, 0, uFlags);
    }
}

// Arranging the dialog layout for empty dialogs, where the controls need to be created
static void CreateDialogLayout(TFlagDialogData * pData)
{
    HWND hWndFirst = GetDlgItem(pData->hDlg, IDC_CHILD_MUSTER);
    HWND hWndChild = hWndFirst;
    HWND hWndGroup;
    RECT DialogRect;                        // Rectangle of the dialog (screen-relative)
    RECT ParentRect;                        // Rectangle of the dialog's parent (screen-relative)
    RECT ClientRect;                        // Rectangle of the dialog client area (screen-relative)
    RECT GroupRect;                         // Rectangle of the group box
    RECT CheckBoxRect;                      // Rectangle of the checkbox
    size_t dwFlagCount;
    DWORD dwFlags = pData->dwBitMask;
    int cxAllButtons;
    int cyAllButtons;
    int nChecked = BST_UNCHECKED;
    int xButtons;
    int yButtons;
    int cxGroup = 0;
    int cyGroup = 0;
    int x, y, cx, cy;

    // Get the size of the parent
    if(pData->hWndParent == NULL)
        SystemParametersInfo(SPI_GETWORKAREA, 0, &ParentRect, FALSE);
    else
        GetWindowRect(pData->hWndParent, &ParentRect);

    // Set the dialog title
    SetWindowTextRc(pData->hDlg, pData->nIDTitle);

    // Get the size of the dialog and the "master" settings
    GetWindowRect(pData->hDlg, &DialogRect);
    GetClientRect(pData->hDlg, &ClientRect);
    ClientRectToScreenRect(pData->hDlg, &ClientRect);

    // Remember the group position
    if((hWndGroup = GetDlgItem(pData->hDlg, IDC_GROUPBOX)) != NULL)
    {
        GetWindowRect(hWndGroup, &GroupRect);
        pData->xGroup = (GroupRect.left - ClientRect.left);
        pData->yGroup = (GroupRect.top - ClientRect.top);
    }

    // Calculate button position
    GetWindowRect(hWndChild, &CheckBoxRect);
    pData->xButton  = (CheckBoxRect.left - ClientRect.left);
    pData->yButton  = (CheckBoxRect.top - ClientRect.top);
    pData->cxButton = (CheckBoxRect.right - CheckBoxRect.left);
    pData->cyButton = (CheckBoxRect.bottom - CheckBoxRect.top);
    pData->cxSpace = pData->cyButton;
    pData->cySpace = 6;

    // Get the settings of the "master" checkbox
    pData->hFont = (HFONT)SendMessage(hWndChild, WM_GETFONT, 0, 0);
    pData->dwExStyle = GetWindowLong(hWndChild, GWL_EXSTYLE);
    pData->dwStyle = GetWindowLong(hWndChild, GWL_STYLE) & ~(WS_TABSTOP | WS_GROUP | BS_TYPEMASK);

    // Get the button types
    dwFlagCount = BuildFlagList(pData);

    // If 20 flags or more, we split the dialog into more columns
    pData->nColumn1 = pData->FlagList.size();
    pData->nColumns = 1;
    while(pData->nColumn1 > 23)
    {
        pData->nColumns++;
        pData->nColumn1 = (dwFlagCount / pData->nColumns) + ((dwFlagCount % pData->nColumns) ? 1 : 0);
    }

    // Create all switch items
    for(size_t nButton = 0; nButton < pData->FlagList.size(); nButton++)
    {
        TDlgFlagInfo & FlagInfo = pData->FlagList[nButton];

        // Create the (next) switch item
        hWndChild = CreateButtonItem(pData, FlagInfo, nButton, hWndChild);

        // Check/uncheck the box
        if(!FlagInfo.IsSeparator())
        {
            nChecked = FlagInfo.IsValuePresent(dwFlags) ? BST_CHECKED : BST_UNCHECKED;
            if(nChecked == BST_CHECKED)
                dwFlags = dwFlags & ~FlagInfo.dwMask;
            Button_SetCheck(hWndChild, nChecked);
        }

        // The next control will be created dynamically, 6 dialog units lower
        hWndChild = NULL;
    }

    // Calculate the size of the entire button area
    cxAllButtons = (int)((pData->nColumns * pData->cxButton) + ((pData->nColumns - 1) * pData->cxSpace));
    cyAllButtons = (int)((pData->nColumn1 * pData->cyButton) + ((pData->nColumn1 - 1) * pData->cySpace));

    // Resize the group frame, if any
    if(hWndGroup != NULL)
    {
        cxGroup = (pData->xButton - pData->xGroup) + cxAllButtons + (pData->xButton - pData->xGroup);
        cyGroup = (pData->yButton - pData->yGroup) + cyAllButtons + (pData->yButton - pData->yGroup);
        SetWindowPos(hWndGroup, NULL, pData->xGroup, pData->yGroup, cxGroup, cyGroup, SWP_NOZORDER | SWP_NOACTIVATE);
    }

    // Arrange the buttons
    xButtons = pData->xButton + cxAllButtons + pData->xButton;
    yButtons = pData->yButton + cyAllButtons + pData->yButton;
    ArrangeDialogButton(pData, IDC_SELECT_ALL, yButtons, pData->xGroup + cxGroup);
    ArrangeDialogButton(pData, IDC_CLEAR_ALL,  yButtons, pData->xGroup + cxGroup);
    ArrangeDialogButton(pData, IDOK,           yButtons, pData->xGroup + cxGroup);

    // Resize and center the dialog
    cx = (DialogRect.right - DialogRect.left) - (ClientRect.right - ClientRect.left) + xButtons;
    cy = (DialogRect.bottom - DialogRect.top) - (ClientRect.bottom - ClientRect.top) + yButtons + pData->yButton + pData->yGroup;
    x = ParentRect.left + ((ParentRect.right - ParentRect.left) - cx) / 2;
    y = ParentRect.top + ((ParentRect.bottom - ParentRect.top) - cy) / 2;
    SetWindowPos(pData->hDlg, NULL, x, y, cx, cy, SWP_NOZORDER | SWP_NOACTIVATE);
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
    if(pFlags != NULL && Button_GetCheck(hWndChild) == BST_CHECKED)
    {
        pData->dwBitMask = (pData->dwBitMask & ~pFlags->dwMask) | pFlags->dwValue;
    }
}

//-----------------------------------------------------------------------------
// Dialog handlers

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    TFlagDialogData * pData = (TFlagDialogData *)lParam;

    // Configure the dialog
    SetDialogIcon(hDlg, IDI_FILE_TEST);
    SetDialogData(hDlg, lParam);
    pData->hDlg = hDlg;

    // Create the layout and clear the bit flags
    CreateDialogLayout(pData);
    pData->dwBitMask = 0;
    return TRUE;
}

static void OnEnumAllButtons(HWND hDlg, CHILD_WINDOW_CALLBACK ChildCallback)
{
    TFlagDialogData * pData = (TFlagDialogData *)GetWindowLongPtr(hDlg, DWLP_USER);
    TDlgFlagInfo * pFlags;
    DWORD dwButtonType;
    DWORD dwStyles;
    HWND hWndChild;

    // Enumerate all children. For checkboxes and radio buttons, call the given callback
    for(hWndChild = GetWindow(hDlg, GW_CHILD); hWndChild != NULL; hWndChild = GetWindow(hWndChild, GW_HWNDNEXT))
    {
        // Retrieve child window styles and button type
        dwStyles = GetWindowLong(hWndChild, GWL_STYLE);
        dwButtonType = dwStyles & BS_TYPEMASK;

        // Is that a check box or a radio button?
        if(dwButtonType == BS_AUTOCHECKBOX || dwButtonType == BS_AUTORADIOBUTTON)
        {
            // Retrieve flag info structure the button
            pFlags = (TDlgFlagInfo *)GetWindowLongPtr(hWndChild, GWLP_USERDATA);
            if(pFlags != NULL)
            {
                // Call the for-each callback
                ChildCallback(pData, pFlags, hWndChild, dwStyles);
            }
        }
    }
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
                    OnEnumAllButtons(hDlg, Callback_SetCheck);
                    break;

                case IDC_CLEAR_ALL:
                    OnEnumAllButtons(hDlg, Callback_ClearCheck);
                    break;

                case IDOK:
                    OnEnumAllButtons(hDlg, Callback_SaveFlag);
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

INT_PTR FlagsDialog(HWND hWndParent, UINT nIDTitle, TFlagInfo * pFlags, DWORD & dwBitMask)
{
    TFlagDialogData fdd;
    INT_PTR Result;

    // Retrieve the flags
    fdd.hWndParent = hWndParent;
    fdd.pFlags     = pFlags;
    fdd.dwBitMask  = dwBitMask;
    fdd.nIDTitle   = nIDTitle;

    // Execute the dialog
    Result = DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_FLAGS_DIALOG), hWndParent, DialogProc, (LPARAM)&fdd);
    dwBitMask = fdd.dwBitMask;
    return Result;
}

INT_PTR FlagsDialog_OnControl(HWND hWndParent, UINT nIDTitle, TFlagInfo * pFlags, UINT nIDCtrl)
{
    INT_PTR Result = IDCANCEL;
    DWORD dwBitMask = 0;

    // Read the flags from the item
    if(DlgText2Hex32(hWndParent, nIDCtrl, &dwBitMask) == ERROR_SUCCESS)
    {
        // Invoke the dialog
        Result = FlagsDialog(hWndParent, nIDTitle, pFlags, dwBitMask);
        if(Result == IDOK)
        {
            Hex2DlgText32(hWndParent, nIDCtrl, dwBitMask);
        }
    }
    return Result;
}

