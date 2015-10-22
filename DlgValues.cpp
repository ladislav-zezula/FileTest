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
// Dialog handlers

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    TFlagDialogData * pData = (TFlagDialogData *)lParam;
    TFlagInfo * pFlags = pData->pFlags;
    HWND hCombo = GetDlgItem(hDlg, IDC_VALUES);
    int nSelect = -1;
    int nIndex;

    // Configure the dialog
    SetDialogData(hDlg, lParam);
    SetDialogIcon(hDlg, IDI_FILE_TEST);
    SetWindowTextRc(hDlg, pData->nIDTitle);

    // Load the combo box
    for(int i = 0; pFlags->szFlagText != NULL; i++, pFlags++)
    {
        nIndex = ComboBox_AddString(hCombo, pFlags->szFlagText);
        ComboBox_SetItemData(hCombo, nIndex, pFlags->dwValue);

        if(IS_FLAG_SET(pFlags, pData->dwFlags))
            nSelect = nIndex;
    }

    // Set the proper value
    ComboBox_SetCurSel(hCombo, nSelect);
    
    // Center the window to its parent
    CenterWindowToParent(hDlg);
    return TRUE;
}

static int OnSaveDialog(HWND hDlg)
{
    TFlagDialogData * pData = (TFlagDialogData *)GetWindowLongPtr(hDlg, DWLP_USER);
    HWND hCombo = GetDlgItem(hDlg, IDC_VALUES);
    int nIndex = ComboBox_GetCurSel(hCombo);

    pData->dwFlags = (DWORD)ComboBox_GetItemData(hCombo, nIndex);
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
                                 
INT_PTR ValuesDialog(HWND hWndParent, PDWORD pdwValue, UINT nIDTitle, TFlagInfo * pFlags)
{
    TFlagDialogData fdd;
    INT_PTR Result;

    // Prepare the flags dialog
    ZeroMemory(&fdd, sizeof(TFlagDialogData));
    fdd.pFlags   = pFlags;
    fdd.hParent  = hWndParent;
    fdd.nIDTitle = nIDTitle;
    fdd.dwFlags  = *pdwValue;
    
    Result = DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_VALUES_DIALOG), hWndParent, DialogProc, (LPARAM)&fdd);
    if(Result == IDOK)
        *pdwValue = fdd.dwFlags;
        
    return Result;
}
