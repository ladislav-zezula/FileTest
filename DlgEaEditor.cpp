/*****************************************************************************/
/* DlgEaEditor.cpp                        Copyright (c) Ladislav Zezula 2005 */
/*---------------------------------------------------------------------------*/
/* Description :                                                             */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 16.08.05  1.00  Lad  The first version of DlgEaEditor.cpp                 */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local functions

static int nChangingEdit = 0;

static DWORD TwoDigitsToBinValue(LPCTSTR szBinValue)
{
    TCHAR chDigit1;
    TCHAR chDigit2;

    // Verify the digits
    if(!isxdigit(szBinValue[0]) || !isxdigit(szBinValue[1]))
        return (DWORD)0x100;

    chDigit2 = (TCHAR)CharUpper((LPTSTR)szBinValue[0]);
    chDigit1 = (TCHAR)CharUpper((LPTSTR)szBinValue[1]);
    if(chDigit1 > '9')
        chDigit1 -= 'A' - '9' - 1;
    if(chDigit2 > '9')
        chDigit2 -= 'A' - '9' - 1;

    return ((chDigit2 - '0') << 0x04) | (chDigit1 - '0');
}

static int CTextToBinArray(LPTSTR szTextValue, LPBYTE pbBinValue)
{
    DWORD dwBinValue;
    int nLength = 0;

    while(*szTextValue != 0)
    {
        if(*szTextValue == _T('\\'))
        {
            szTextValue++;
            switch(*szTextValue)
            {
                case _T('\\'):
                    *pbBinValue = '\\'; 
                    break;

                case _T('x'):
                case _T('X'):
                    szTextValue++;
                    dwBinValue = TwoDigitsToBinValue(szTextValue);
                    if(dwBinValue == 0x0100)
                        return -1;

                    *pbBinValue = (BYTE)dwBinValue;
                    szTextValue++;
                    break;
            }
        }
        else
            *pbBinValue = (BYTE)(*szTextValue);

        szTextValue++;
        pbBinValue++;
        nLength++;
    }

    return nLength;
}

static int BinTextToBinArray(LPTSTR szBinValue, LPBYTE pbBinValue)
{
    DWORD dwBinValue;
    int nLength = 0;

    while(*szBinValue != 0)
    {
        // Skip spaces
        while(0 < *szBinValue && *szBinValue <= 0x20)
            szBinValue++;

        dwBinValue = TwoDigitsToBinValue(szBinValue);
        if(dwBinValue == 0x0100)
            return -1;

        *pbBinValue++ = (BYTE)dwBinValue;
        szBinValue += 2;
        nLength++;

        // Must be a space there
        if(*szBinValue > 0x20)
            return -1;

        // Skip spaces
        while(0 < *szBinValue && *szBinValue <= 0x20)
            szBinValue++;
    }

    return nLength;
}

static int BinArrayToBinText(LPBYTE pbBinValue, int nBinLength, LPTSTR szBinValue)
{
    *szBinValue = 0;
    for(int i = 0; i < nBinLength; i++, pbBinValue++)
        szBinValue += _stprintf(szBinValue, _T("%02lX "), (*pbBinValue & 0x000000FF));

    return nBinLength;
}

static int BinArrayToCText(LPBYTE pbBinValue, int nBinLength, LPTSTR szTextValue)
{
    for(int i = 0; i < nBinLength; i++, pbBinValue++)
    {
        if(*pbBinValue == '\\')
        {
            szTextValue += _stprintf(szTextValue, _T("\\\\"));
        }
        else if(0x20 <= *pbBinValue && *pbBinValue < 0x80)
        {
            *szTextValue++ = (TCHAR)*pbBinValue;
        }
        else
        {
            szTextValue += _stprintf(szTextValue, _T("\\x%02lX"), (*pbBinValue & 0x000000FF));
        }
    }

    *szTextValue = 0;
    return nBinLength;
}


static void UpdateDialog(HWND hDlg)
{
    BOOL bEnable;

    nChangingEdit++;

    bEnable = (IsDlgButtonChecked(hDlg, IDC_RADIO1) == BST_CHECKED);
    EnableWindow(GetDlgItem(hDlg, IDC_DATA_VALUE_TEXT), bEnable);

    bEnable = (IsDlgButtonChecked(hDlg, IDC_RADIO2) == BST_CHECKED);
    EnableWindow(GetDlgItem(hDlg, IDC_DATA_VALUE_BIN), bEnable);

    nChangingEdit--;
}


static void SetDlgItemCText(HWND hDlg, UINT nIDCtrl, LPBYTE pbData, int nLength)
{
    LPTSTR szBinText;

    szBinText = new TCHAR[nLength * 4 + 1];
    if(szBinText != NULL)
    {
        BinArrayToCText(pbData, nLength, szBinText);
        SetDlgItemText(hDlg, nIDCtrl, szBinText);
        delete [] szBinText;
    }
}


static void SetDlgItemBin(HWND hDlg, UINT nIDCtrl, LPBYTE pbData, int nLength)
{
    LPTSTR szBinText = new TCHAR [nLength * 4 + 1];

    if(szBinText != NULL)
    {
        BinArrayToBinText(pbData, nLength, szBinText);
        SetDlgItemText(hDlg, nIDCtrl, szBinText);
        delete [] szBinText;
    }
}

// Text value has changed
static int UpdateEaValueBin(HWND hDlg)
{
    LPTSTR szTextValue;
    LPTSTR szBinValue;
    LPBYTE pbBinValue;
    HWND hSrcEdit = GetDlgItem(hDlg, IDC_DATA_VALUE_TEXT);
    HWND hTrgEdit = GetDlgItem(hDlg, IDC_DATA_VALUE_BIN);
    int nTextLength = GetWindowTextLength(hSrcEdit);
    int nBinLength;

    szTextValue = new TCHAR[nTextLength + 1];
    szBinValue = new TCHAR[nTextLength * 3 + 1];
    pbBinValue = new BYTE[nTextLength + 1];
    GetWindowText(hSrcEdit, szTextValue, nTextLength + 1);

    // Process the binary buffer and convert it to the binary data
    nChangingEdit++;
    nBinLength = CTextToBinArray(szTextValue, pbBinValue);
    if(nBinLength != -1)
    {
        BinArrayToBinText(pbBinValue, nBinLength, szBinValue);
        SetWindowText(hTrgEdit, szBinValue);
    }
    else
        SetWindowTextRc(hTrgEdit, IDS_CONVERSION_ERROR);
    nChangingEdit--;

    delete [] pbBinValue;
    delete [] szBinValue;
    delete [] szTextValue;
    return TRUE;
}

// Binary value has changed
static int UpdateEaValueText(HWND hDlg)
{
    LPTSTR szTextValue;
    LPTSTR szBinValue;
    LPBYTE pbBinValue;
    HWND hSrcEdit = GetDlgItem(hDlg, IDC_DATA_VALUE_BIN);
    HWND hTrgEdit = GetDlgItem(hDlg, IDC_DATA_VALUE_TEXT);
    int nTextLength = GetWindowTextLength(hSrcEdit);
    int nBinLength;

    szTextValue = new TCHAR[nTextLength * 4 + 1];
    szBinValue = new TCHAR[nTextLength + 1];
    pbBinValue = new BYTE[nTextLength + 1];
    GetWindowText(hSrcEdit, szBinValue, nTextLength + 1);
    _tcsupr(szBinValue);

    // Process the binary buffer and convert it to the binary data
    nChangingEdit++;
    nBinLength = BinTextToBinArray(szBinValue, pbBinValue);
    if(nBinLength != -1)
    {
        BinArrayToCText(pbBinValue, nBinLength, szTextValue);
        SetWindowText(hTrgEdit, szTextValue);
    }
    else
        SetWindowTextRc(hTrgEdit, IDS_CONVERSION_ERROR);
    nChangingEdit--;

    delete [] pbBinValue;
    delete [] szBinValue;
    delete [] szTextValue;
    return TRUE;
}

//-----------------------------------------------------------------------------
// Dialog handlers

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    PFILE_FULL_EA_INFORMATION * ppEaItem = (PFILE_FULL_EA_INFORMATION *)lParam;
    PFILE_FULL_EA_INFORMATION pEaItem = *ppEaItem;
    HWND hWndChild;

    // Configure the dialog
    SetWindowLongPtr(hDlg, DWLP_USER, lParam);
    SetDialogIcon(hDlg, IDI_FILE_TEST);
    CenterWindowToParent(hDlg);

    // Set the dialog title to "Insert" or to "Edit"
    SetWindowTextRc(hDlg, pEaItem ? IDS_EDIT_EA_TITLE : IDS_INSERT_EA_TITLE);

    // Set the name and value limit
    hWndChild = GetDlgItem(hDlg, IDC_DATA_NAME);
    if(hWndChild != NULL)
        Edit_LimitText(hWndChild, (BYTE)-1);

    // Fill the dialog
    nChangingEdit++;
    CheckDlgButton(hDlg, IDC_RADIO1, BST_CHECKED);
    if(pEaItem != NULL)
    {
        if(hWndChild != NULL)
            SetWindowTextA(hWndChild, pEaItem->EaName);

        SetDlgItemCText(hDlg,
                        IDC_DATA_VALUE_TEXT,
                (LPBYTE)pEaItem->EaName + pEaItem->EaNameLength + 1,
                        pEaItem->EaValueLength);

        SetDlgItemBin(hDlg,
                      IDC_DATA_VALUE_BIN,
              (LPBYTE)pEaItem->EaName + pEaItem->EaNameLength + 1,
                      pEaItem->EaValueLength);
    }
    UpdateDialog(hDlg);
    nChangingEdit--;

    return TRUE;
}

static BOOL OnSaveDialog(HWND hDlg)
{
    PFILE_FULL_EA_INFORMATION * ppEaItem = (PFILE_FULL_EA_INFORMATION *)GetWindowLongPtr(hDlg, DWLP_USER);
    PFILE_FULL_EA_INFORMATION NewEaItem = NULL;
    PFILE_FULL_EA_INFORMATION OldEaItem = *ppEaItem;
    LPTSTR szBinBuffer = NULL;
    HWND hWndName = GetDlgItem(hDlg, IDC_DATA_NAME);
    HWND hWndValue = GetDlgItem(hDlg, IDC_DATA_VALUE_BIN);
    int nTotalLength;
    int nValueLength = GetWindowTextLength(hWndValue);
    int nNameLength = 0;

    if(hWndName != NULL)
    {
        // Retrieve the name length
        nNameLength = GetWindowTextLength(hWndName);
        if(nNameLength == 0)
        {
            // Don't accept empty name
            MessageBoxRc(hDlg, IDS_ERROR, IDS_NO_EA_NAME);
            SetFocus(hWndName);
            return FALSE;
        }

        // Make sure that the name length is not bigger than 255
        if(nNameLength > 255)
            nNameLength = 255;
    }

    // Create new EA entry
    nTotalLength = sizeof(FILE_FULL_EA_INFORMATION) + nNameLength + nValueLength + 2;
    szBinBuffer = new TCHAR[nValueLength + 1];
    NewEaItem = (PFILE_FULL_EA_INFORMATION)(new char[nTotalLength]);

    // Initialize the EA entry
    ZeroMemory(NewEaItem, nTotalLength);

    // Fill the name and value
    if(hWndName != NULL)
        GetWindowTextA(hWndName, NewEaItem->EaName, nNameLength + 1);
    NewEaItem->EaNameLength = (UCHAR)nNameLength;

    GetWindowText(hWndValue, szBinBuffer, nValueLength + 1);
    NewEaItem->EaValueLength = (USHORT)BinTextToBinArray(szBinBuffer,
                                                 (LPBYTE)NewEaItem->EaName + NewEaItem->EaNameLength + 1);
    if(NewEaItem->EaValueLength == (USHORT)-1)
    {
        MessageBoxRc(hDlg, IDS_ERROR, IDS_CONVERSION_ERROR_MSG);
        delete [] szBinBuffer;
        delete [] NewEaItem;
        return FALSE;
    }

    // Set the correct length of the EA item
    NewEaItem->NextEntryOffset = GetEaEntrySize(NewEaItem);

    // Replace the item
    if(OldEaItem != NULL)
        delete OldEaItem;
    *ppEaItem = NewEaItem;
    delete [] szBinBuffer;
    return TRUE;
}

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    if(nNotify == BN_CLICKED)
    {
        switch(nIDCtrl)
        {
            case IDC_RADIO1:
                UpdateDialog(hDlg);
                SetFocus(GetDlgItem(hDlg, IDC_DATA_VALUE_TEXT));
                return TRUE;

            case IDC_RADIO2:
                UpdateDialog(hDlg);
                SetFocus(GetDlgItem(hDlg, IDC_DATA_VALUE_BIN));
                return TRUE;

            case IDOK:
                if(OnSaveDialog(hDlg) == FALSE)
                    return TRUE;
                // No break here !!

            case IDCANCEL:
                EndDialog(hDlg, nIDCtrl);
                break;
        }
    }

    if(nNotify == EN_CHANGE && nChangingEdit == 0)
    {
        switch(nIDCtrl)
        {
            case IDC_DATA_VALUE_BIN:
                return UpdateEaValueText(hDlg);

            case IDC_DATA_VALUE_TEXT:
                return UpdateEaValueBin(hDlg);
        }
    }

    return FALSE;
}

static INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // Dialog initialization
    if(uMsg == WM_INITDIALOG)
        return OnInitDialog(hDlg, lParam);

    if(uMsg == WM_COMMAND)
        return OnCommand(hDlg, HIWORD(wParam), LOWORD(wParam));

    return FALSE;
}
                                 
INT_PTR EaEditorDialog(HWND hParent, PFILE_FULL_EA_INFORMATION * ppEaItem)
{
    return DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_EA_EDITOR), hParent, DialogProc, (LPARAM)ppEaItem);
}
