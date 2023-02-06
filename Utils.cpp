/*****************************************************************************/
/* Utils.cpp                              Copyright (c) Ladislav Zezula 2004 */
/*---------------------------------------------------------------------------*/
/* Description:                                                              */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 05.01.04  1.00  Lad  The first version of Utils.cpp                       */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// _tcstol replacement

static BYTE CharToValue[0x80] =
{
//   00    01    02    03    04    05    06    07    08    09    0A    0B    0C    0D    0E    0F
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
};

static TCHAR ValueToChar[] = _T("0123456789ABCDEF");

static inline LPCTSTR SkipHexaPrefix(LPCTSTR szString)
{
    return (szString[0] == _T('0') && (szString[1] == _T('x') || szString[1] == _T('X'))) ? szString + 2 : szString;
}

static void Hex2TextXX(ULONGLONG Value, LPTSTR szBuffer, int nSize)
{
    // Get the number of hexa digits
    nSize = nSize + nSize - 1;
    
    // Convert the number to string
    for(int i = 0; i <= nSize; i++)
    {
        szBuffer[nSize - i] = ValueToChar[Value & 0x0F];
        Value >>= 4;
    }
    
    // Terminate the string
    szBuffer[nSize + 1] = 0;
}

static bool IsPossibleFileId(LPCTSTR szFileName)
{
    size_t nLength = _tcslen(szFileName);
                     
    // File ID has 15 characters, object ID has 32
    if(nLength != 16 && nLength != 32)
        return false;

    // File ID can only contain hexadecimal letters
    for(size_t i = 0; i < nLength; i++)
    {
        if(!isxdigit(szFileName[i]))
            return false;
    }

    // All checks passed. It could be a file ID
    return true;
}

static void ShowConversionError(HWND hWndParent, HWND hWndChild)
{
    // Show the error to the user
    MessageBoxRc(hWndParent, IDS_ERROR, IDS_E_CONVERT_VALUE);

    // Select and focus the control
    SendMessage(hWndChild, EM_SETSEL, 0, (LPARAM)-1);
    SetFocus(hWndChild);
}

//-----------------------------------------------------------------------------
// Converts the string to long. This function was written because
// the builtin strtol does not work correctly (try to convert 0xAABBCCDD !!!)

DWORD StrToInt(LPCTSTR szString, LPTSTR * szEnd, int nRadix)
{
    DWORD nSaveValue = 0;
    DWORD nValue = 0;
    int nDigit;

    while((nDigit = szString[0]) != 0)
    {
        // If the character is not an hexa number, break
        if(nDigit > 0x80 || CharToValue[nDigit] == 0xFF)
            break;

        // Convert to digit
        nDigit = CharToValue[nDigit];
        if(nDigit > (nRadix - 1))
            break;

        // Move the value to the next rank and add the digit
        nSaveValue = nValue;
        nValue *= nRadix;
        nValue += nDigit;
        szString++;

        // Overflow check
        if(nValue < nSaveValue)
            break;
    }
    
    if(szEnd != NULL)
        *szEnd = (LPTSTR)szString;
    return nValue;
}

//-----------------------------------------------------------------------------
// bool values support

int Text2Bool(LPCTSTR szText, bool * pValue)
{
    bool bNewValue = false;

    if(_tcsicmp(szText, _T("true")))
        bNewValue = true;
    else if(_tcsicmp(szText, _T("on")))
        bNewValue = true;
    else if(_tcsicmp(szText, _T("1")))
        bNewValue = true;

    pValue[0] = bNewValue;
    return ERROR_SUCCESS;
}

//-----------------------------------------------------------------------------
// 32-bit values support

int Text2Hex32(LPCTSTR szText, PDWORD pValue)
{
    DWORD Value = 0;
    int nDigit;

    // Skip the C-style hexa prefix, if any
    szText = SkipHexaPrefix(szText);

    // Convert the value
    while((nDigit = *szText++) != 0)
    {
        // If the character is not a hexa number, break
        if(nDigit > 0x80 || CharToValue[nDigit] == 0xFF)
            return ERROR_BAD_FORMAT;

        // Convert to digit
        nDigit = CharToValue[nDigit];

        // Overflow check
        if(Value & 0xF0000000)
            return ERROR_ARITHMETIC_OVERFLOW;
        Value = (Value << 0x04) + nDigit;
    }

    // Give the value to the caller
    *pValue = Value;
    return ERROR_SUCCESS;
}

int DlgText2Hex32(HWND hDlg, UINT nIDCtrl, PDWORD pValue)
{
    TCHAR szText[128];
    HWND hWndChild = GetDlgItem(hDlg, nIDCtrl);
    DWORD dwErrCode = ERROR_INVALID_PARAMETER;

    // Perform the conversion of the child text to a 32-bit hexa value
    if(hWndChild != NULL)
    {
        // Retrieve the window text
        GetWindowText(hWndChild, szText, _countof(szText));
    
        // Attempt to convert the value
        dwErrCode = Text2Hex32(szText, pValue);
        if(dwErrCode != ERROR_SUCCESS)
            ShowConversionError(hDlg, hWndChild);
    }

    return dwErrCode;
}

void Hex2Text32(LPTSTR szBuffer, DWORD Value)
{
    Hex2TextXX(Value, szBuffer, sizeof(DWORD));
}

void Hex2DlgText32(HWND hDlg, UINT nIDCtrl, DWORD Value)
{
    TCHAR szText[128];

    Hex2TextXX(Value, szText, sizeof(DWORD));
    SetDlgItemText(hDlg, nIDCtrl, szText);
}

//-----------------------------------------------------------------------------
// Pointer support

int Text2HexPtr(LPCTSTR szText, PDWORD_PTR pValue)
{
    DWORD_PTR ValueMask = ((DWORD_PTR)0x0F << ((sizeof(DWORD_PTR) * 8) - 4));
    DWORD_PTR Value = 0;
    int nDigit;

    // Skip the C-style hexa prefix, if any
    szText = SkipHexaPrefix(szText);

    // Convert the value
    while((nDigit = *szText++) != 0)
    {
        // If the character is not a hexa number, break
        if(nDigit > 0x80 || CharToValue[nDigit] == 0xFF)
            return ERROR_BAD_FORMAT;

        // Convert to digit
        nDigit = CharToValue[nDigit];

        // Overflow check
        if(Value & ValueMask)
            return ERROR_ARITHMETIC_OVERFLOW;
        Value = (Value << 0x04) + nDigit;

    }

    // Give the value to the caller
    *pValue = Value;
    return ERROR_SUCCESS;
}

int DlgText2HexPtr(HWND hDlg, UINT nIDCtrl, PDWORD_PTR pValue)
{
    TCHAR szText[128];
    HWND hWndChild = GetDlgItem(hDlg, nIDCtrl);
    DWORD dwErrCode = ERROR_INVALID_PARAMETER;

    // Perform the conversion of the child text to a 32-bit hexa value
    if(hWndChild != NULL)
    {
        // Retrieve the window text
        GetWindowText(hWndChild, szText, _countof(szText));
    
        // Attempt to convert the value
        dwErrCode = Text2HexPtr(szText, pValue);
        if(dwErrCode != ERROR_SUCCESS)
            ShowConversionError(hDlg, hWndChild);
    }

    return dwErrCode;
}

void Hex2TextPtr(LPTSTR szBuffer, DWORD_PTR Value)
{
    Hex2TextXX(Value, szBuffer, sizeof(DWORD_PTR));
}

void Hex2DlgTextPtr(HWND hDlg, UINT nIDCtrl, DWORD_PTR Value)
{
    TCHAR szText[128];

    Hex2TextXX(Value, szText, sizeof(DWORD_PTR));
    SetDlgItemText(hDlg, nIDCtrl, szText);
}

//-----------------------------------------------------------------------------
// 64-bit values support

int Text2Hex64(LPCTSTR szText, PLONGLONG pValue)
{
    ULONGLONG SaveValue = 0;
    ULONGLONG Value = 0;
    int nDigit;

    // Skip the C-style hexa prefix, if any
    szText = SkipHexaPrefix(szText);

    // Convert the value
    while((nDigit = *szText++) != 0)
    {
        // If the character is not a hexa number, break
        if(nDigit > 0x80 || CharToValue[nDigit] == 0xFF)
            return ERROR_BAD_FORMAT;

        // Convert to digit
        nDigit = CharToValue[nDigit];

        // Move the value to the next rank and add the digit
        SaveValue = Value;
        Value = (Value << 0x04) + nDigit;

        // Overflow check
        if(Value < SaveValue)
            return ERROR_ARITHMETIC_OVERFLOW;
    }

    // Give the value to the caller
    *pValue = Value;
    return ERROR_SUCCESS;
}

int DlgText2Hex64(HWND hDlg, UINT nIDCtrl, PLONGLONG pValue)
{
    TCHAR szText[128];
    HWND hWndChild = GetDlgItem(hDlg, nIDCtrl);
    DWORD dwErrCode = ERROR_INVALID_PARAMETER;

    // Perform the conversion of the child text to a 32-bit hexa value
    if(hWndChild != NULL)
    {
        // Retrieve the window text
        GetWindowText(hWndChild, szText, _countof(szText));
    
        // Attempt to convert the value
        dwErrCode = Text2Hex64(szText, pValue);
        if(dwErrCode != ERROR_SUCCESS)
            ShowConversionError(hDlg, hWndChild);
    }

    return dwErrCode;
}

void Hex2Text64(LPTSTR szBuffer, LONGLONG Value)
{
    Hex2TextXX(Value, szBuffer, sizeof(LONGLONG));
}

void Hex2DlgText64(HWND hDlg, UINT nIDCtrl, LONGLONG Value)
{
    TCHAR szText[128];

    Hex2TextXX(Value, szText, sizeof(LONGLONG));
    SetDlgItemText(hDlg, nIDCtrl, szText);
}

//-----------------------------------------------------------------------------
// Clipboard manipulation

HGLOBAL Clipboard_AddText(HGLOBAL hMemory, LPCTSTR szText)
{
    LPBYTE pbClipboard;
    size_t cbTotalSize;
    size_t cbPrevSize = 0;
    size_t cbAddSize = _tcslen(szText) * sizeof(TCHAR);

    // If we don't have any previousle allocated memory, then allocate new block
    if(hMemory == NULL)
    {
        // Allocate text plus EOS
        cbTotalSize = cbAddSize + sizeof(WCHAR);
        hMemory = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, cbTotalSize);
    }
    else
    {
        // Find out the previous size of the memory
        cbPrevSize = GlobalSize(hMemory);
        cbTotalSize = cbPrevSize + cbAddSize;
        hMemory = GlobalReAlloc(hMemory, cbTotalSize, GMEM_MOVEABLE | GMEM_ZEROINIT);

        // Subtract the end-of-string
        cbPrevSize -= sizeof(TCHAR);
    }

    // Now if we have a memory allocated, append the text there
    if(hMemory != NULL)
    {
        pbClipboard = (LPBYTE)GlobalLock(hMemory);
        if(pbClipboard != NULL)
        {
            memcpy(pbClipboard + cbPrevSize, szText, cbAddSize);
            GlobalUnlock(hMemory);
        }
    }

    // Return the allocated memory
    return hMemory;
}

bool Clipboard_Finish(HWND hWnd, HGLOBAL hMemory)
{
    if(hMemory != NULL)
    {
        // Insert text to the clipboard
        if(OpenClipboard(hWnd))
        {
            EmptyClipboard();
            SetClipboardData(CF_UNICODETEXT, hMemory);
            CloseClipboard();
            return true;
        }

        // If the opening clipboard failed, free the memory
        GlobalFree(hMemory);
    }

    return false;
}

//-----------------------------------------------------------------------------
// Path manipulation

LPTSTR FindDirectoryPathPart(LPTSTR szFullPath)
{
    LPTSTR szPathPart = szFullPath;

    // Skip the initial complicated parts
    // \\.\GlobalRoot\Device\Mup\Dir1\Dir2
    // \\.\Device\Mup\Dir1\Dir2
    while(szPathPart[0] != 0 && !isalpha(szPathPart[0]))
        szPathPart++;

    // If found, search fuhrter for well-known path parts
    if(szPathPart[0] != 0)
    {
        // Is it "GlobalRoot" ?
        if(!_tcsnicmp(szPathPart, _T("GlobalRoot\\"), 11))
            szPathPart += 11;
        if(!_tcsnicmp(szPathPart, _T("Device\\"), 7))
            szPathPart += 11;

        // Skip the Drive letter, if present
        if(isalpha(szPathPart[0]) && szPathPart[1] == _T(':'))
            szPathPart += 2;

        // Skip slashes and backslashes
        while(szPathPart[0] == _T('\\') || szPathPart[0] == _T('/'))
            szPathPart++;

        // Return what we got
        return szPathPart;
    }

    // Not recognized, return NULL
    return NULL;
}

LPTSTR FindNextPathSeparator(LPTSTR szPathPart)
{
    // Skip slashes and backslashes
    while(szPathPart[0] == _T('\\') || szPathPart[0] == _T('/'))
        szPathPart++;

    // Find next slash, backslash or end of string
    while(szPathPart[0] != 0 && szPathPart[0] != _T('\\') && szPathPart[0] != _T('/'))
        szPathPart++;
    
    return szPathPart;
}

//-----------------------------------------------------------------------------
// Other

// Calculates the necessary length of PFILE_FULL_EA_INFORMATION structure
ULONG GetEaEntrySize(PFILE_FULL_EA_INFORMATION EaInfo)
{
    ULONG EntrySize = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName[0]);

    //
    // The length of the item must be calculated very exactly.
    // No additional bytes (except for default alignment of 
    // FILE_FULL_EA_INFORMATION structure) is allowed.
    //

    EntrySize += EaInfo->EaNameLength + 1;      // Add the name length plus the ending zero character
    EntrySize += EaInfo->EaValueLength;         // Add the data length
    EntrySize = ALIGN_INT32(EntrySize);         // Align to 4-byte boundary

    return EntrySize;
}

DWORD TreeView_GetChildCount(HWND hTreeView, HTREEITEM hItem)
{
    DWORD dwChildCount = 0;

    // If both TreeView and item handle are valid
    if(hTreeView != NULL && hItem != NULL)
    {
        // Count all children
        hItem = TreeView_GetChild(hTreeView, hItem);
        while(hItem != NULL)
        {
            dwChildCount++;
            hItem = TreeView_GetNextSibling(hTreeView, hItem);
        }
    }

    return dwChildCount;
}

LPARAM TreeView_GetItemParam(HWND hTreeView, HTREEITEM hItem)
{
    TVITEM tvi;

    // Retrieve the item param
    tvi.mask   = TVIF_PARAM;
    tvi.hItem  = hItem;
    tvi.lParam = 0;
    TreeView_GetItem(hTreeView, &tvi);

    // Return the parameter
    return tvi.lParam;
}

HTREEITEM TreeView_SetTreeItem(HWND hTreeView, HTREEITEM hItem, LPCTSTR szText, LPARAM lParam)
{
    TVITEM tvi;

    // Retrieve the item param
    tvi.mask    = TVIF_TEXT | TVIF_PARAM;
    tvi.hItem   = hItem;
    tvi.lParam  = lParam;
    tvi.pszText = (LPTSTR)szText;
    if(!TreeView_SetItem(hTreeView, &tvi))
        hItem = NULL;

    // Return the parameter
    return hItem;
}

BOOL TreeView_EditLabel_ID(HWND hDlg, UINT nID)
{
    HTREEITEM hItem = NULL;
    HWND hTreeView = GetDlgItem(hDlg, nID);
    BOOL bResult = FALSE;

    // Only start editing if the proper tree view has focus
    if(GetFocus() == hTreeView)
    {
        hItem = TreeView_GetSelection(hTreeView);
        if(hItem != NULL)
        {
            TreeView_EditLabel(hTreeView, hItem);
            bResult = TRUE;
        }
    }

    return bResult;
}

HTREEITEM InsertTreeItem(HWND hTreeView, HTREEITEM hParent, HTREEITEM hInsertAfter, LPCTSTR szText, PVOID pParam)
{
    TVINSERTSTRUCT tvis;

    // If NULL specified as InsertAfter, we insert it after the last item
    if(hInsertAfter == NULL)
        hInsertAfter = TVI_LAST;
    
    // Insert the item to the tree
    tvis.hParent      = hParent;
    tvis.hInsertAfter = hInsertAfter;
    tvis.item.mask    = TVIF_TEXT | TVIF_PARAM;
    tvis.item.pszText = (LPTSTR)szText;
    tvis.item.lParam  = (LPARAM)pParam;
    return TreeView_InsertItem(hTreeView, &tvis);
}

HTREEITEM InsertTreeItem(HWND hTreeView, HTREEITEM hParent, LPCTSTR szText, PVOID pParam)
{
    return InsertTreeItem(hTreeView, hParent, NULL, szText, pParam);
}

HTREEITEM InsertTreeItem(HWND hTreeView, HTREEITEM hParent, LPCTSTR szText, LPARAM lParam)
{
    return InsertTreeItem(hTreeView, hParent, TVI_LAST, szText, (PVOID)lParam);
}

void TreeView_DeleteChildren(HWND hTreeView, HTREEITEM hParent)
{
    HTREEITEM hItem;

    // Remove all children, if any
    while((hItem = TreeView_GetChild(hTreeView, hParent)) != NULL)
        TreeView_DeleteItem(hTreeView, hItem);
}

HGLOBAL TreeView_CopyToClipboard(HWND hTreeView, HTREEITEM hItem, HGLOBAL hGlobal, size_t nLevel)
{
    HTREEITEM hChild;
    TVITEMEX tvi;
    TCHAR szBuffer[0x400] = _T("");
    TCHAR szIndent[0x400];
    size_t i;

    // Prepare the item
    ZeroMemory(&tvi, sizeof(TVITEM));
    tvi.mask = TVIF_TEXT;

    // Get all siblings
    while(hItem != NULL)
    {
        // Get the item text
        memset(szBuffer, 0, sizeof(szBuffer));
        tvi.hItem = hItem;
        tvi.pszText = szBuffer;
        tvi.cchTextMax = _countof(szBuffer);
        tvi.cchTextMax = _countof(szBuffer);
        TreeView_GetItem(hTreeView, &tvi);
        StringCchCat(szBuffer, _countof(szBuffer), _T("\r\n"));

        // Put the text to clipboard
        for(i = 0; i < nLevel * 4; i++)
            szIndent[i] = ' ';
        szIndent[i] = 0;

        // Insert the indent
        hGlobal = Clipboard_AddText(hGlobal, szIndent);
        hGlobal = Clipboard_AddText(hGlobal, szBuffer);

        // Are there any children?
        if((hChild = TreeView_GetChild(hTreeView, hItem)) != NULL)
        {
            hGlobal = TreeView_CopyToClipboard(hTreeView, hChild, hGlobal, nLevel + 1);
        }

        // Get the next sibling
        hItem = TreeView_GetNextSibling(hTreeView, hItem);
    }

    return hGlobal;
}

void TreeView_CopyToClipboard(HWND hTreeView)
{
    HGLOBAL hGlobal = NULL;

    hGlobal = TreeView_CopyToClipboard(hTreeView, TreeView_GetRoot(hTreeView), hGlobal, 0);
    Clipboard_Finish(hTreeView, hGlobal);
}

int OnTVKeyDown_CopyToClipboard(HWND /* hDlg */, LPNMTVKEYDOWN pNMTVKeyDown)
{
    // On Ctrl+C, copy the text to clipboard 
    if(pNMTVKeyDown->wVKey == 'C' && GetAsyncKeyState(VK_CONTROL) < 0)
    {
        TreeView_CopyToClipboard(pNMTVKeyDown->hdr.hwndFrom);
        return TRUE;
    }

    return FALSE;
}

//-----------------------------------------------------------------------------
// Virtualization for the current process

BOOL GetTokenElevation(PBOOL pbElevated)
{
    TOKEN_ELEVATION Elevation;
    HANDLE hToken;
    DWORD dwLength = 0;
    DWORD dwValue = 0;
    BOOL bResult = FALSE;

    if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        // Step1: Query the elevation type
        bResult = GetTokenInformation(hToken, TokenElevationType, &dwValue, sizeof(dwValue), &dwLength);
        if(bResult)
        {
            switch((TOKEN_ELEVATION_TYPE)dwValue)
            {
                case TokenElevationTypeDefault:
                    bResult = GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &dwLength);
                    if(bResult)
                        pbElevated[0] = Elevation.TokenIsElevated ? TRUE : FALSE;
                    break;

                case TokenElevationTypeFull:
                    pbElevated[0] = TRUE;
                    break;

                case TokenElevationTypeLimited:
                    pbElevated[0] = FALSE;
                    break;
            }
        }

        CloseHandle(hToken);
    }

    return bResult;
}

BOOL GetTokenVirtualizationEnabled(PBOOL pbEnabled)
{
    HANDLE hToken;
    DWORD dwEnabled = 0;
    DWORD dwLength = 0;
    BOOL bResult = FALSE;

    if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        bResult = GetTokenInformation(hToken, TokenVirtualizationEnabled, &dwEnabled, sizeof(dwEnabled), &dwLength);
        if(bResult && pbEnabled)
            pbEnabled[0] = dwEnabled ? TRUE : FALSE;

        CloseHandle(hToken);
    }

    return bResult;
}

BOOL SetTokenVirtualizationEnabled(BOOL bEnabled)
{
    HANDLE hToken;
    DWORD dwEnabled = bEnabled;
    BOOL bResult = FALSE;

    if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT, &hToken))
    {
        bResult = SetTokenInformation(hToken,
                                      TokenVirtualizationEnabled,
                                     &dwEnabled,
                                      sizeof(dwEnabled));
        CloseHandle(hToken);
    }

    return bResult;
}

//-----------------------------------------------------------------------------
// Set result status

static void DeleteBlinkTimer(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    // If there is already a blinker timer, destroy it
    if(pData->BlinkTimer != 0)
        KillTimer(hDlg, pData->BlinkTimer);
    pData->BlinkTimer = 0;

    // If there is a blink window already, destroy it
    if(pData->hWndBlink != NULL)
        DestroyWindow(pData->hWndBlink);
    pData->hWndBlink = NULL;
}

static VOID CALLBACK BlinkTimerProc(HWND hDlg, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
    UNREFERENCED_PARAMETER(dwTime);
    UNREFERENCED_PARAMETER(uMsg);

    if(idEvent == WM_TIMER_BLINK)
    {
        DeleteBlinkTimer(hDlg);
    }
}

HWND AttachIconToEdit(HWND hDlg, HWND hWndChild, LPTSTR szIDIcon)
{
    HINSTANCE hInst = g_hInst;
    HICON hIcon;
    POINT pt;
    HWND hWndBlink = NULL;
    RECT rect;
    int cx = 16; // GetSystemMetrics(SM_CXSMICON);
    int cy = 16; // GetSystemMetrics(SM_CYSMICON);

    // Load OEM icons if it's their ID
    if(IDI_APPLICATION <= szIDIcon && szIDIcon <= IDI_SHIELD)
        hInst = NULL;

    // Load the icon, 16x16
    hIcon = (HICON)LoadImage(hInst, szIDIcon, IMAGE_ICON, cx, cy, LR_SHARED);
    if(hIcon != NULL)
    {
        // Get the position of the edit box window
        GetWindowRect(hWndChild, &rect);
        pt.x = rect.left;
        pt.y = rect.top;
        ScreenToClient(hDlg, &pt);
        pt.x = pt.x - cx - 4;
        pt.y = pt.y + (rect.bottom - rect.top - cx) / 2;

        // Create the window for icon
        hWndBlink = CreateWindowEx(WS_EX_NOPARENTNOTIFY,
                                   WC_STATIC,
                                   NULL,
                                   WS_CHILD | WS_VISIBLE | SS_ICON,
                                   pt.x, pt.y, cx, cx,
                                   hDlg,
                                   NULL,
                                   g_hInst,
                                   NULL);
        if(hWndBlink != NULL)
        {
            // Apply the icon to the icon window
            SendMessage(hWndBlink, STM_SETICON, (WPARAM)hIcon, 0);
        }
    }

    return hWndBlink;
}

static void CreateBlinkingIcon(HWND hDlg, HWND hWndChild, int nSeverity)
{
    TFileTestData * pData = GetDialogData(hDlg);
//  LPTSTR IconSet[] = { IDI_INFORMATION, IDI_ERROR, MAKEINTRESOURCE(IDI_ICON_WAIT)};
    HWND hWndBlink;
    UINT IconSet[] = {IDI_ICON_INFORMATION, IDI_ICON_ERROR, IDI_ICON_WAIT};

    // If there is already a blinker timer, destroy it
    DeleteBlinkTimer(hDlg);

    // Create the icon, left-attached to the edit field
    // Note that I tried the system icons, but they look like shit
    // when reduced to small icon.
    hWndBlink = AttachIconToEdit(hDlg, hWndChild, MAKEINTRESOURCE(IconSet[nSeverity]));

    // Create timer for hiding the window
    pData->BlinkTimer = SetTimer(hDlg, WM_TIMER_BLINK, 800, BlinkTimerProc);
    pData->hWndBlink = hWndBlink;
}

void SetWindowEnumText(HWND hWndChild, LPCTSTR TextArray[], size_t nArraySize, size_t nIndex)
{
    LPCTSTR szTextToSet = _T("");

    // Sanity check
    assert(hWndChild != NULL);

    // Get the proper text message
    if(nIndex < nArraySize)
        szTextToSet = TextArray[nIndex];

    // Set the text message
    SetWindowText(hWndChild, szTextToSet);
}

int GetLastErrorSeverity(DWORD dwErrCode)
{
    switch(dwErrCode)
    {
        case ERROR_SUCCESS:
            return SEVERITY_SUCCESS;

        case ERROR_IO_PENDING:
            return SEVERITY_PENDING;

        default:
            return SEVERITY_ERROR;
    }
}

void SetResultInfo(HWND hDlg, DWORD dwFlags, ...)
{
    TCHAR szText[256];
    HWND hWndChild;
    va_list argList;

    // Start the argument list
    va_start(argList, dwFlags);

    //
    // 1) RSI_LAST_ERROR: DWORD dwErrCode
    // 

    if(dwFlags & RSI_LAST_ERROR)
    {
        LPTSTR szError;
        DWORD dwErrCode = va_arg(argList, DWORD);

        // Set the title
        if((hWndChild = GetDlgItem(hDlg, IDC_ERROR_CODE_TITLE)) != NULL)
            SetWindowText(hWndChild, _T("GetLastError:"));

        // Set the error text and the blinking icon
        if((hWndChild = GetDlgItem(hDlg, IDC_ERROR_CODE)) != NULL)
        {
            // Create the error text (code + text)
            szError = GetErrorText(dwErrCode);
            if(szError != NULL)
            {
                StringCchPrintf(szText, _countof(szText), _T("(0x%08lX) %s"), dwErrCode, szError);
                SetWindowText(hWndChild, szText);
                delete [] szError;
            }

            // Create the blinking icon
            CreateBlinkingIcon(hDlg, hWndChild, GetLastErrorSeverity(dwErrCode));
        }
    }

    //
    // 2) RSI_NTSTATUS: NTSTATUS Status
    //

    if(dwFlags & RSI_NTSTATUS)
    {
        LPCTSTR szStatus;
        NTSTATUS Status = va_arg(argList, NTSTATUS);
        int nSeverity;

        // Set the title
        if((hWndChild = GetDlgItem(hDlg, IDC_ERROR_CODE_TITLE)) != NULL)
            SetWindowText(hWndChild, _T("Status:"));

        // Set the error text and the blinking icon
        if((hWndChild = GetDlgItem(hDlg, IDC_ERROR_CODE)) != NULL)
        {
            switch(Status)
            {
                case STATUS_PENDING:
                    szStatus = NtStatus2Text(Status);
                    nSeverity = SEVERITY_PENDING;
                    break;

                case STATUS_INVALID_DATA_FORMAT:
                    szStatus = _T("The entered value has bad format.");
                    nSeverity = SEVERITY_ERROR;
                    break;

                case STATUS_CANNOT_EDIT_THIS:
                    szStatus = _T("This item is not editable.");
                    nSeverity = SEVERITY_ERROR;
                    break;

                case STATUS_FILE_ID_CONVERSION:
                    szStatus = _T("Skipped conversion of File ID to an NT name.");
                    nSeverity = SEVERITY_SUCCESS;
                    break;

                case STATUS_COPIED_TO_CLIPBOARD:
                    szStatus = _T("Item value copied to clipboard.");
                    nSeverity = SEVERITY_SUCCESS;
                    break;

                default:
                    szStatus = NtStatus2Text(Status);
                    nSeverity = NT_SUCCESS(Status) ? SEVERITY_SUCCESS : SEVERITY_ERROR;
                    break;
            }

            // Set the status text and blinking icon
            SetWindowText(hWndChild, szStatus);
            CreateBlinkingIcon(hDlg, hWndChild, nSeverity);
        }
    }

    //
    // 3) RSI_HANDLE: HANDLE hHandle
    //

    if(dwFlags & RSI_HANDLE)
    {
        HANDLE hHandle = va_arg(argList, HANDLE);
        BOOL bEnable = TRUE;

        // Enable/disable the hint for close handle, if any
        if((hWndChild = GetDlgItem(hDlg, IDC_CLOSE_HANDLE_HINT)) != NULL)
        {
            if(IsHandleInvalid(hHandle))
                bEnable = FALSE;
            EnableWindow(hWndChild, bEnable);
        }

        // Enable/disable the "CloseHandle" button, if present
        if((hWndChild = GetDlgItem(hDlg, IDC_CLOSE_HANDLE)) != NULL)
        {
            if(IsHandleInvalid(hHandle))
                bEnable = FALSE;
            EnableWindow(hWndChild, bEnable);
        }

        // Set the handle value
        if((hWndChild = GetDlgItem(hDlg, IDC_HANDLE)) != NULL)
        {
            if(hHandle == INVALID_HANDLE_VALUE)
                SetWindowText(hWndChild, _T("INVALID_HANDLE_VALUE"));
            else if(hHandle == NULL)
                SetWindowText(hWndChild, _T("NULL"));
            else
                Hex2DlgTextPtr(hDlg, IDC_HANDLE, (DWORD_PTR)hHandle);
        }
    }

    //
    // 4) RSI_NOINFO: Set the info field to empty
    //

    if(dwFlags & RSI_NOINFO)
    {
        // Set the title
        if((hWndChild = GetDlgItem(hDlg, IDC_INFORMATION_TITLE)) != NULL)
            SetWindowText(hWndChild, _T("Result:"));
        SetDlgItemText(hDlg, IDC_INFORMATION, _T(""));
    }

    //
    // 5) RSI_INFORMATION: PIO_STATUS_BLOCK IoStatus
    //

    if(dwFlags & RSI_INFORMATION)
    {
        PIO_STATUS_BLOCK IoStatus = va_arg(argList, PIO_STATUS_BLOCK);

        // Set the title
        if((hWndChild = GetDlgItem(hDlg, IDC_INFORMATION_TITLE)) != NULL)
            SetWindowText(hWndChild, _T("IoStatus.Info:"));
        Hex2DlgTextPtr(hDlg, IDC_INFORMATION, IoStatus->Information);
    }

    //
    // 6) RSI_INFO_INT32: DWORD dwInfo
    //

    if(dwFlags & RSI_INFO_INT32)
    {
        DWORD dwInfo = va_arg(argList, DWORD);

        // Set the title
        if((hWndChild = GetDlgItem(hDlg, IDC_INFORMATION_TITLE)) != NULL)
            SetWindowText(hWndChild, _T("Length:"));
        Hex2DlgText32(hDlg, IDC_INFORMATION, dwInfo);
    }

    //
    // 7) RSI_NTCREATE: PIO_STATUS_BLOCK IoStatus (result of NtCreateFile)
    //

    if(dwFlags & RSI_NTCREATE)
    {
        PIO_STATUS_BLOCK IoStatus = va_arg(argList, PIO_STATUS_BLOCK);

        if((hWndChild = GetDlgItem(hDlg, IDC_INFORMATION)) != NULL)
        {
            LPCTSTR szNtCreateResult[] = 
            {
                _T("FILE_SUPERSEDED"),
                _T("FILE_OPENED"),
                _T("FILE_CREATED"),
                _T("FILE_OVERWRITTEN"),
                _T("FILE_EXISTS"),
                _T("FILE_DOES_NOT_EXIST"),
                _T("0x00000006"),
                _T("FILE_OPLOCK_BROKEN_TO_LEVEL_2"),
                _T("FILE_OPLOCK_BROKEN_TO_NONE"),
                _T("FILE_OPBATCH_BREAK_UNDERWAY")
            };

            SetWindowEnumText(hWndChild, szNtCreateResult, _countof(szNtCreateResult), IoStatus->Information);
        }
    }

    //
    // 8) RSI_READ: DWORD dwBytesRead
    //

    if(dwFlags & RSI_READ)
    {
        DWORD dwBytesRead = va_arg(argList, DWORD);

        // Set the title text
        if((hWndChild = GetDlgItem(hDlg, IDC_INFORMATION_TITLE)) != NULL)
        {
            SetWindowText(hWndChild, _T("Bytes Read:"));
        }

        // Set the value
        Hex2DlgText32(hDlg, IDC_INFORMATION, dwBytesRead);
    }

    //
    // 9) RSI_WRITTEN: DWORD dwBytesWritten
    //

    if(dwFlags & RSI_WRITTEN)
    {
        DWORD dwBytesWritten = va_arg(argList, DWORD);

        // Set the title text
        if((hWndChild = GetDlgItem(hDlg, IDC_INFORMATION_TITLE)) != NULL)
        {
            SetWindowText(hWndChild, _T("Bytes Written:"));
        }

        // Set the value
        Hex2DlgText32(hDlg, IDC_INFORMATION, dwBytesWritten);
    }

    //
    // 10) RSI_FILESIZE: PLARGE_INTEGER pFileSize
    //

    if(dwFlags & RSI_FILESIZE)
    {
        PLARGE_INTEGER pFileSize = va_arg(argList, PLARGE_INTEGER);

        // Set the title text
        if((hWndChild = GetDlgItem(hDlg, IDC_INFORMATION_TITLE)) != NULL)
        {
            SetWindowText(hWndChild, _T("File Size:"));
        }

        // Set the value
        Hex2DlgText64(hDlg, IDC_INFORMATION, pFileSize->QuadPart);
    }

    //
    // 11) RSI_FILEPOS: PLARGE_INTEGER pFilePos
    //

    if(dwFlags & RSI_FILEPOS)
    {
        PLARGE_INTEGER pFilePos = va_arg(argList, PLARGE_INTEGER);

        // Set the title text
        if((hWndChild = GetDlgItem(hDlg, IDC_INFORMATION_TITLE)) != NULL)
        {
            SetWindowText(hWndChild, _T("File Pos:"));
        }

        // Set the value
        Hex2DlgText64(hDlg, IDC_INFORMATION, pFilePos->QuadPart);
    }

    // End the arguments
    va_end(argList);
}

//-----------------------------------------------------------------------------
// Dynamic loaded APIs

RTLGETCURRENTTRANSACTION pfnRtlGetCurrentTransaction = NULL;
RTLSETCURRENTTRANSACTION pfnRtlSetCurrentTransaction = NULL;
CREATETRANSACTION        pfnCreateTransaction     = NULL;
COMMITTRANSACTION        pfnCommitTransaction     = NULL;
ROLLBACKTRANSACTION      pfnRollbackTransaction   = NULL;
CREATEDIRTRANSACTED      pfnCreateDirectoryTransacted = NULL;
CREATEFILETRANSACTED     pfnCreateFileTransacted  = NULL;
CREATEHARDLINK           pfnCreateHardLink = NULL;
ADDMANDATORYACE          pfnAddMandatoryAce = NULL;

static HINSTANCE hNtdll = NULL;
static HINSTANCE hKernel32 = NULL;
static HINSTANCE hAdvapi32 = NULL;
static HINSTANCE hKtmw32 = NULL;

DWORD GetBuildNumber(HMODULE hMod)
{
    ULARGE_INTEGER Version;
    TCHAR szFileName[MAX_PATH];

    GetModuleFileName(hMod, szFileName, _countof(szFileName));
    GetModuleVersion(szFileName, &Version);
    return HIWORD(Version.LowPart);
}

void ResolveDynamicLoadedAPIs()
{
    // Get imports from Ntdll.dll
    if(hNtdll == NULL)
    {
        hNtdll = GetModuleHandle(_T("Ntdll.dll"));
        if(hNtdll != NULL)
        {
            pfnRtlGetCurrentTransaction = (RTLGETCURRENTTRANSACTION)
                                          GetProcAddress(hNtdll, "RtlGetCurrentTransaction");
            pfnRtlSetCurrentTransaction = (RTLSETCURRENTTRANSACTION)
                                          GetProcAddress(hNtdll, "RtlSetCurrentTransaction");
            g_dwWinBuild = GetBuildNumber(hNtdll);
        }
    }

    // Get imports from Kernel32.dll
    if(hKernel32 == NULL)
    {
        hKernel32 = GetModuleHandle(_T("Kernel32.dll"));
        if(hKernel32 != NULL)
        {
#ifdef _UNICODE
            pfnCreateDirectoryTransacted = (CREATEDIRTRANSACTED)GetProcAddress(hKernel32, "CreateDirectoryTransactedW");
            pfnCreateFileTransacted = (CREATEFILETRANSACTED)GetProcAddress(hKernel32, "CreateFileTransactedW");
            pfnCreateHardLink = (CREATEHARDLINK)GetProcAddress(hKernel32, "CreateHardLinkW");
#else
            pfnCreateDirectoryTransacted = (CREATEDIRTRANSACTED)GetProcAddress(hKernel32, "CreateDirectoryTransactedA");
            pfnCreateFileTransacted = (CREATEFILETRANSACTED)GetProcAddress(hKernel32, "CreateFileTransactedA");
            pfnCreateHardLink = (CREATEHARDLINK)GetProcAddress(hKernel32, "CreateHardLinkA");
#endif
        }
    }

    // Get imports from Advapi32.dll
    if(hAdvapi32 == NULL)
    {
        hAdvapi32 = LoadLibrary(_T("Advapi32.dll"));
        if(hAdvapi32 != NULL)
        {
            pfnAddMandatoryAce = (ADDMANDATORYACE)GetProcAddress(hAdvapi32, "AddMandatoryAce");
        }
    }

    // Get imports from Ktmw32.dll
    if(hKtmw32 == NULL)
    {
        hKtmw32 = LoadLibrary(_T("Ktmw32.dll"));
        if(hKtmw32 != NULL)
        {
            pfnCreateTransaction   = (CREATETRANSACTION)GetProcAddress(hKtmw32, "CreateTransaction");
            pfnCommitTransaction   = (COMMITTRANSACTION)GetProcAddress(hKtmw32, "CommitTransaction");
            pfnRollbackTransaction = (ROLLBACKTRANSACTION)GetProcAddress(hKtmw32, "RollbackTransaction");
        }
    }
}

void UnloadDynamicLoadedAPIs()
{
    if(hKtmw32 != NULL)
    {
        pfnCreateTransaction   = NULL;
        pfnCommitTransaction   = NULL;
        pfnRollbackTransaction = NULL;

        FreeLibrary(hKtmw32);
        hKtmw32 = NULL;
    }

    if(hAdvapi32 == NULL)
    {
        pfnAddMandatoryAce = NULL;
        
        FreeLibrary(hAdvapi32);
        hAdvapi32 = NULL;
    }

    if(hKernel32 != NULL)
    {
        pfnCreateFileTransacted = NULL;

        FreeLibrary(hKernel32);
        hKernel32 = NULL;
    }

    if(hNtdll != NULL)
    {
        pfnRtlGetCurrentTransaction = NULL;
        pfnRtlSetCurrentTransaction = NULL;

        FreeLibrary(hNtdll);
        hNtdll = NULL;
    }
}

//-----------------------------------------------------------------------------
// Obtaining NT name from a name, either DOS or NT

static LPCWSTR szGlobalRootMaskW = L"\\\\.\\GlobalRoot";

typedef enum _PATH_TYPE
{
    PathTypeNative,                 // Full local path in native format ("\??\")
    PathTypeNativePrefix,           // Full local path prefixed with native prefix ("\\?\" or "\\.\")
    PathTypeLocalFull,              // Full local path, including drive letter  ("C:\Windows\...")
    PathTypeLocalRoot,              // Local root of the current drive ("\Windows\...")
    PathTypeLocalRelative,          // Relative path ("Windows\...")
    PathTypeNetwork,                // Network path ("\\Server\Share\...")
    PathTypeUnknown
} PATH_TYPE, *PPATH_TYPE;

static PATH_TYPE GetDosPathType(LPCWSTR szFileNameW)
{
    // Does it begin with backslash character?
    if(szFileNameW[0] == L'\\')
    {
        // Check for native-like win32 prefixes and network share paths
        if(szFileNameW[1] == L'\\')
        {
            // "\\?\" or "\\.\"
            if(szFileNameW[2] == '?' && szFileNameW[3] == '\\')
                return PathTypeNativePrefix;
            if(szFileNameW[2] == '.' && szFileNameW[3] == '\\')
                return PathTypeNativePrefix;
            
            // Network paths begin with "\\"
            return PathTypeNetwork;
        }

        // Check for native path ([refixed with "\??\")
        if(szFileNameW[1] == L'?' && szFileNameW[2] == L'?' && szFileNameW[3] == L'\\')
            return PathTypeNative;

        // Anything else that begins with "\\" is considered a local root path
        return PathTypeLocalRoot;
    }
    else
    {
        // Check for local DOS paths ("C:\Path\File.ext")
        // Note: Do not use "isalpha()" function, because it could fail on exotic characters
        // (and also ASSERTs in debug builds)
        if(('A' <= szFileNameW[0] && szFileNameW[0] <= 'Z') || ('a' <= szFileNameW[0] && szFileNameW[0] <= 'z'))
        {
            if(szFileNameW[1] == ':' && szFileNameW[2] == '\\')
                return PathTypeLocalFull;
        }

        // Anything else that does not begin with "\\" is considered a local relative path
        return PathTypeLocalRelative;
    }
}

size_t IsGlobalRootPrefix(LPCWSTR szFileNameW)
{
    // If the path name is a Win32 native-like prefix
    if(GetDosPathType(szFileNameW) == PathTypeNativePrefix)
    {
        // Skip the native prefix
        szFileNameW += 4;

        // Check for "GlobalRoot".
        // Note: Return length without the backslash after "GlobalRoot"
        if(!_wcsnicmp(szFileNameW, L"GlobalRoot\\", 11))
            return 4 + 10;
    }

    return 0;
}

BOOLEAN IsNativeName(LPCWSTR szFileName)
{
    OBJECT_ATTRIBUTES ObjAttr;
    UNICODE_STRING FileName;
    UNICODE_STRING TempName;
    PATH_TYPE PathType;
    NTSTATUS Status;
    HANDLE Handle;

    // Determine the path type
    PathType = GetDosPathType(szFileName);
    if(PathType == PathTypeNative)
        return TRUE;

    // If the path begins with backslash, determine if it really is an NT name,
    // and for example not local root path (e.g. "\Systemroot" is an NT name,
    // but "\Windows" it a local path name)
    if(PathType == PathTypeLocalRoot)
    {
        // Prepare the object attributes
        InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        // Find the next path part
        FileName.MaximumLength =
        FileName.Length = 0;
        FileName.Buffer = (PWSTR)szFileName;
        szFileName++;

        // Go until we find the second backslash
        while(szFileName[0] != 0 && szFileName[0] != L'\\')
            szFileName++;
        
        // Set the length to the UNICODE_STRING
        FileName.MaximumLength =
        FileName.Length = (USHORT)((szFileName - FileName.Buffer) * sizeof(WCHAR));

        // Note: "\Windows" matches both FS directory and NT namespace directory
        RtlInitUnicodeString(&TempName, L"\\Windows");
        if(RtlCompareUnicodeString(&FileName, &TempName, TRUE) == 0)
            return FALSE;

        // Attempt to open the symlink (Example: "\Systemroot")
        Status = NtOpenSymbolicLinkObject(&Handle, SYMBOLIC_LINK_QUERY, &ObjAttr);
        if(NT_SUCCESS(Status))
        {
            NtClose(Handle);
            return TRUE;
        }

        // Try to open a directory (Example: "\Device")
        Status = NtOpenDirectoryObject(&Handle, DIRECTORY_TRAVERSE, &ObjAttr);
        if(NT_SUCCESS(Status))
        {
            NtClose(Handle);
            return TRUE;
        }
    }

    return FALSE;
}

// Replacement for RtlDosPathNameToNtPathName_U
BOOLEAN Win32PathNameToNtPathName(PUNICODE_STRING FileName, LPCWSTR szFileNameW)
{
    LPCWSTR szNtPrefix = NULL;
    LPWSTR szCurrentDir = NULL;
//  LPWSTR szBufferEnd;
//  LPWSTR szBuffer;
    size_t cbFileName = 0;
    size_t cbNtPrefix = 0;

    // Determine the path type
    switch(GetDosPathType(szFileNameW))
    {
        // DOS native-like paths ("\\?\C:\" and "\\.\C:\") - need to replace prefix
        case PathTypeNativePrefix:
            szNtPrefix = L"\\??\\";
            cbNtPrefix = 8;
            szFileNameW += 4;
            break;

        // Local full paths need to be prefixed with "\??\"
        case PathTypeLocalFull:
            szNtPrefix = L"\\??\\";
            cbNtPrefix = 8;
            break;

        // Local root paths need to be prefixed with the current drive
//      case PathTypeLocalRoot:
//          szCurrentDir = Win32PathGetCurrentDir(FALSE);
//          cbNtPrefix = wcslen(szCurrentDir) * sizeof(WCHAR);
//          szNtPrefix = szCurrentDir;
//          break;

        // Local relative paths need to be prefixed with the current directory
//      case PathTypeLocalRelative:
//          szCurrentDir = Win32PathGetCurrentDir(TRUE);
//          cbNtPrefix = wcslen(szCurrentDir) * sizeof(WCHAR);
//          szNtPrefix = szCurrentDir;
//          break;

        // Network share paths need to be prefixed with "\??\UNC\"
        case PathTypeNetwork:
            szNtPrefix = L"\\??\\UNC\\";
            cbNtPrefix = 16;
            szFileNameW += 2;
            break;
    }

    // Do not try to convert the name if it would be too long
    cbFileName = wcslen(szFileNameW) * sizeof(WCHAR);
    if((cbNtPrefix + cbFileName) >= 0xFFFE)
        return FALSE;

    // Allocate buffer for the path name
    FileName->MaximumLength = (USHORT)(cbNtPrefix + cbFileName + sizeof(WCHAR));
    FileName->Length = (USHORT)(cbNtPrefix + cbFileName);
    FileName->Buffer = (PWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, FileName->MaximumLength);
    if(FileName->Buffer == NULL)
        return FALSE;

    // Copy the prefix, if any
    if(szNtPrefix != NULL && cbNtPrefix != 0) 
        memcpy(FileName->Buffer, szNtPrefix, cbNtPrefix);

    // Copy the name itself. Also terminate the name with zero
    // (i.e. the same like RtlDosPathNameToNtPathName_U)
    memcpy(FileName->Buffer + (cbNtPrefix / sizeof(WCHAR)), szFileNameW, cbFileName);
    FileName->Buffer[FileName->Length / sizeof(WCHAR)] = 0;
    
    // Change slashes to backslashes
//  szBufferEnd = FileName->Buffer + (FileName->Length / sizeof(WCHAR));
//  for(szBuffer = FileName->Buffer; szBuffer < szBufferEnd; szBuffer++)
//      szBuffer[0] = (szBuffer[0] == L'/') ? L'\\' : szBuffer[0];

    // Free buffers and exit
    delete [] szCurrentDir;
    return TRUE;
}

// Converts file name to UNICODE_STRING
// Both DOS names and native  NT names are processed properly
// Buffer in "FileName" needs to be freed using FreeFileNameString(&FileName)
NTSTATUS FileNameToUnicodeString(
    PUNICODE_STRING FileName,    
    LPCTSTR szFileName)
{
    UNICODE_STRING UnicodeName = {0, 0, NULL};
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN Result;
    PWSTR szFileNameW = NULL;

    // Set the FileName to empty UNICODE_STRING
    FileName->MaximumLength = 0;
    FileName->Length = 0;
    FileName->Buffer = NULL;

    // Convert the file name to Unicode, if needed
#ifndef UNICODE
    // CreateUnicodeStringFromAsciiz produces zero-terminated UNICODE_STRING
    Status = RtlCreateUnicodeStringFromAsciiz(&UnicodeName, szFileName);
    if(!NT_SUCCESS(Status))
        return Status;

    szFileNameW = UnicodeName.Buffer;
#else
    UNREFERENCED_PARAMETER(UnicodeName);
    szFileNameW = (PWSTR)szFileName;
#endif

    //
    // Several problems of RtlDosPathNameToNtPathName_U
    // ================================================
    //
    // 1) Names longer than about 0x200 characters are not correctly processed
    // 2) If the name ends with space, that space is cut
    // 3) Generally works unpredicably for the following path types:
    //
    //    - \??\C:\Dir\File.ext                       - doesn't work on WinNT 4.0
    //    - \\?\C:\Dir\File.ext                       - works OK on WinNT 4.0
    //    - \\Server\Share\Dir\File.ext               - works OK on WinNT 4.0
    //    - \Device\LanmanRedirector\Server\Share\... - doesn't work on WinNT 4.0
    //    - \SystemRoot\System32\Kernel32.dll         - doesn't work on WinNT 4.0
    //    - \??\UNC\Server\Share\Dir\File.ext         - doesn't work on WinNT 4.0
    //
    // From the above reasons, we won't use the RtlDosPathNameToNtPathName_U.
    //
    
    // Convert Win32 name using GlobalRoot to native name
    // ("\\?\GlobalRoot\Device\xxxx" to "\Device\xxxx")
    szFileNameW += IsGlobalRootPrefix(szFileNameW);

    // If it's not an NT path name yet, convert it to an NT name.
    if(IsNativeName(szFileNameW) == FALSE)
    {
        // Use our own method for converting the DOS path name to NT name
//      Result = RtlDosPathNameToNtPathName_U(szFileNameW, FileName, NULL, NULL);
        Result = Win32PathNameToNtPathName(FileName, szFileNameW);
        if(!Result || FileName->Length == 0)
        {
            Status = STATUS_OBJECT_PATH_SYNTAX_BAD;
        }
    }
    else
    {
        if(!RtlCreateUnicodeString(FileName, szFileNameW))
            Status = STATUS_UNSUCCESSFUL;
    }

    // Free the allocated unicode string with DOS name
    RtlFreeUnicodeString(&UnicodeName);
    return Status;
}

void FreeFileNameString(PUNICODE_STRING FileName)
{
    if(FileName != NULL)
    {
        if(FileName->Buffer != NULL)
            RtlFreeHeap(RtlProcessHeap(), 0, FileName->Buffer);
        FileName->Buffer = NULL;
    }
}

NTSTATUS ConvertToNtName(HWND hDlg, UINT nIDEdit)
{
    UNICODE_STRING NtName = {0};
    NTSTATUS Status = STATUS_SUCCESS;
    HWND hEdit = GetDlgItem(hDlg, nIDEdit);
    LPTSTR szFileName = NULL;
    int nLength = GetWindowTextLength(hEdit);

    // Only do something if the text length is > 0)
    if(nLength > 0)
    {
        // Allocate buffer
        szFileName = new TCHAR[nLength + 1];
        if(szFileName != NULL)
        {
            // Get the window text
            // If it already appears to be an NT name, do nothing
            GetWindowText(hEdit, szFileName, nLength + 1);

            // Don't convert file ID
            if(nIDEdit == IDC_FILE_NAME && IsPossibleFileId(szFileName))
            {
                SetResultInfo(hDlg, STATUS_FILE_ID_CONVERSION);
            }
            else
            {
                // Convert the name to UNICODE_STRING
                Status = FileNameToUnicodeString(&NtName, szFileName);
                if(NT_SUCCESS(Status))
                {
                    SetWindowText(hEdit, NtName.Buffer);
                    FreeFileNameString(&NtName);
                }
            }
            
            delete [] szFileName;
        }
    }
    return Status;
}

int ConvertToWin32Name(HWND hDlg, UINT nIDEdit)
{
    LPTSTR szNewFileName;
    LPTSTR szFileName;
    HWND hWndEdit = GetDlgItem(hDlg, nIDEdit);
    size_t nLength = GetWindowTextLength(hWndEdit);

    // Only do something if the text length is > 0)
    if(nLength > 0)
    {
        // Allocate buffer
        szFileName = new TCHAR[nLength + 1];
        if(szFileName != NULL)
        {
            // Get the window text
            // If it already appears to be an Win32 name, do nothing
            GetWindowText(hWndEdit, szFileName, (int)(nLength + 1));

            // The "\??\Path" case
            if(!_tcsnicmp(szFileName, _T("\\??\\"), 4))
            {
                // If it looks like the \??\C:\..., just skip the initial NT prefix
                if(szFileName[4] != 0 && szFileName[5] == _T(':') && szFileName[6] == _T('\\'))
                {
                    SetWindowText(hWndEdit, szFileName + 4);
                }

                // Network paths: Remove the "\??\UNC\"
                else if(!_tcsnicmp(szFileName, _T("\\??\\UNC\\"), 8))
                {
                    szFileName[6] = _T('\\');
                    SetWindowText(hWndEdit, szFileName + 6);
                }

                // Otherwise, replace "\??\" with "\\.\"
                else
                {
                    szFileName[1] = _T('\\');
                    szFileName[2] = _T('.');
                    SetWindowText(hWndEdit, szFileName);
                }
            }

            // The "\Device\XXX case can still be solved on WinXP or newer
            // The "\Systemroot case can still be solved on WinXP or newer
            else if(g_dwWinVer >= 0x0501 && IsNativeName(szFileName))
            {
                nLength = nLength + wcslen(szGlobalRootMaskW) + 1;
                szNewFileName = new TCHAR[nLength];
                if(szNewFileName != NULL)
                {
                    StringCchPrintf(szNewFileName, nLength, _T("%s%s"), szGlobalRootMaskW, szFileName);
                    SetWindowText(hWndEdit, szNewFileName);
                    delete [] szNewFileName;
                }
            }

            // Leave the name be
            delete [] szFileName;
        }
    }
    return ERROR_SUCCESS;
}

//-----------------------------------------------------------------------------
// Conversion flags to the text value

LPTSTR FlagsToString(TFlagInfo * pFlags, LPTSTR szBuffer, size_t cchBuffer, DWORD dwBitMask, bool bNewLineSeparated)
{
    TFlagString fs(pFlags, dwBitMask, (bNewLineSeparated) ? GetBitSeparatorNewLine() : NULL);

    StringCchCopy(szBuffer, cchBuffer, fs);
    return szBuffer;
}

LPTSTR NamedValueToString(TFlagInfo * pFlags, LPTSTR szBuffer, size_t cchBuffer, LPCTSTR szFormat, DWORD dwBitMask)
{
    LPTSTR szSaveBuffer = szBuffer;
    LPTSTR szBufferEnd = szBuffer + cchBuffer;

    // Print the format and value
    StringCchPrintfEx(szBuffer, cchBuffer, &szBuffer, NULL, 0, szFormat, dwBitMask);

    // Format the flags as user-friendly value
    if(dwBitMask != 0)
        FlagsToString(pFlags, szBuffer, (szBufferEnd - szBuffer), dwBitMask, false);

    // Return the start of the buffer
    return szSaveBuffer;
}

LPTSTR GuidValueToString(LPTSTR szBuffer, size_t cchBuffer, LPCTSTR szFormat, LPGUID PtrGuid)
{
    LPTSTR szSaveBuffer = szBuffer;
    TCHAR szGuidText[0x40];

    GuidToString(PtrGuid, szGuidText, _countof(szGuidText));
    StringCchPrintf(szBuffer, cchBuffer, szFormat, szGuidText);
    return szSaveBuffer;
}

//-----------------------------------------------------------------------------
// File ID and object ID support

void FileIDToString(TFileTestData * pData, ULONGLONG FileId, LPTSTR szBuffer)
{
    PATH_TYPE PathType;
    LPTSTR szPath = (pData->szDirName[0] != 0) ? pData->szDirName : pData->szFileName1;

    // Skip the NT prefix, if any
    PathType = GetDosPathType(szPath);
    if(PathType == PathTypeNative || PathType == PathTypeNativePrefix)
        szPath += 4;

    // Supply the disk name
    if(isalpha(szPath[0]) && szPath[1] == _T(':') && szPath[2] == _T('\\'))
    {
        *szBuffer++ = *szPath++;
        *szBuffer++ = *szPath++;
        *szBuffer++ = *szPath++;
    }

    Hex2Text64(szBuffer, FileId);
}

void ObjectIDToString(PBYTE pbObjId, LPCTSTR szFileName, LPTSTR szObjectID)
{
    // Supply the disk name
    if(szFileName != NULL)
    {
        if(isalpha(szFileName[0]) && szFileName[1] == _T(':') && szFileName[2] == _T('\\'))
        {
            *szObjectID++ = *szFileName++;
            *szObjectID++ = *szFileName++;
            *szObjectID++ = *szFileName++;
        }
    }

    // Format the object ID
    for(int i = 0; i < 0x10; i++)
    {
        BYTE OneByte = *pbObjId++;

        *szObjectID++ = ValueToChar[OneByte >> 0x04];
        *szObjectID++ = ValueToChar[OneByte & 0x0F];
    }

    *szObjectID = 0;
}

int StringToFileID(
    LPCTSTR szFileOrObjId,
    LPTSTR szVolume,
    PVOID pvFileObjId,
    PDWORD pLength)
{
    PBYTE pbObjectID = (PBYTE)pvFileObjId;
    DWORD dwLength = 0;
    TCHAR OneChar;
    BYTE OneByte;
    DWORD dwErrCode = ERROR_SUCCESS;

    // Is there drive letter?
    if(isalpha(szFileOrObjId[0]) && szFileOrObjId[1] == _T(':') && szFileOrObjId[2] == _T('\\'))
    {
        if(szVolume != NULL)
        {
            szVolume[0] = szFileOrObjId[0];
            szVolume[1] = szFileOrObjId[1];
            szVolume[2] = szFileOrObjId[2];
            szVolume[3] = 0;
        }
        szFileOrObjId += 3;
    }

    //
    // TODO: Is there a device name?
    //

    // Perform conversion based of length of the string
    switch(_tcslen(szFileOrObjId))
    {
        // Is the rest a file ID? (16 characters)
        case 0x10:
            dwLength = sizeof(ULONGLONG);
            dwErrCode = Text2Hex64(szFileOrObjId, (PLONGLONG)pvFileObjId);
            break;

        case 0x20:
            for(int i = 0; i < 0x10; i++)
            {
                if(szFileOrObjId[0] > 0x80 || szFileOrObjId[1] > 0x80)
                {
                    dwErrCode = ERROR_BAD_FORMAT;
                    break;
                }

                // Convert the first character
                OneChar = *szFileOrObjId++;
                if(CharToValue[OneChar] == 0xFF)
                {
                    dwErrCode = ERROR_BAD_FORMAT;
                    break;
                }
                OneByte = CharToValue[OneChar] << 0x04;

                // Convert the second character
                OneChar = *szFileOrObjId++;
                if(CharToValue[OneChar] == 0xFF)
                {
                    dwErrCode = ERROR_BAD_FORMAT;
                    break;
                }
                OneByte |= CharToValue[OneChar];
                *pbObjectID++ = OneByte;
            }
            dwLength = 0x10;
            break;

        default:
            dwErrCode = ERROR_BAD_FORMAT;
            break;
    }

    // Give the output length
    if(dwErrCode == ERROR_SUCCESS && pLength != NULL)
        *pLength = dwLength;
    return dwErrCode;
}

HMENU FindContextMenu(UINT nIDMenu)
{
    // Search the pre-loaded menu array
    for(size_t i = 0; i < MAX_CONTEXT_MENUS; i++)
    {
        if(g_ContextMenus[i].szMenuName == MAKEINTRESOURCE(nIDMenu))
            return g_ContextMenus[i].hMenu;
    }

    // Chould never happen, but anyway
    assert(false);
    return LoadMenu(g_hInst, MAKEINTRESOURCE(nIDMenu));
}

int ExecuteContextMenu(HWND hWndParent, HMENU hMainMenu, LPARAM lParam)
{
    HMENU hSubMenu = GetSubMenu(hMainMenu, 0);
    POINT pt;

    if(hSubMenu != NULL)
    {
        // If activated by a key, get the left-top window position
        if(lParam == 0xFFFFFFFF)
        {
            pt.x = pt.y = 5;
            ClientToScreen(hWndParent, &pt);
        }
        else
        {
            pt.x = GET_X_LPARAM(lParam);
            pt.y = GET_Y_LPARAM(lParam);
        }

        // Set the window to foreground due to capture mouse events
        SetForegroundWindow(hWndParent);
        TrackPopupMenu(hSubMenu, (TPM_LEFTBUTTON | TPM_RIGHTBUTTON), pt.x, pt.y, 0, hWndParent, NULL);
        PostMessage(hWndParent, WM_NULL, 0, 0);
        return TRUE;
    }

    return FALSE;
}

int ExecuteContextMenuForDlgItem(HWND hWndParent, HMENU hMainMenu, UINT nIDCtrl)
{
    LPARAM lParam;
    HWND hWndChild = GetDlgItem(hWndParent, nIDCtrl);
    RECT rect;

    // Calculate position of the menu
    GetWindowRect(hWndChild, &rect);
    lParam = MAKELPARAM(rect.left, rect.bottom);

    // Execute the context menu
    return ExecuteContextMenu(hWndParent, hMainMenu, lParam);
}

NTSTATUS NtDeleteReparsePoint(HANDLE ObjectHandle)
{
    PREPARSE_DATA_BUFFER pReparseData = NULL;
    IO_STATUS_BLOCK IoStatus;
    ULONGLONG ReparseBuffer[0x100];         // ULONGLONG makes sure it's aligned to 8
    NTSTATUS Status;
    ULONG Length = sizeof(ReparseBuffer);

    // Query the reparse point 
    pReparseData = (PREPARSE_DATA_BUFFER)ReparseBuffer;
    Status = NtFsControlFile(ObjectHandle, 
                             NULL,
                             NULL,
                             NULL,
                            &IoStatus,
                             FSCTL_GET_REPARSE_POINT,
                             NULL,
                             0,
                             pReparseData,
                             Length);

    // ... and delete it
    if(NT_SUCCESS(Status))
    {
        pReparseData->ReparseDataLength = 0;
        Status = NtFsControlFile(ObjectHandle,
                                 NULL,
                                 NULL,
                                 NULL,
                                &IoStatus,
                                 FSCTL_DELETE_REPARSE_POINT,
                                 pReparseData,
                                 REPARSE_GUID_DATA_BUFFER_HEADER_SIZE,
                                 NULL,
                                 0);
    }

    return Status;
}

NTSTATUS NtDeleteReparsePoint(POBJECT_ATTRIBUTES PtrObjectAttributes)
{
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;
    HANDLE FileHandle = NULL;

    // Open the reparse point
    Status = NtOpenFile(&FileHandle,
                         FILE_WRITE_ATTRIBUTES,
                         PtrObjectAttributes,
                        &IoStatus,
                         0,
                         FILE_OPEN_REPARSE_POINT);
    if(NT_SUCCESS(Status))
    {
        Status = NtDeleteReparsePoint(FileHandle);
        NtClose(FileHandle);
    }

    return Status;
}

//-----------------------------------------------------------------------------
// Local functions - Mandatory label ACE

BOOL WINAPI MyAddMandatoryAce(PACL pAcl, DWORD dwAceRevision, DWORD dwAceFlags, DWORD MandatoryPolicy, PSID pSid)
{
    if(pfnAddMandatoryAce == NULL)
        return FALSE;

    // Call the function
    return pfnAddMandatoryAce(pAcl, dwAceRevision, dwAceFlags, MandatoryPolicy, pSid);
}

// TODO: 
// AddAccessAllowedObjectAce
// AddAccessDeniedObjectAce

//-----------------------------------------------------------------------------
// My own implementation of RtlComputeCrc32

/* CRC polynomial 0xedb88320 */
static const DWORD CRC_table[256] =
{
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

ULONG RtlComputeCrc32(ULONG InitialCrc, PVOID Buffer, ULONG Length)
{
    LPBYTE DataPtr = (LPBYTE)Buffer;
    DWORD Crc32 = ~InitialCrc;

    while (Length > 0)
    {
        Crc32 = CRC_table[(Crc32 ^ *DataPtr) & 0xff] ^ (Crc32 >> 8);
        DataPtr++;
        Length--;
    }
    
    return ~Crc32;
}

//-----------------------------------------------------------------------------
// Methods of the TDataBlob structure

DWORD TDataBlob::SetLength(SIZE_T cbNewData)
{
    LPBYTE pbNewData;
    SIZE_T cbNewDataAligned = ALIGN_TO_SIZE(cbNewData, WIN32_PAGE_SIZE);

    if(cbNewData > cbDataMax)
    {
        // Allocate new data
        pbNewData = (LPBYTE)VirtualAlloc(NULL, cbNewDataAligned, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if(pbNewData == NULL)
            return ERROR_NOT_ENOUGH_MEMORY;

        // Copy and free old data
        if(pbData != NULL)
        {
            if(cbData != 0)
                memcpy(pbNewData, pbData, cbData);
            VirtualFree(pbData, cbDataMax, MEM_RELEASE);
        }

        // Assign the new data
        pbData = pbNewData;
        cbDataMax = cbNewDataAligned;
    }

    // Set the new length and exit
    cbData = cbNewData;
    return ERROR_SUCCESS;
}

void TDataBlob::Free()
{
    if(pbData != NULL)
        VirtualFree(pbData, cbDataMax, MEM_RELEASE);

    pbData = NULL;
    cbData = 0;
    cbDataMax = 0;
}
