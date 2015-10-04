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
    int nError = ERROR_INVALID_PARAMETER;

    // Perform the conversion of the child text to a 32-bit hexa value
    if(hWndChild != NULL)
    {
        // Retrieve the window text
        GetWindowText(hWndChild, szText, _tsize(szText));
    
        // Attempt to convert the value
        nError = Text2Hex32(szText, pValue);
        if(nError != ERROR_SUCCESS)
            ShowConversionError(hDlg, hWndChild);
    }

    return nError;
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
    int nError = ERROR_INVALID_PARAMETER;

    // Perform the conversion of the child text to a 32-bit hexa value
    if(hWndChild != NULL)
    {
        // Retrieve the window text
        GetWindowText(hWndChild, szText, _tsize(szText));
    
        // Attempt to convert the value
        nError = Text2HexPtr(szText, pValue);
        if(nError != ERROR_SUCCESS)
            ShowConversionError(hDlg, hWndChild);
    }

    return nError;
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
    int nError = ERROR_INVALID_PARAMETER;

    // Perform the conversion of the child text to a 32-bit hexa value
    if(hWndChild != NULL)
    {
        // Retrieve the window text
        GetWindowText(hWndChild, szText, _tsize(szText));
    
        // Attempt to convert the value
        nError = Text2Hex64(szText, pValue);
        if(nError != ERROR_SUCCESS)
            ShowConversionError(hDlg, hWndChild);
    }

    return nError;
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


HTREEITEM InsertTreeItem(HWND hTreeView, HTREEITEM hParentItem, HTREEITEM hInsertAfter, LPCTSTR szText, PVOID pParam)
{
    TVINSERTSTRUCT tvis;

    // If NULL specified as InsertAfter, we insert it after the last item
    if(hInsertAfter == NULL)
        hInsertAfter = TVI_LAST;
    
    // Insert the item to the tree
    tvis.hParent      = hParentItem;
    tvis.hInsertAfter = hInsertAfter;
    tvis.item.mask    = TVIF_TEXT | TVIF_PARAM;
    tvis.item.pszText = (LPTSTR)szText;
    tvis.item.lParam  = (LPARAM)pParam;
    return TreeView_InsertItem(hTreeView, &tvis);
}

HTREEITEM InsertTreeItem(HWND hTreeView, HTREEITEM hParentItem, LPCTSTR szText, PVOID pParam)
{
    return InsertTreeItem(hTreeView, hParentItem, NULL, szText, pParam);
}

//-----------------------------------------------------------------------------
// Virtualization for the current process

#define TOKEN_ELEVATION_TYPE_LIMITED_USER   0x00000001
#define TOKEN_ELEVATION_TYPE_ADMINISTRATOR  0x00000002

static BOOL GetTokenFlags(PDWORD PtrFlags, DWORD TokenInfoType)
{
    HANDLE hToken;
    DWORD dwLength = 0;
    DWORD dwFlags = 0;
    BOOL bResult = FALSE;

    if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        bResult = GetTokenInformation(hToken,
             (TOKEN_INFORMATION_CLASS)TokenInfoType,
                                     &dwFlags,
                                      sizeof(dwFlags),
                                     &dwLength);
        CloseHandle(hToken);
    }

    if(PtrFlags != NULL)
        PtrFlags[0] = dwFlags;
    return bResult;
}

static BOOL SetTokenFlags(DWORD dwFlags, DWORD TokenInfoType)
{
    HANDLE hToken;
    BOOL bResult = FALSE;

    if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT, &hToken))
    {
        bResult = SetTokenInformation(hToken,
             (TOKEN_INFORMATION_CLASS)TokenInfoType,
                                     &dwFlags,
                                      sizeof(dwFlags));
        CloseHandle(hToken);
    }

    return bResult;
}

BOOL IsLUAEnabled()
{
    LPCTSTR szKeyName = _T("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
    DWORD dwLuaEnabled = 0;
    DWORD dwLength = 0;
    HKEY hSubKey = NULL;

    // First, check if LUA is enabled at all
    if(!RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKeyName, 0, KEY_QUERY_VALUE, &hSubKey))
    {
        dwLuaEnabled = 0;        
        dwLength = sizeof(dwLuaEnabled);
        RegQueryValueEx(hSubKey, _T("EnableLUA"), NULL, NULL, (LPBYTE)&dwLuaEnabled, &dwLength);
        RegCloseKey(hSubKey);
    }

    return (BOOL)dwLuaEnabled;
}

// Returns TRUE if the program runs as restricted or elevated.
BOOL GetElevationFlags(PDWORD PtrFlags)
{
    // TokenElevationType, not defined in pre-Vista SDKs
    return GetTokenFlags(PtrFlags, 0x12);   
}

BOOL GetVirtualizationFlags(PDWORD PtrFlags)
{
    // TokenVirtualizationEnabled, not defined in pre-Vista SDKs
    return GetTokenFlags(PtrFlags, 0x18);
}

BOOL SetVirtualizationFlags(DWORD dwFlags)
{
    // TokenVirtualizationEnabled, not defined in pre-Vista SDKs
    return SetTokenFlags(dwFlags, 0x18);
}

//-----------------------------------------------------------------------------
// Application title

void GetFileTestAppTitle(LPTSTR szTitle, int nMaxChars)
{
    TCHAR szUserName[256] = _T("");
    DWORD dwElevationFlags = 0;
    DWORD dwSize = _tsize(szUserName);
    UINT nIDTitle = IDS_APP_TITLE;

    // Get the elevation flags. Note that this returns FALSE on pre-Vista
    if(GetElevationFlags(&dwElevationFlags))
        nIDTitle = (dwElevationFlags & TOKEN_ELEVATION_TYPE_ADMINISTRATOR) ? IDS_APP_TITLE_VISTA2 : IDS_APP_TITLE_VISTA1;

    GetUserName(szUserName, &dwSize);
    rsprintf(szTitle, nMaxChars, nIDTitle, szUserName);
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

static void CreateBlinkingIcon(HWND hDlg, HWND hWndChild, int nSeverity)
{
    TFileTestData * pData = GetDialogData(hDlg);
    HICON hIcon = NULL;
    POINT pt;
    HWND hWndBlink;
    RECT rect;
    UINT IconSet[] = {IDI_ICON_INFORMATION, IDI_ICON_ERROR, IDI_ICON_WAIT};

    // If there is already a blinker timer, destroy it
    DeleteBlinkTimer(hDlg);

    // Get the appropriate icon
    assert(nSeverity < _countof(IconSet));
    hIcon = (HICON)LoadImage(g_hInst, MAKEINTRESOURCE(IconSet[nSeverity]), IMAGE_ICON, 16, 16, LR_SHARED);
    if(hIcon == NULL)
        return;

    // Get the position of the child window
    GetWindowRect(hWndChild, &rect);
    pt.x = rect.left;
    pt.y = rect.top;
    ScreenToClient(hDlg, &pt);
    pt.x = pt.x - 18;
    pt.y = pt.y + (rect.bottom - rect.top - 16) / 2;

    // Create the window for icon
    hWndBlink = CreateWindowEx(WS_EX_NOPARENTNOTIFY,
                               WC_STATIC,
                               NULL,
                               WS_CHILD | WS_VISIBLE | SS_ICON,
                               pt.x, pt.y, 18, 18,
                               hDlg,
                               NULL,
                               g_hInst,
                               NULL);
    if(hWndBlink == NULL)
        return;

    // Apply the icon to the icon window
    SendMessage(hWndBlink, STM_SETICON, (WPARAM)hIcon, 0);

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

void SetResultInfo(HWND hDlg, NTSTATUS Status, HANDLE hHandle, UINT_PTR ResultLength, PLARGE_INTEGER pResultLength)
{
    LPCTSTR szStatus;
    LPTSTR szError;
    TCHAR szText[256] = _T("");
    HWND hWndChild;
    int nSeverity = SEVERITY_SUCCESS;
    BOOL bEnable = TRUE;

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

    // Set the text for NTSTATUS
    hWndChild = GetDlgItem(hDlg, IDC_RESULT_STATUS);
    if(hWndChild != NULL)
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

        SetWindowText(hWndChild, szStatus);
    }

    // Set the text for GetLastError() result
    hWndChild = GetDlgItem(hDlg, IDC_LAST_ERROR);
    if(hWndChild != NULL)
    {
        switch(Status)
        {
            case ERROR_SUCCESS:
                nSeverity = SEVERITY_SUCCESS;
                break;

            case ERROR_IO_PENDING:
                nSeverity = SEVERITY_PENDING;
                break;

            default:
                nSeverity = SEVERITY_ERROR;
                break;
        }

        // Format the result string
        szError = GetErrorText(Status);
        if(szError != NULL)
        {
            _stprintf(szText, _T("(0x%08lX) %s"), Status, szError);
            SetWindowText(hWndChild, szText);
            delete [] szError;
        }
    }

    // Set the handle, if present
    hWndChild = GetDlgItem(hDlg, IDC_HANDLE);
    if(hWndChild != NULL)
    {
        if(hHandle == INVALID_HANDLE_VALUE)
            SetWindowText(hWndChild, _T("INVALID_HANDLE_VALUE"));
        else if(hHandle == NULL)
            SetWindowText(hWndChild, _T("NULL"));
        else
            Hex2DlgTextPtr(hDlg, IDC_HANDLE, (DWORD_PTR)hHandle);
    }

    // Enable/disable the "CloseHandle" button, if present
    hWndChild = GetDlgItem(hDlg, IDC_CLOSE_HANDLE);
    if(hWndChild != NULL)
    {
        if(IsHandleInvalid(hHandle))
            bEnable = FALSE;
        EnableWindow(hWndChild, bEnable);
    }

    // Enable/disable the hint for close handle, if any
    hWndChild = GetDlgItem(hDlg, IDC_CLOSE_HANDLE_HINT);
    if(hWndChild != NULL)
    {
        if(IsHandleInvalid(hHandle))
            bEnable = FALSE;
        EnableWindow(hWndChild, bEnable);
    }

    // Set the extra length, if present
    hWndChild = GetDlgItem(hDlg, IDC_IOSTATUS_INFO);
    if(hWndChild != NULL)
    {
        if(pResultLength != NULL)
        {
            Hex2Text64(szText, (ULONGLONG)pResultLength->QuadPart);
            SetWindowText(hWndChild, szText);
        }
        else
        {
            Hex2Text32(szText, (DWORD)ResultLength);
            SetWindowText(hWndChild, szText);
        }
    }

    // Set the result of NtCreate, if present
    hWndChild = GetDlgItem(hDlg, IDC_NTCREATE_RESULT);
    if(hWndChild != NULL && NT_SUCCESS(Status))
        SetWindowEnumText(hWndChild, szNtCreateResult, _countof(szNtCreateResult), (size_t)ResultLength);

    // Blink the icon on LastError, if any
    hWndChild = GetDlgItem(hDlg, IDC_LAST_ERROR);
    if(hWndChild != NULL)
    {
        CreateBlinkingIcon(hDlg, hWndChild, nSeverity);
    }

    // Blink the icon on status, if any
    hWndChild = GetDlgItem(hDlg, IDC_RESULT_STATUS);
    if(hWndChild != NULL)
    {
        CreateBlinkingIcon(hDlg, hWndChild, nSeverity);
    }
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
ADDMANDATORYACE          pfnAddMandatoryAce = NULL;

static HINSTANCE hNtdll = NULL;
static HINSTANCE hKernel32 = NULL;
static HINSTANCE hAdvapi32 = NULL;
static HINSTANCE hKtmw32 = NULL;

void ResolveDynamicLoadedAPIs()
{
    // Get imports from Ntdll.dll
    if(hNtdll == NULL)
    {
        hNtdll = LoadLibrary(_T("Ntdll.dll"));
        if(hNtdll != NULL)
        {
            pfnRtlGetCurrentTransaction = (RTLGETCURRENTTRANSACTION)
                                          GetProcAddress(hNtdll, "RtlGetCurrentTransaction");
            pfnRtlSetCurrentTransaction = (RTLSETCURRENTTRANSACTION)
                                          GetProcAddress(hNtdll, "RtlSetCurrentTransaction");
        }
    }

    // Get imports from Kernel32.dll
    if(hKernel32 == NULL)
    {
        hKernel32 = LoadLibrary(_T("Kernel32.dll"));
        if(hKernel32 != NULL)
        {
#ifdef _UNICODE
            pfnCreateDirectoryTransacted = (CREATEDIRTRANSACTED)GetProcAddress(hKernel32, "CreateDirectoryTransactedW");
            pfnCreateFileTransacted = (CREATEFILETRANSACTED)GetProcAddress(hKernel32, "CreateFileTransactedW");
#else
            pfnCreateDirectoryTransacted = (CREATEDIRTRANSACTED)GetProcAddress(hKernel32, "CreateDirectoryTransactedA");
            pfnCreateFileTransacted = (CREATEFILETRANSACTED)GetProcAddress(hKernel32, "CreateFileTransactedA");
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
    int nLength = GetWindowTextLength(hWndEdit);

    // Only do something if the text length is > 0)
    if(nLength > 0)
    {
        // Allocate buffer
        szFileName = new TCHAR[nLength + 1];
        if(szFileName != NULL)
        {
            // Get the window text
            // If it already appears to be an Win32 name, do nothing
            GetWindowText(hWndEdit, szFileName, nLength + 1);

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
                szNewFileName = new TCHAR[nLength + wcslen(szGlobalRootMaskW) + 1];
                if(szNewFileName != NULL)
                {
                    _stprintf(szNewFileName, _T("%s%s"), szGlobalRootMaskW, szFileName);
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
    int nError = ERROR_SUCCESS;

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
            nError = Text2Hex64(szFileOrObjId, (PLONGLONG)pvFileObjId);
            break;

        case 0x20:
            for(int i = 0; i < 0x10; i++)
            {
                if(szFileOrObjId[0] > 0x80 || szFileOrObjId[1] > 0x80)
                {
                    nError = ERROR_BAD_FORMAT;
                    break;
                }

                // Convert the first character
                OneChar = *szFileOrObjId++;
                if(CharToValue[OneChar] == 0xFF)
                {
                    nError = ERROR_BAD_FORMAT;
                    break;
                }
                OneByte = CharToValue[OneChar] << 0x04;

                // Convert the second character
                OneChar = *szFileOrObjId++;
                if(CharToValue[OneChar] == 0xFF)
                {
                    nError = ERROR_BAD_FORMAT;
                    break;
                }
                OneByte |= CharToValue[OneChar];
                *pbObjectID++ = OneByte;
            }
            dwLength = 0x10;
            break;

        default:
            nError = ERROR_BAD_FORMAT;
            break;
    }

    // Give the output length
    if(nError == ERROR_SUCCESS && pLength != NULL)
        *pLength = dwLength;
    return nError;
}

int ExecuteContextMenu(HWND hWndParent, UINT nIDMenu, LPARAM lParam)
{
    HMENU hMainMenu = LoadMenu(g_hInst, MAKEINTRESOURCE(nIDMenu));
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
        DestroyMenu(hMainMenu);
    }

    return TRUE;
}

int ExecuteContextMenuForDlgItem(HWND hDlg, UINT nIDCtrl, UINT nIDMenu)
{
    LPARAM lParam;
    HWND hWndChild = GetDlgItem(hDlg, nIDCtrl);
    RECT rect;

    // Calculate position of the menu
    GetWindowRect(hWndChild, &rect);
    lParam = MAKELPARAM(rect.left, rect.bottom);

    // Execute the context menu
    return ExecuteContextMenu(hDlg, nIDMenu, lParam);
}
