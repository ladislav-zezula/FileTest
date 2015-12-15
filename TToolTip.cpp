/*****************************************************************************/
/* TToolTip.cpp                           Copyright (c) Ladislav Zezula 2014 */
/*---------------------------------------------------------------------------*/
/* Implementation of TTooltip class                                          */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 16.03.14  1.00  Lad  The first version of TToolTip.cpp                    */
/*****************************************************************************/

#include "FileTest.h"

//-----------------------------------------------------------------------------
// Tooltip implementation

TToolTip::TToolTip()
{
    hWndToolTip = NULL;
    szToolTipText = NULL;
    cchTooltipText = 0x400;
};

TToolTip::~TToolTip()
{
    Destroy();
}

BOOL TToolTip::Initialize(HINSTANCE hInst, HWND hWndParent)
{
    // Sanity check
    assert(hWndToolTip == NULL);

    // Allocate buffer for constructing tooltip test
    szToolTipText = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, cchTooltipText * sizeof(TCHAR));
    if(szToolTipText == NULL)
        return FALSE;

    // Create the tooltip window
    hWndToolTip = CreateWindowEx(NULL,
                                 TOOLTIPS_CLASS,
                                 NULL,
                                 WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
                                 CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                                 hWndParent,
                                 NULL,
                                 hInst,
                                 NULL);
    if(hWndToolTip == NULL)
        return FALSE;

    // Initialize the tooltip window
    SetWindowPos(hWndToolTip, HWND_TOPMOST,0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    SendMessage(hWndToolTip, TTM_SETMAXTIPWIDTH, 0, 300);
    SendMessage(hWndToolTip, TTM_ACTIVATE, TRUE, 0);
    return TRUE;
}

void TToolTip::Destroy()
{
    if(hWndToolTip != NULL)
        DestroyWindow(hWndToolTip);
    hWndToolTip = NULL;

    if(szToolTipText != NULL)
        HeapFree(GetProcessHeap(), 0, szToolTipText);
    szToolTipText = NULL;
}

//-----------------------------------------------------------------------------
// Adds a tooltip that will display user-friendly flags

BOOL TToolTip::AddToolTip(HWND hDlg, UINT nIDChild, TFlagInfo * pFlags)
{
    return AddToolTipInternal(hDlg, nIDChild, LPSTR_TEXTCALLBACK, (LPARAM)pFlags);
}

BOOL TToolTip::AddToolTip(HWND hDlg, UINT nIDChild, UINT nIDTip)
{
    return AddToolTipInternal(hDlg, nIDChild, MAKEINTRESOURCE(nIDTip), 0);
}

//-----------------------------------------------------------------------------
// Message handler

LRESULT TToolTip::HandleMessages(HWND /* hDlg */, UINT uMsg, WPARAM /* wParam */, LPARAM lParam, BOOL * pbHandled)
{
    LPNMTTDISPINFO pTTDispInfo;
    BOOL bHandled = FALSE;

    if(uMsg == WM_NOTIFY)
    {
        // The message must be TTN_GETDISPINFO and the 'idFrom' must be a window handle
        pTTDispInfo = (LPNMTTDISPINFO)lParam;
        if(pTTDispInfo->hdr.code == TTN_GETDISPINFO && (pTTDispInfo->uFlags & TTF_IDISHWND) && pTTDispInfo->lParam != 0)
        {
            // Call the tooltip handler
            OnGetTooltipText(pTTDispInfo);
            bHandled = TRUE;
        }
    }

    if(pbHandled != NULL)
        *pbHandled = FALSE;
    return 0;
}

//-----------------------------------------------------------------------------
// Protected functions

BOOL TToolTip::AddToolTipInternal(HWND hDlg, UINT nIDCtrl, LPCTSTR szTip, LPARAM lParam)
{
    TTTOOLINFO ti;
    TCHAR szClassName[0x80];
    DWORD dwStyle;
    HWND hWndChild;
    BOOL bResult = FALSE;

    // Only if we actually have a tooltip
    if(hWndToolTip != NULL)
    {
        // If the child window is not valid, do nothing
        hWndChild = GetDlgItem(hDlg, nIDCtrl);
        if(hWndChild != NULL)
        {
            // If the child window is a static text without SS_NOTIFY,
            // the tooltip would not activate. We need to set the SS_NOTIFY flag
            GetClassName(hWndChild, szClassName, _maxchars(szClassName));
            if(!_tcsicmp(szClassName, WC_STATIC))
            {
                dwStyle = GetWindowLong(hWndChild, GWL_STYLE);
                if((dwStyle & SS_NOTIFY) == 0)
                    SetWindowLong(hWndChild, GWL_STYLE, dwStyle | SS_NOTIFY);
            }

            // Note: Make sure we put the size for COMCTL32.dll version 4.70
            ZeroMemory(&ti, sizeof(TTTOOLINFO));
            ti.cbSize   = CCSIZEOF_STRUCT(TTTOOLINFO, lParam);
            ti.uFlags   = TTF_IDISHWND | TTF_SUBCLASS;
            ti.hwnd     = hDlg;
            ti.uId      = (UINT_PTR)hWndChild;
            ti.hinst    = g_hInst;
            ti.lpszText = (LPTSTR)szTip;
            ti.lParam   = lParam;
            bResult = (BOOL)SendMessage(hWndToolTip, TTM_ADDTOOL, 0, (LPARAM)&ti);
        }
    }

    return bResult;
}

LPTSTR TToolTip::AddNewLine(LPTSTR szTextBuff, size_t cchMaxChars)
{
    StringCchCopy(szTextBuff, cchMaxChars, _T(" |\r\n"));
    return szTextBuff + 4;
}

void TToolTip::OnGetTooltipText(LPNMTTDISPINFO pTTDispInfo)
{
    TFlagInfo * pFlags = (TFlagInfo *)pTTDispInfo->lParam;
    LPTSTR szTextBuffEnd = szToolTipText + cchTooltipText;
    LPTSTR szTextBuff = szToolTipText;
    TCHAR szWindowText[0x80];
    DWORD dwValue32 = 0;
    HWND hWndChild = (HWND)pTTDispInfo->hdr.idFrom;

    // Only if the text buffer has been allocated
    if(pFlags != NULL && szTextBuff != NULL)
    {
        // Reset the tooltip info to an empty string
        szToolTipText[0] = 0;

        // Retrieve the window text and convert it to 32-bit hexa value
        GetWindowText(hWndChild, szWindowText, _maxchars(szWindowText));
        if(Text2Hex32(szWindowText, &dwValue32) == ERROR_SUCCESS)
        {
            // Supply the flags
            while(dwValue32 != 0 && pFlags->szFlagText != NULL)
            {
                // Is that flag set?
                if(IS_FLAG_SET(pFlags, dwValue32))
                {
                    size_t nLength = _tcslen(pFlags->szFlagText);

                    // Is there enough space left?
                    if((size_t)(szTextBuffEnd - szTextBuff) < (nLength + 0x20))
                        break;

                    // If there is a flag from the previous pass, append newline to it
                    if(szTextBuff > szToolTipText)
                        szTextBuff = AddNewLine(szTextBuff, (szTextBuffEnd - szTextBuff));

                    // Append the flag text
                    memcpy(szTextBuff, pFlags->szFlagText, (nLength + 1) * sizeof(TCHAR));
                    szTextBuff += nLength;

                    // Clear the bit from the 
                    dwValue32 &= ~pFlags->dwValue;
                }

                // Move to the next flag
                pFlags++;
            }

            // If there is no text or there are unknown flags left, put them as hexa value
            if(szTextBuff == szToolTipText || dwValue32 != 0)
            {
                // If there is a flag from the previous pass, append newline to it
                if(szTextBuff > szToolTipText)
                    szTextBuff = AddNewLine(szTextBuff, (szTextBuffEnd - szTextBuff));

                StringCchPrintf(szTextBuff, (szTextBuffEnd - szTextBuff), _T("0x%08X"), dwValue32);
            }

            // Supply the text to the tooltip
            pTTDispInfo->lpszText = szToolTipText;
            pTTDispInfo->szText[0] = 0;
        }
        else
        {
            StringCchPrintf(pTTDispInfo->szText, _countof(pTTDispInfo->szText), _T("Error converting \"%s\" to 32-bit integer"), szWindowText);
        }
    }
}

