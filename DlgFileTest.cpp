/*****************************************************************************/
/* DlgFileTest.cpp                        Copyright (c) Ladislav Zezula 2009 */
/*---------------------------------------------------------------------------*/
/* Description :                                                             */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 27.05.09  1.00  Lad  The first version of DlgFileTest.cpp                 */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local variables

#define SC_HELP_ABOUT (SC_CLOSE + 0x800)

static BOOL bDisableDialogMessages = FALSE;

//-----------------------------------------------------------------------------
// Thread moving the dialog

static DWORD WINAPI MoveDialogThread(PVOID pParam)
{
    TWindowData * pData = (TWindowData *)pParam;
    int nCurrentY = pData->nStartY;
    int nAddY;

    // Determine the direction
    nAddY = (pData->nEndY > pData->nStartY) ? +1 : -1;

    for(;;)
    {
        // Move the dialog
        nCurrentY += nAddY;

        // Check for end of moving
        if(pData->nEndY > pData->nStartY && nCurrentY > pData->nEndY)
            break;
        if(pData->nEndY < pData->nStartY && nCurrentY < pData->nEndY)
            break;

        // Move the entire dialog
        SetWindowPos(pData->hDlg, NULL, pData->nStartX, nCurrentY, 0, 0, SWP_NOZORDER | SWP_NOSIZE | SWP_NOACTIVATE);
    }

    // We are done; close the thread handle and refresh the dialog position
    GetWindowRect(pData->hDlg, &pData->DialogRect);
    CloseHandle(pData->hThread);
    pData->hThread = NULL;
    return 0;
}

//-----------------------------------------------------------------------------
// "APC" thread - performing wait on all queued APCs and sends message
// when an APC is awaken

#define ALERT_REASON_STOP_WORKER    0               // The worker needs to stop
#define ALERT_REASON_UPDATE_WAIT    1               // The wait list needs to be updated

static DWORD WINAPI ApcThread(LPVOID pvParameter)
{
    TWindowData * pData = (TWindowData *)pvParameter;
    PLIST_ENTRY pHeadEntry;
    PLIST_ENTRY pListEntry;
    TApcEntry * ApcList[MAXIMUM_WAIT_OBJECTS];
    HANDLE WaitHandles[MAXIMUM_WAIT_OBJECTS];
    TApcEntry * pApc;

    // The first event is always the alert event
    WaitHandles[0] = pData->hAlertEvent;
    assert(pData->hAlertEvent != NULL);

    // Perform a loop until the process does not end
    while(pData->hAlertEvent != NULL)
    {
        DWORD dwWaitCount = 1;
        DWORD dwWaitResult;

        // Prepare the list of handles to wait
        EnterCriticalSection(&pData->ApcLock);
        pHeadEntry = &pData->ApcList;
        for(pListEntry = pHeadEntry->Flink; pListEntry != pHeadEntry; pListEntry = pListEntry->Flink)
        {
            // Retrieve the APC entry
            pApc = CONTAINING_RECORD(pListEntry, TApcEntry, Entry);

            // Insert the APC entry to the wait list
            WaitHandles[dwWaitCount] = pApc->hEvent;
            ApcList[dwWaitCount++] = pApc;
        }
        LeaveCriticalSection(&pData->ApcLock);

        // Now when the list if prepared, we can perform wait on all
        assert(dwWaitCount < MAXIMUM_WAIT_OBJECTS);
        dwWaitResult = WaitForMultipleObjects(dwWaitCount, WaitHandles, FALSE, INFINITE);

        // If the first wait broke, it means that we need to exit
        if(dwWaitResult == WAIT_OBJECT_0 || dwWaitResult == WAIT_ABANDONED_0)
        {
            // If we need just to update wait list, do it
            if(pData->dwAlertReason == ALERT_REASON_UPDATE_WAIT)
                continue;                        
            break;
        }

        // Check if any of the APCs has broken
        if(WAIT_OBJECT_0 < dwWaitResult && dwWaitResult < (WAIT_OBJECT_0 + dwWaitCount))
        {
            // Get the pointer to the triggered APC
            pApc = ApcList[dwWaitResult - WAIT_OBJECT_0];
            assert(pApc != NULL);

            // Lock the list and remove the APC from the list
            EnterCriticalSection(&pData->ApcLock);
            RemoveEntryList(&pApc->Entry);
            pData->nApcCount--;
            LeaveCriticalSection(&pData->ApcLock);

            // Send the APC to the main dialog
            // Note that the main dialog is responsible for freeing the APC
            PostMessage(pData->hDlg, WM_APC, 0, (LPARAM)pApc);
        }
    }

    // Now we need to free all the APCs
    EnterCriticalSection(&pData->ApcLock);
    pHeadEntry = &pData->ApcList;
    for(pListEntry = pHeadEntry->Flink; pListEntry != pHeadEntry; )
    {
        // Retrieve the APC entry
        pApc = CONTAINING_RECORD(pListEntry, TApcEntry, Entry);
        pListEntry = pListEntry->Flink;

        // Remove the APC from the list and free it
        RemoveEntryList(&pApc->Entry);
        FreeApcEntry(pApc);
    }
    pData->nApcCount = 0;;
    LeaveCriticalSection(&pData->ApcLock);
    
    return 0;
}

static void AlertApcThread(TWindowData * pData, DWORD dwAlertReason)
{
    // Signal the event handle and close it
    if(pData->hApcThread && pData->hAlertEvent)
    {
        pData->dwAlertReason = dwAlertReason;
        SetEvent(pData->hAlertEvent);
    }
}

//-----------------------------------------------------------------------------
// Local functions

static void InitializeTabControl(HWND hDlg, TWindowData * pData)
{
    PROPSHEETHEADER psh;
    PROPSHEETPAGE psp[13];
    TCHAR szAppTitle[256];
    HWND hTabCtrl = GetDlgItem(hDlg, IDC_TAB);
    int nPages = 0;

    // Get the title of FileTest application
    GetFileTestAppTitle(szAppTitle, _maxchars(szAppTitle));

    // Fill the property sheet header
    ZeroMemory(&psh, sizeof(PROPSHEETHEADER));
    psh.dwSize     = sizeof(PROPSHEETHEADER);
    psh.dwFlags    = PSH_PROPSHEETPAGE | PSH_USEICONID | PSH_NOAPPLYNOW | PSH_NOCONTEXTHELP | PSH_MODELESS;
    psh.hwndParent = hDlg;
    psh.hInstance  = g_hInst;
    psh.pszIcon    = MAKEINTRESOURCE(IDI_FILE_TEST);
    psh.pszCaption = szAppTitle;
    psh.nStartPage = 1;
    psh.ppsp       = psp;

    // Fill the "Transaction" page (Vista only)
    if(pfnCreateTransaction != NULL)
    {
        ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
        psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
        psp[nPages].dwFlags     = PSP_DEFAULT;
        psp[nPages].hInstance   = g_hInst;
        psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE00_TRANSACTION);
        psp[nPages].pfnDlgProc  = PageProc00;
        psp[nPages].lParam      = (LPARAM)pData;
        nPages++;
    }

    // Fill the "CreateFile" page
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE01_CREATE);
    psp[nPages].pfnDlgProc  = PageProc01;
    psp[nPages].lParam      = (LPARAM)pData;
    psh.nStartPage = nPages;
    nPages++;

    // Fill the "NtCreateFile"
    // Note: If the file name looks like an NT name, go to NtCreateFile page
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE02_NTCREATE);
    psp[nPages].pfnDlgProc  = PageProc02;
    psp[nPages].lParam      = (LPARAM)pData;
    if(IsNativeName(((TFileTestData *)pData)->szFileName1))
        psh.nStartPage = nPages;
    nPages++;

    // Fill the "ReadWrite"
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE03_READWRITE);
    psp[nPages].pfnDlgProc  = PageProc03;
    psp[nPages].lParam      = (LPARAM)pData;
    nPages++;

    // Fill the "Mapping"
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE04_MAPPING);
    psp[nPages].pfnDlgProc  = PageProc04;
    psp[nPages].lParam      = (LPARAM)pData;
    nPages++;

    // Fill the "File Ops".
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE05_FILEOPS);
    psp[nPages].pfnDlgProc  = PageProc05;
    psp[nPages].lParam      = (LPARAM)pData;
    nPages++;

    // Fill the "NtFileInfo" page
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE06_NTFILEINFO);
    psp[nPages].pfnDlgProc  = PageProc06;
    psp[nPages].lParam      = (LPARAM)pData;
    nPages++;

    // Fill the "NtFsInfo" page.
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE07_NTVOLINFO);
    psp[nPages].pfnDlgProc  = PageProc06;
    psp[nPages].lParam      = (LPARAM)pData;
    nPages++;

    // Fill the "EA" page.
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE08_EA);
    psp[nPages].pfnDlgProc  = PageProc08;       // The same like NtFileInfo
    psp[nPages].lParam      = (LPARAM)pData;
    nPages++;

    // Fill the "Security".
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE09_SECURITY);
    psp[nPages].pfnDlgProc  = PageProc09;
    psp[nPages].lParam      = (LPARAM)pData;
    nPages++;

    // Fill the "Links".
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE10_LINKS);
    psp[nPages].pfnDlgProc  = PageProc10;
    psp[nPages].lParam      = (LPARAM)pData;
    nPages++;

    // Fill the "Streams".
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE11_STREAMS);
    psp[nPages].pfnDlgProc  = PageProc11;
    psp[nPages].lParam      = (LPARAM)pData;
    nPages++;
    psh.nPages = nPages;

    // Create Tab Control
    TabCtrl_Create(hTabCtrl, &psh);

    // Get the currently selected page HWND
    pData->hWndPage = TabCtrl_GetSelectedPage(hTabCtrl);
}

static void RefreshScreenSize(HWND hDlg)
{
    TWindowData * pData = GetDialogData(hDlg);
    int nScreenHeight;
    int nDialogHeight;

    // Save the screen size
    SystemParametersInfo(SPI_GETWORKAREA, 0, &pData->ScreenRect, 0);
    GetWindowRect(hDlg, &pData->DialogRect);

    // Is the dialog higher than the screen?
    nScreenHeight = pData->ScreenRect.bottom - pData->ScreenRect.top;
    nDialogHeight = pData->DialogRect.bottom - pData->DialogRect.top;
    pData->bDialogBiggerThanScreen = (nDialogHeight > nScreenHeight);

    // If the dialog is bigger than the screen, set the timer
    if(pData->bDialogBiggerThanScreen)
    {
        if(pData->CheckMouseTimer == 0)
        {
            pData->CheckMouseTimer = SetTimer(hDlg, WM_TIMER_CHECK_MOUSE, 500, NULL);
        }
    }
    else
    {
        if(pData->CheckMouseTimer != 0)
        {
            KillTimer(hDlg, pData->CheckMouseTimer);
            pData->CheckMouseTimer = 0;
        }
    }
}

//-----------------------------------------------------------------------------
// Original dialog size

#pragma pack(1)
typedef struct _DLGTEMPLATEEX_BEGIN
{
    WORD  dlgVer;
    WORD  signature;
    DWORD helpID;
    DWORD exStyle;
    DWORD style;
    WORD  cDlgItems;
    short x;
    short y;
    short cx;
    short cy;
} DLGTEMPLATEEX_BEGIN, *PDLGTEMPLATEEX_BEGIN;
#pragma pack()

int GetDialogRectFromTemplate(HWND hDlg, UINT DlgResID, RECT & DlgRect)
{
    PDLGTEMPLATEEX_BEGIN pDlgTemplate;
    HGLOBAL hDlgRes;
    HRSRC hResource;

    hResource = FindResource(g_hInst, MAKEINTRESOURCE(DlgResID), RT_DIALOG);
    if(hResource != NULL)
    {
        hDlgRes = LoadResource(g_hInst, hResource);
        if(hDlgRes != NULL)
        {
            pDlgTemplate = (DLGTEMPLATEEX_BEGIN *)LockResource(hDlgRes);
            if(pDlgTemplate != NULL)
            {
                // Check the dialog template
                assert(pDlgTemplate->signature == (WORD)-1);
                assert(pDlgTemplate->dlgVer == 1);

                // Calculate the dialog size in pixels
                DlgRect.top = 0;
                DlgRect.left = 0;
                DlgRect.right = pDlgTemplate->cx;
                DlgRect.bottom = pDlgTemplate->cy;
                MapDialogRect(hDlg, &DlgRect);

                // Append the borders and the caption
                DlgRect.right += (GetSystemMetrics(SM_CXSIZEFRAME) * 2);
                DlgRect.bottom += GetSystemMetrics(SM_CYCAPTION) + (GetSystemMetrics(SM_CYSIZEFRAME) * 2);
                return ERROR_SUCCESS;
            }
        }
    }

    return ERROR_RESOURCE_NOT_FOUND;
}

static void FixDialogToOriginalSize(HWND hDlg, UINT DlgResID)
{
    RECT OriginalRect;
    RECT CurrentRect;
    RECT ScreenRect;
    int x;

    // Get the work area of the screen
    SystemParametersInfo(SPI_GETWORKAREA, 0, &ScreenRect, 0);
    ScreenRect.bottom = (ScreenRect.bottom - ScreenRect.top);
    ScreenRect.right = (ScreenRect.right - ScreenRect.left);

    // Get the current dialog size
    GetWindowRect(hDlg, &CurrentRect);
    CurrentRect.bottom = (CurrentRect.bottom - CurrentRect.top);
    CurrentRect.right = (CurrentRect.right - CurrentRect.left);
    CurrentRect.left = CurrentRect.top = 0;

    // If the current height is greater than height
    // of the worker area, we need to fix it
    if(CurrentRect.bottom > ScreenRect.bottom)
    {
        // Get the dialog expected size
        GetDialogRectFromTemplate(hDlg, DlgResID, OriginalRect);

        // If the dialog has been shrunk, fix its size
        if(OriginalRect.bottom > CurrentRect.bottom)
        {
            x = (ScreenRect.right - OriginalRect.right) / 2;
            SetWindowPos(hDlg, NULL, x, 0, OriginalRect.right, OriginalRect.bottom, SWP_NOZORDER | SWP_NOACTIVATE);
        }
    }
}

static void AddAboutToSystemMenu(HWND hDlg)
{
    MENUITEMINFO mii;
    HMENU hSysMenu;
    TCHAR szItemText[256];
    int nSeparatorIndex = -1;
    int nMenuCount;

    // Retrieve system menu
    hSysMenu = GetSystemMenu(hDlg, FALSE);
    if(hSysMenu != NULL)
    {
        // Find the separator
        nMenuCount = GetMenuItemCount(hSysMenu);
        for(int i = 0; i < nMenuCount; i++)
        {
            // Retrieve the item type
            ZeroMemory(&mii, sizeof(MENUITEMINFO));
            mii.cbSize = sizeof(MENUITEMINFO);
            mii.fMask = MIIM_FTYPE;
            GetMenuItemInfo(hSysMenu, i, TRUE, &mii);

            // Separator?
            if(mii.fType == MFT_SEPARATOR)
            {
                nSeparatorIndex = i;
                break;
            }
        }

        // If we found a separator, we need to add two more items
        if(nSeparatorIndex != -1)
        {
            LoadString(g_hInst, IDS_HELP_ABOUT, szItemText, _maxchars(szItemText));
            InsertMenu(hSysMenu, nSeparatorIndex, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
            InsertMenu(hSysMenu, nSeparatorIndex+1, MF_BYPOSITION | MF_STRING, SC_HELP_ABOUT, szItemText);
        }
    }
}

//-----------------------------------------------------------------------------
// Dialog handlers

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    TWindowData * pData = (TWindowData *)lParam;
    DWORD dwThreadId;

    // Initialize dialog data
    ZeroMemory(pData, sizeof(TWindowData));
    InitializeCriticalSection(&pData->ApcLock);
    InitializeListHead(&pData->ApcList);
    pData->hDlg = hDlg;
    SetDialogData(hDlg, pData);

    // Add "About" in the system menu
    AddAboutToSystemMenu(hDlg);

    //
    // Note: If the screen size is too low at this point (like 800x600),
    // the dialog gets shrinked. We need to resize the dialog to the original size
    //

    FixDialogToOriginalSize(hDlg, IDD_FILE_TEST);

    // Create the tooltip window
    g_Tooltip.Initialize(g_hInst, hDlg);

    // Initialize Tab Control
    InitializeTabControl(hDlg, pData);

    // Refresh information about screen rect and dialog rect
    RefreshScreenSize(hDlg);

    // Create the so called "APC" thread that will monitor our list of APC entries
    pData->hAlertEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    pData->hApcThread = CreateThread(NULL, 0, ApcThread, pData, 0, &dwThreadId);
    return TRUE;
}

static void OnSize(HWND hDlg, LPARAM lParam)
{
    TWindowData * pData = GetDialogData(hDlg);
    HWND hTabCtrl = GetDlgItem(hDlg, IDC_TAB);
    HWND hButton = GetDlgItem(hDlg, IDC_EXIT);
    RECT rect;
    int nHeight = HIWORD(lParam);
    int nWidth = LOWORD(lParam);
    int x, y, cx, cy;

    // Sanity check for zero size
    if(pData != NULL && nWidth != 0 && nHeight != 0)
    {
        // If the dialog hasn't done the initial resize,
        // we have to remember the relative sizes of the tab control
        // and the exit button
        if(!pData->bInitialResizeDone)
        {
            // Save the relative position of the tab control
            GetWindowRect(hTabCtrl, &rect);
            ScreenRectToClientRect(hDlg, &rect);
            pData->nTabInnerTop = rect.top;
            pData->nTabInnerLeft = rect.left;
            pData->nTabInnerRight = pData->nTabInnerTop;
            pData->nTabInnerBottom = pData->nTabInnerTop;

            // Save position of the "Exit" button
            GetWindowRect(hButton, &rect);
            pData->nButtonInnerRight = pData->nTabInnerRight + (rect.right - rect.left);
            pData->nButtonInnerBottom = pData->nTabInnerBottom + (rect.bottom - rect.top);

            // Update the inner bottom margin of the tab cobtrol
            pData->nTabInnerBottom = pData->nButtonInnerBottom + 8;
            pData->bInitialResizeDone = true;
        }

        // Resize the tab control
        cx = nWidth - (pData->nTabInnerLeft + pData->nTabInnerRight);
        cy = nHeight - (pData->nTabInnerTop + pData->nTabInnerBottom);
        TabCtrl_Resize(hTabCtrl, pData->nTabInnerLeft, pData->nTabInnerTop, cx, cy);

        // Move the Exit button
        x = nWidth - pData->nButtonInnerRight;
        y = nHeight - pData->nButtonInnerBottom;
        SetWindowPos(hButton, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    }
}

static void OnGetMinMaxInfo(HWND /* hDlg */, LPARAM lParam)
{
    LPMINMAXINFO pmmi = (LPMINMAXINFO)lParam;

    pmmi->ptMinTrackSize.x = 490;
    pmmi->ptMinTrackSize.y = 700;
}

static void OnTimerCheckMouse(HWND hDlg)
{
    TWindowData * pData = GetDialogData(hDlg);
    POINT pt;
    DWORD ThreadID;
    int nTresholdX = 40;
    int nTresholdY = pData->ScreenRect.bottom - 40;

    // Get the current mouse position
    GetCursorPos(&pt);

    // If the dialog is currently bigger than the screen, check for limit values
    if(pData->bDialogBiggerThanScreen)
    {
        // Only do something if the mouse cursor is within our rectangle
        if(GetActiveWindow() == hDlg && PtInRect(&pData->DialogRect, pt))
        {
            if(pData->DialogRect.top < pData->ScreenRect.top && pt.y <= nTresholdX)
            {
                // Create thread that will move the dialog down
                if(pData->hThread == NULL)
                {
                    pData->nStartX = pData->DialogRect.left;
                    pData->nStartY = pData->DialogRect.top;
                    pData->nEndY = 0;
                    pData->hThread = CreateThread(NULL, 0, MoveDialogThread, pData, 0, &ThreadID);
                }
                return;
            }

            if(pData->DialogRect.bottom > pData->ScreenRect.bottom && pt.y >= nTresholdY)
            {
                // Create thread that will move the dialog up
                if(pData->hThread == NULL)
                {
                    pData->nStartX = pData->DialogRect.left;
                    pData->nStartY = pData->DialogRect.top;
                    pData->nEndY = (pData->ScreenRect.bottom - pData->ScreenRect.top) - (pData->DialogRect.bottom - pData->DialogRect.top);
                    pData->hThread = CreateThread(NULL, 0, MoveDialogThread, pData, 0, &ThreadID);
                }
                return;
            }
        }
    }
}

static void OnApc(HWND /* hDlg */, LPARAM lParam)
{
    TApcEntry * pApc = (TApcEntry *)lParam;

    // Only if the APC is valid
    if(pApc != NULL)
    {
        // Let the same page to handle the APC operation.
        // The page may be invisible (switched away from) at the moment,
        // but it must exist
        if(IsWindow(pApc->hWndPage))
            SendMessage(pApc->hWndPage, WM_APC, 0, lParam);

        // Delete the APC after the page has handled it.
        FreeApcEntry(pApc);
    }
}

static void OnHelpAbout(HWND hDlg)
{
    HelpAboutDialog(hDlg);
}

static BOOL OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    // IDC_EXIT or IDCANCEL pressed
    if(nNotify == BN_CLICKED && bDisableDialogMessages == FALSE)
    {
        if(nIDCtrl == IDCANCEL || nIDCtrl == IDC_EXIT)
        {
            EndDialog(hDlg, nIDCtrl);
            PostQuitMessage(nIDCtrl);
            return TRUE;
        }
    }

    return FALSE;
}

static void OnNotify(HWND hDlg, NMHDR * pNMHDR)
{
    TWindowData * pData;

    if(pNMHDR->code == TCN_SELCHANGE)
    {
        pData = GetDialogData(hDlg);
        pData->hWndPage = TabCtrl_GetSelectedPage(pNMHDR->hwndFrom);
    }
}

static void OnClose(HWND hDlg)
{
    TWindowData * pData = GetDialogData(hDlg);

    if(pData->hApcThread != NULL)
    {
        // Stop the watcher thread, if any
        AlertApcThread(pData, ALERT_REASON_STOP_WORKER);

        // Wait for the thread to exit. Not more than 5 second
        WaitForSingleObject(pData->hApcThread, 5000);
        CloseHandle(pData->hApcThread);
    }

    // Close the alert event handle
    if(pData->hAlertEvent != NULL)
        CloseHandle(pData->hAlertEvent);
    pData->hAlertEvent = NULL;

    // Delete the APC critical section
    DeleteCriticalSection(&pData->ApcLock);
}

static INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // Let Tab Control handle messages belonging to it
    if(TabCtrl_HandleMessages(GetDlgItem(hDlg, IDC_TAB), uMsg, wParam, lParam))
        return TRUE;

    // Handle messages that have been passed to us
    switch(uMsg)
    {
        case WM_INITDIALOG:
            OnInitDialog(hDlg, lParam);
            return TRUE;

        case WM_SIZE:
            OnSize(hDlg, lParam);
            return FALSE;

        case WM_GETMINMAXINFO:
            OnGetMinMaxInfo(hDlg, lParam);
            return FALSE;

        case WM_WINDOWPOSCHANGED:
        case WM_DISPLAYCHANGE:
            RefreshScreenSize(hDlg);
            break;

        case WM_SETTINGCHANGE:
            if(wParam == SPI_SETWORKAREA)
                RefreshScreenSize(hDlg);
            break;

        case WM_TIMER:
            if(wParam == WM_TIMER_CHECK_MOUSE)
                OnTimerCheckMouse(hDlg);
            break;

        case WM_APC:
            OnApc(hDlg, lParam);
            return TRUE;

        case WM_COMMAND:
            return OnCommand(hDlg, HIWORD(wParam), LOWORD(wParam));

        case WM_SYSCOMMAND:
            if(wParam == SC_HELP_ABOUT)
                OnHelpAbout(hDlg);
            break;

        case WM_NOTIFY:
            OnNotify(hDlg, (NMHDR *)lParam);
            break;

        case WM_CLOSE:
            OnClose(hDlg);
            break;
    }

    return FALSE;
}

static BOOL IsMyDialogMessage(HWND hDlg, HWND hTabCtrl, LPMSG pMsg)
{
    int nPageCount;
    int nPageIndex;
    BOOL bNextTab = TRUE;

    // Support for navigation keys
    if(pMsg->message == WM_KEYDOWN)
    {
        if(GetAsyncKeyState(VK_CONTROL) & 0x8000)
        {
            switch(pMsg->wParam)
            {
                case VK_TAB:        // Ctrl+Tab: select next
                                    // Ctrl+Shift+Tab: Select previous
                    if(GetAsyncKeyState(VK_SHIFT) & 0x8000)
                        bNextTab = FALSE;
                    break;

                case VK_PRIOR:      // Ctrl+PgUp: Select previous page
                    bNextTab = FALSE;
                    break;

                case VK_NEXT:       // Ctrl+PgDown: Select next page
                    bNextTab = TRUE;
                    break;

                default:
                    goto __KeyNotSupported;   // Other keys: Do nothing
            }

            // Get total number of tabs and the index of the current tab
            nPageCount = TabCtrl_GetItemCount(hTabCtrl);
            nPageIndex = TabCtrl_GetCurSel(hTabCtrl);

            // Determine index of the page to be selected next
            if(bNextTab == FALSE)
                nPageIndex += (nPageCount - 1);
            else
                nPageIndex++;
            nPageIndex %= nPageCount;

            // Select the given tab
            TabCtrl_SelectPageByIndex(hTabCtrl, nPageIndex);
            return TRUE;
        }

        // Enter key: Pass it to the dialog as-is
        if(pMsg->wParam == VK_RETURN || pMsg->wParam == VK_SPACE)
            return FALSE;

        // If the dialog messages are disabled, we pass all key messages as-is.
        // Example: When editing a tree view item, Enter and Esc key would
        // be eaten by the dialog and they would never arrive to the edit box.
        if(bDisableDialogMessages)
            return FALSE;
    }

__KeyNotSupported:
    return IsDialogMessage(hDlg, pMsg);
}

//-----------------------------------------------------------------------------
// Public functions - APC support

TApcEntry * CreateApcEntry(TWindowData * pData, UINT ApcType, size_t cbApcSize)
{
    TApcEntry * pApc = NULL;

    // If there is too many APCs queued, do nothing
    if(pData->nApcCount < MAXIMUM_WAIT_OBJECTS - 1)
    {
        // Allocate space for the APC structure
        pApc = (TApcEntry *)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, cbApcSize);
        if(pApc != NULL)
        {
            // Create new event object for the APC entry
            pApc->Overlapped.hEvent =
            pApc->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
            pApc->ApcType = ApcType;
            pApc->hWndPage = pData->hWndPage;
            if(pApc->hEvent != NULL)
                return pApc;

            // Free the (now useless) APC entry
            HeapFree(g_hHeap, 0, pApc);
        }
    }

    // Failed
    return NULL;
}

bool InsertApcEntry(TWindowData * pData, TApcEntry * pApc)
{
    // Only if the APC is valid
    if(pApc != NULL)
    {
        // Sanity check
        assert(pApc->hEvent != NULL);

        // If there is too many APCs queued, do nothing
        if(pData->nApcCount < MAXIMUM_WAIT_OBJECTS - 1)
        {
            // Insert the APC to the APC list.
            // The APC thread does not know about it yet
            EnterCriticalSection(&pData->ApcLock);
            InsertTailList(&pData->ApcList, &pApc->Entry);
            pData->nApcCount++;
            LeaveCriticalSection(&pData->ApcLock);

            // Alert the APC thread so it knows that it needs to update the APC list
            AlertApcThread(pData, ALERT_REASON_UPDATE_WAIT);
            return true;
        }
    }

    // TODO: Memory leak when failed!!!
    return false;
}

void FreeApcEntry(TApcEntry * pApc)
{
    if(pApc != NULL)
    {
        if(pApc->hEvent != NULL)
            CloseHandle(pApc->hEvent);
        HeapFree(g_hHeap, 0, pApc);
    }
}

//-----------------------------------------------------------------------------
// Public functions

int NtUseFileId(HWND hDlg, LPCTSTR szFileId)
{
    TFileTestData * pData = GetDialogData(hDlg);
    LPCTSTR szPlainName = szFileId + 3;
    HWND hWndParent = GetParent(hDlg);
    HWND hTabCtrl = GetDlgItem(hWndParent, IDC_TAB);

    // The file ID is expected in the format of "X:\################"
    if(szFileId[1] != _T(':') || szFileId[2] != _T('\\'))
        return ERROR_BAD_FORMAT;

    // The file ID must not contain special characters
    if(_tcschr(szPlainName, _T('\\')) || _tcschr(szPlainName, _T('/')) || _tcschr(szPlainName, _T(':')))
        return ERROR_BAD_FORMAT;

    // Copy the directory name
    pData->szDirName[0] = szFileId[0];
    pData->szDirName[1] = szFileId[1];
    pData->szDirName[2] = szFileId[2];
    pData->szDirName[3] = 0;

    // Copy the file id
    StringCchCopy(pData->szFileName1, _countof(pData->szFileName1), szPlainName);

    // Set the appropriate flags
    pData->dwCreateOptions = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_BY_FILE_ID;

    // Switch to the "NtCreateFile" tab
    TabCtrl_SelectPageByID(hTabCtrl, MAKEINTRESOURCE(IDD_PAGE02_NTCREATE));
    return ERROR_SUCCESS;
}

void DisableDialogMessages(HWND hDlg, BOOL bDisable)
{
    HWND hExitButton = GetDlgItem(GetParent(hDlg), IDC_EXIT);

    // Initialize the buttons
    // Hide "OK" button and change "Cancel" to "Exit"
    if(hExitButton != NULL)
        EnableWindow(hExitButton, !bDisable);
    bDisableDialogMessages = bDisable;
}

INT_PTR FileTestDialog(HWND hParent, TFileTestData * pData)
{
    HACCEL hAccelTable = LoadAccelerators(g_hInst, MAKEINTRESOURCE(IDR_ACCELERATORS));
    HWND hTabCtrl;
    HWND hDlg;
    MSG msg;

    // Create the property sheet
    pData->bEnableResizing = TRUE;
    hDlg = CreateDialogParam(g_hInst,
                             MAKEINTRESOURCE(IDD_FILE_TEST),
                             hParent,
                             DialogProc,
                             (LPARAM)pData);
    
    // Perform the modal loop
    if(hDlg != NULL)
    {
        ShowWindow(hDlg, SW_SHOW);
        hTabCtrl = GetDlgItem(hDlg, IDC_TAB);

        while(IsWindow(hDlg))
        {
            // We need an alertable sleep to make APCs to work.
            // Uncomment this if you want to use the asynchronous "ApcRoutine"
            // parameter(s) in some native API
//          MsgWaitForMultipleObjectsEx(0,
//                                      NULL,
//                                      INFINITE,
//                                      QS_ALLEVENTS | QS_ALLINPUT | QS_ALLPOSTMESSAGE,
//                                      MWMO_WAITALL | MWMO_ALERTABLE | MWMO_INPUTAVAILABLE);

            // Get the message. Stop processing if WM_QUIT has arrived
            if(!GetMessage(&msg, NULL, 0, 0))
                break;

            // Process the accelerator table
            if(!TranslateAccelerator(hDlg, hAccelTable, &msg))
            {
                if(!IsMyDialogMessage(hDlg, hTabCtrl, &msg))
                {
                    TranslateMessage(&msg);
                    DispatchMessage(&msg);
                }
            }
        }
    }

    if(hAccelTable != NULL)
        DestroyAcceleratorTable(hAccelTable);
    return IDOK;
}
