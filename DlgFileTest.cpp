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
// Local structures

struct TDialogData
{
    HWND hWndPage;                          // HWND of the current page
    HWND hDlg;                              // Handle to ourself
    bool bInitialResizeDone;                // If TRUE, the first resize has already completed

    int  nTabInnerLeft;                     // Inner space tab control <==> dialog client edge
    int  nTabInnerTop;
    int  nTabInnerRight;
    int  nTabInnerBottom;
    int  nButtonInnerRight;                 // Button distance from right-bottom corner
    int  nButtonInnerBottom;

    UINT_PTR CheckMouseTimer;               // Timer for checking mouse
    RECT ScreenRect;                        // Size of the screen
    RECT DialogRect;                        // Size of the dialog
    bool bDialogBiggerThanScreen;           // true = the main dialog is bigger than the screen

    HANDLE hThread;                         // Thread that moves the dialog
    int nStartX;                            // The dialog's starting X position
    int nStartY;                            // The dialog's starting Y position
    int nEndY;                              // The dialog's final Y position
    int nAddY;                              // The dialog's movement direction
};

//-----------------------------------------------------------------------------
// Local variables

static BOOL bDisableDialogMessages = FALSE;

//-----------------------------------------------------------------------------
// Local functions

static DWORD WINAPI MoveDialogThread(PVOID pParam)
{
    TDialogData * pData = (TDialogData *)pParam;
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

static void InitializeTabControl(HWND hDlg, TFileTestData * pftd)
{
    PROPSHEETHEADER psh;
    PROPSHEETPAGE psp[13];
    TCHAR szAppTitle[256];
    HWND hTabCtrl = GetDlgItem(hDlg, IDC_TAB);
    int nPages = 0;

    // Get the title of FileTest application
    GetFileTestAppTitle(szAppTitle);

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
    if(g_dwWinVer >= 0x0600)
    {
        ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
        psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
        psp[nPages].dwFlags     = PSP_DEFAULT;
        psp[nPages].hInstance   = g_hInst;
        psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE00_TRANSACTION);
        psp[nPages].pfnDlgProc  = PageProc00;
        psp[nPages].lParam      = (LPARAM)pftd;
        nPages++;
    }

    // Fill the "CreateFile" page
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE01_CREATE);
    psp[nPages].pfnDlgProc  = PageProc01;
    psp[nPages].lParam      = (LPARAM)pftd;
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
    psp[nPages].lParam      = (LPARAM)pftd;
    if(IsNativeName(pftd->szFileName1))
        psh.nStartPage = nPages;
    nPages++;

    // Fill the "ReadWrite"
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE03_READWRITE);
    psp[nPages].pfnDlgProc  = PageProc03;
    psp[nPages].lParam      = (LPARAM)pftd;
    nPages++;

    // Fill the "Mapping"
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE04_MAPPING);
    psp[nPages].pfnDlgProc  = PageProc04;
    psp[nPages].lParam      = (LPARAM)pftd;
    nPages++;

    // Fill the "File Ops".
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE05_FILEOPS);
    psp[nPages].pfnDlgProc  = PageProc05;
    psp[nPages].lParam      = (LPARAM)pftd;
    nPages++;

    // Fill the "NtFileInfo" page
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE06_NTFILEINFO);
    psp[nPages].pfnDlgProc  = PageProc06;
    psp[nPages].lParam      = (LPARAM)pftd;
    nPages++;

    // Fill the "NtFsInfo" page.
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE07_NTVOLINFO);
    psp[nPages].pfnDlgProc  = PageProc06;
    psp[nPages].lParam      = (LPARAM)pftd;
    nPages++;

    // Fill the "EA" page.
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE08_EA);
    psp[nPages].pfnDlgProc  = PageProc08;       // The same like NtFileInfo
    psp[nPages].lParam      = (LPARAM)pftd;
    nPages++;

    // Fill the "Security".
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE09_SECURITY);
    psp[nPages].pfnDlgProc  = PageProc09;
    psp[nPages].lParam      = (LPARAM)pftd;
    nPages++;

    // Fill the "Links".
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE10_LINKS);
    psp[nPages].pfnDlgProc  = PageProc10;
    psp[nPages].lParam      = (LPARAM)pftd;
    nPages++;

    // Fill the "Streams".
    ZeroMemory(&psp[nPages], sizeof(PROPSHEETPAGE));
    psp[nPages].dwSize      = sizeof(PROPSHEETPAGE);
    psp[nPages].dwFlags     = PSP_DEFAULT;
    psp[nPages].hInstance   = g_hInst;
    psp[nPages].pszTemplate = MAKEINTRESOURCE(IDD_PAGE11_STREAMS);
    psp[nPages].pfnDlgProc  = PageProc11;
    psp[nPages].lParam      = (LPARAM)pftd;
    nPages++;
    psh.nPages = nPages;

    // Create Tab Control
    TabCtrl_Create(hTabCtrl, &psh);
}

static void RefreshScreenSize(HWND hDlg)
{
    TDialogData * pData = (TDialogData *)GetWindowLongPtr(hDlg, DWLP_USER);
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

//-----------------------------------------------------------------------------
// Dialog handlers

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    TFileTestData * pftd = (TFileTestData *)lParam;
    TDialogData * pData = new TDialogData;

    // Initialize dialog data
    ZeroMemory(pData, sizeof(TDialogData));
    pData->hDlg = hDlg;
    g_hDlg = hDlg;
    SetDialogData(hDlg, pData);

    //
    // Note: If the screen size is too low at this point (like 800x600),
    // the dialog gets shrinked. We need to fis the dialog to the original size
    //

    FixDialogToOriginalSize(hDlg, IDD_FILE_TEST);

    // Create the tooltip window
    g_Tooltip.Initialize(g_hInst, hDlg);

    // Initialize Tab Control
    InitializeTabControl(hDlg, pftd);

    // Refresh information about screen rect and dialog rect
    RefreshScreenSize(hDlg);
    return TRUE;
}

static void OnSize(HWND hDlg, LPARAM lParam)
{
    TDialogData * pData = (TDialogData *)GetWindowLongPtr(hDlg, DWLP_USER);
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
    TDialogData * pData = (TDialogData *)GetWindowLongPtr(hDlg, DWLP_USER);
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

        case WM_COMMAND:
            return OnCommand(hDlg, HIWORD(wParam), LOWORD(wParam));
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
    _tcscpy(pData->szFileName1, szPlainName);

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

        while(IsWindow(hDlg) && GetMessage(&msg, NULL, 0, 0))
        {
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
