/*****************************************************************************/
/* DlgDataEditor.cpp                      Copyright (c) Ladislav Zezula 2014 */
/*---------------------------------------------------------------------------*/
/* Description: Common module for a few simple dialogs                       */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 19.03.14  1.00  Lad  The first version of DlgDataEditor.cpp               */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local structures

struct TDialogData
{
    TAnchors * pAnchors;
    ULONGLONG BaseAddress;
    LPBYTE pbFileData;
    size_t cbFileData;
    HWND hDlg;
};

//-----------------------------------------------------------------------------
// Message handlers

static void OnInitDialog(HWND hDlg, LPARAM lParam)
{
    TDialogData * pData = (TDialogData *)lParam;
    TAnchors * pAnchors;
    HWND hWndChild;

    // Initialize dialog data
    SetDialogIcon(hDlg, IDI_FILE_TEST);
    pData->hDlg = hDlg;
    SetDialogData(hDlg, pData);

    // Configure the anchors
    pData->pAnchors = pAnchors = new TAnchors();
    if(pAnchors != NULL)
    {
        pAnchors->AddAnchor(hDlg, IDC_FILE_DATA, akAll);
        pAnchors->AddAnchor(hDlg, IDC_INFORMATION, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDOK, akRight | akBottom);
    }

    // Configure the data viewer
    hWndChild = GetDlgItem(hDlg, IDC_FILE_DATA);
    if(hWndChild != NULL)
    {
        DataEditor_SetDataFormat(hWndChild, PtrPlatformSpecific, 0x10);
        DataEditor_SetData(hWndChild, (ULONGLONG)pData->BaseAddress, pData->pbFileData, pData->cbFileData);
    }
}

static void OnSize(HWND hDlg)
{
    TDialogData * pData = ((TDialogData *)GetWindowLongPtr(hDlg, DWLP_USER));

    if(pData != NULL && pData->pAnchors != NULL)
        pData->pAnchors->OnSize();
}

static void OnGetMinMaxInfo(HWND hDlg, LPARAM lParam)
{
    TDialogData * pData = ((TDialogData *)GetWindowLongPtr(hDlg, DWLP_USER));

    if(pData != NULL && pData->pAnchors != NULL)
        pData->pAnchors->OnGetMinMaxInfo(lParam);
}

static void OnNotify(HWND hDlg, NMHDR * pNMHDR)
{
    if(pNMHDR->code == DEN_EXCEPTION)
    {
        PDTE_EXCEPTION_DATA pExceptionData = (PDTE_EXCEPTION_DATA)pNMHDR;
        HWND hWndChild = GetDlgItem(hDlg, IDC_INFORMATION);
        
        if(hWndChild != NULL)
        {
            SetWindowTextRc(hWndChild, IDS_DATA_EXCEPTION,
                                       pExceptionData->WriteOperation ? _T("writing") : _T("reading"),
                                       pExceptionData->ExceptionAddress);
        }
    }
}

static void OnDestroy(HWND hDlg)
{
    TDialogData * pData = ((TDialogData *)GetWindowLongPtr(hDlg, DWLP_USER));

    if(pData != NULL)
    {
        if(pData->pAnchors != NULL)
            delete pData->pAnchors;
        pData->pAnchors = NULL;
    }
}

static INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    UINT nIDCtrl;
    UINT nIDNotify;

    // Dialog initialization
    switch(uMsg)
    {
        case WM_INITDIALOG:
            OnInitDialog(hDlg, lParam);
            return TRUE;

        case WM_SIZE:
            OnSize(hDlg);
            break;

        case WM_GETMINMAXINFO:
            OnGetMinMaxInfo(hDlg, lParam);
            break;

        case WM_NOTIFY:
            OnNotify(hDlg, (NMHDR *)lParam);
            break;

        case WM_COMMAND:
            nIDNotify = HIWORD(wParam);
            nIDCtrl = LOWORD(wParam);

            if(nIDNotify == BN_CLICKED)
                EndDialog(hDlg, nIDCtrl);
            break;

        case WM_DESTROY:
            OnDestroy(hDlg);
            break;
    }

    return FALSE;
}

//-----------------------------------------------------------------------------
// Dialog functions

INT_PTR DataEditorDialog(HWND hParent, LPVOID BaseAddress, size_t ViewSize)
{
    TDialogData Data;

    ZeroMemory(&Data, sizeof(TDialogData));
    Data.BaseAddress = (ULONGLONG)BaseAddress;
    Data.pbFileData = (LPBYTE)BaseAddress;
    Data.cbFileData = ViewSize;
    return DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_DATA_EDITOR), hParent, DialogProc, (LPARAM)&Data);
}
