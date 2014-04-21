/*****************************************************************************/
/* Page00Transaction.cpp                  Copyright (c) Ladislav Zezula 2006 */
/*---------------------------------------------------------------------------*/
/* Description:                                                              */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 02.05.06  1.00  Lad  The first version of Page00Transaction.cpp           */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

static void UpdateDialog(HWND hDlg, int nError)
{
    TFileTestData * pData = GetDialogData(hDlg);
    BOOL bEnable;

    if(pfnCreateTransaction != NULL)
    {
        // CreateTransaction is allowed when no transaction is created
        bEnable = (BOOL)(IsHandleInvalid(pData->hTransaction));
        EnableDlgItems(hDlg, bEnable, IDC_CREATE_TRANSACTION, IDC_CREATE_TRANSACTION_HINT, 0);

        // CommitTransaction and RollbackTransaction are allowed when a transaction is assigned
        bEnable = (BOOL)(IsHandleValid(pData->hTransaction));
        EnableDlgItems(hDlg, bEnable, IDC_COMMIT_TRANSACTION, IDC_COMMIT_TRANSACTION_HINT,
                                      IDC_ROLLBACK_TRANSACTION, IDC_ROLLBACK_TRANSACTION_HINT,
                                      0);

        SetResultInfo(hDlg, nError, pData->hTransaction);
    }
    else
    {
        EnableDlgItems(hDlg, FALSE, IDC_CREATE_TRANSACTION, IDC_CREATE_TRANSACTION_HINT,
                                    IDC_COMMIT_TRANSACTION, IDC_COMMIT_TRANSACTION_HINT,
                                    IDC_ROLLBACK_TRANSACTION, IDC_ROLLBACK_TRANSACTION_HINT,
                                    IDC_CLOSE_HANDLE, IDC_CLOSE_HANDLE_HINT,
                                    0);
    }
}

//-----------------------------------------------------------------------------
// Message handlers

static TAnchors * pAnchors = NULL;

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    PROPSHEETPAGE * pPage = (PROPSHEETPAGE *)lParam;
    TFileTestData * pData = (TFileTestData *)pPage->lParam;

    // Load the transaction APIs, as they are only supported in Vista and later
    SetDialogData(hDlg, pPage->lParam);
    pData->hTransaction = INVALID_HANDLE_VALUE;

    // Configure dialog resizing
    if(pData->bEnableResizing)
    {
        pAnchors = new TAnchors();
        pAnchors->AddAnchor(hDlg, IDC_MAIN_FRAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_CREATE_TRANSACTION, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_CREATE_TRANSACTION_HINT, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_COMMIT_TRANSACTION, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_COMMIT_TRANSACTION_HINT, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_ROLLBACK_TRANSACTION, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_ROLLBACK_TRANSACTION_HINT, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_CLOSE_HANDLE, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_CLOSE_HANDLE_HINT, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_FRAME, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_LAST_ERROR_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_LAST_ERROR, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_HANDLE_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_HANDLE, akLeft | akRight | akBottom);
    }

    return TRUE;
}

static int OnCreateTransaction(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    int nError = ERROR_SUCCESS;

    // Create new transaction
    if(nError == ERROR_SUCCESS && pfnCreateTransaction != NULL)
    {
        pData->hTransaction = pfnCreateTransaction(NULL,
                                                   NULL,
                                                   0,
                                                   0,
                                                   0,
                                                   NULL,
                                                   _T("Transaction for FileTest"));
        if(IsHandleValid(pData->hTransaction))
            pData->bTransactionActive = TRUE;
        else
            nError = GetLastError();
    }

    UpdateDialog(hDlg, nError);
    return TRUE;
}

static int OnCommitTransaction(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    int nError = ERROR_SUCCESS;

    // Commit the transaction
    if(IsHandleValid(pData->hTransaction))
    {
        if(!pfnCommitTransaction(pData->hTransaction))
            nError = GetLastError();

        pData->bTransactionActive = FALSE;
        pData->bUseTransaction = FALSE;
        UpdateDialog(hDlg, nError);
    }
    return TRUE;
}

static int OnRollbackTransaction(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    int nError = ERROR_SUCCESS;

    // Rollback the transaction
    if(IsHandleValid(pData->hTransaction))
    {
        if(!pfnRollbackTransaction(pData->hTransaction))
            nError = GetLastError();

        pData->bTransactionActive = FALSE;
        pData->bUseTransaction = FALSE;
        UpdateDialog(hDlg, nError);
    }
    return TRUE;
}

static int OnCloseTransaction(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    int nError = ERROR_SUCCESS;

    // Assign the transaction to the current thread
    if(IsHandleValid(pData->hTransaction))
        CloseHandle(pData->hTransaction);

    // Clear information about transaction
    pData->hTransaction = INVALID_HANDLE_VALUE;
    UpdateDialog(hDlg, nError);
    return TRUE;
}

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    if(nNotify == BN_CLICKED)
    {
        switch(nIDCtrl)
        {
            case IDC_CREATE_TRANSACTION:
                OnCreateTransaction(hDlg);
                return TRUE;

            case IDC_COMMIT_TRANSACTION:
                OnCommitTransaction(hDlg);
                return TRUE;

            case IDC_ROLLBACK_TRANSACTION:
                OnRollbackTransaction(hDlg);
                return TRUE;

            case IDC_CLOSE_HANDLE:
                OnCloseTransaction(hDlg);
                return TRUE;
        }
    }

    return FALSE;
}

//-----------------------------------------------------------------------------
// Public page callback

INT_PTR CALLBACK PageProc00(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
        case WM_INITDIALOG:
            return OnInitDialog(hDlg, lParam);

        case WM_SIZE:
            if(pAnchors != NULL)
                pAnchors->OnSize();
            return FALSE;

        case WM_COMMAND:
            return OnCommand(hDlg, HIWORD(wParam), LOWORD(wParam));

        case WM_DESTROY:
            if(pAnchors != NULL)
                delete pAnchors;
            pAnchors = NULL;
            return FALSE;
    }
    return FALSE;
}
