/*****************************************************************************/
/* Page08Ea.cpp                           Copyright (c) Ladislav Zezula 2005 */
/*---------------------------------------------------------------------------*/
/* Description :                                                             */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 15.08.05  1.00  Lad  The first version of Page08Ea.cpp                    */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Message handlers

static TAnchors * pAnchors = NULL;

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    PROPSHEETPAGE * pPage = (PROPSHEETPAGE *)lParam;
    TFileTestData * pData = (TFileTestData *)pPage->lParam;

    UNREFERENCED_PARAMETER(lParam);
    UNREFERENCED_PARAMETER(hDlg);

    // Done by shared code
    SetDialogData(hDlg, pPage->lParam);

    // Configure dialog resizing
    if(pData->bEnableResizing)
    {
        pAnchors = new TAnchors(hDlg);
        pAnchors->AddAnchor(hDlg, IDC_EA_TITLE, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_EA_LIST, akAll);
        pAnchors->AddAnchor(hDlg, IDC_MOVE_UP, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_MOVE_DOWN, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_QUERY_EA, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_INSERT, akLeftCenter | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_EDIT, akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_DELETE, akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_SET_EA, akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_FRAME, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_INFORMATION_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_INFORMATION, akLeft | akRight | akBottom);
    }

    return TRUE;
}

static int OnSetActive(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    BOOL bEnable = FALSE;

    if(IsHandleValid(pData->hFile))
        bEnable = TRUE;
    EnableDlgItems(hDlg, bEnable, IDC_QUERY_EA, IDC_SET_EA, 0);
    return TRUE;
}

static int OnQueryEa(HWND hDlg)
{
    PFILE_FULL_EA_INFORMATION NewEaBuffer = NULL;
    PFILE_FULL_EA_INFORMATION EaBuffer = NULL;
    TFileTestData * pData = GetDialogData(hDlg);
    IO_STATUS_BLOCK IoStatus = {0};
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG EaBufferSize = 0x400;

    // Allocate the buffer for extended attributes
    EaBuffer = (PFILE_FULL_EA_INFORMATION)HeapAlloc(g_hHeap, 0, EaBufferSize);
    if(EaBuffer != NULL)
    {
        __TryQueryEA:

        // Try to query the extended attributes
        memset(EaBuffer, 0, EaBufferSize);
        Status = NtQueryEaFile(pData->hFile, &IoStatus, EaBuffer, EaBufferSize, FALSE, NULL, 0, NULL, TRUE);
        switch(Status)
        {
            // If not enough memory, then reallocate buffer
            case STATUS_BUFFER_OVERFLOW:
            case STATUS_BUFFER_TOO_SMALL:

                // Allocate new buffer. If succeeded, we try to query again
                EaBufferSize = EaBufferSize << 1;
                NewEaBuffer = (PFILE_FULL_EA_INFORMATION)HeapReAlloc(g_hHeap, 0, EaBuffer, EaBufferSize);
                if(NewEaBuffer != NULL)
                {
                    EaBuffer = NewEaBuffer;
                    goto __TryQueryEA;
                }

                // Failed to reallocate - free the buffer and stop
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;

            // If OK, format the list view with extended attributes
            case STATUS_SUCCESS:
                ExtendedAttributesToListView(hDlg, EaBuffer);
                break;
        }

        // Free the buffer for extended attributes
        HeapFree(g_hHeap, 0, EaBuffer);
    }
    else
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set the result to the dialog
    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_INFORMATION, Status, &IoStatus);
    return TRUE;
}

static int OnSetEa(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    IO_STATUS_BLOCK IoStatus = {0};
    TOpenPacket OpenFile;
    NTSTATUS Status = STATUS_SUCCESS;

    // Get the EA buffer and size
    if(ListViewToExtendedAttributes(hDlg, OpenFile) == ERROR_SUCCESS)
    {
        // Set the extended attributes to the file
        Status = NtSetEaFile(pData->hFile,
                            &IoStatus,
                             OpenFile.pvFileEa,
                             OpenFile.cbFileEa);

        // Set the result to the dialog
        SetResultInfo(hDlg, RSI_NTSTATUS | RSI_INFORMATION, Status, &IoStatus);
        OpenFile.Free();
    }
    return TRUE;
}

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    if(nNotify == BN_CLICKED)
    {
        switch(nIDCtrl)
        {
            case IDC_QUERY_EA:
                return OnQueryEa(hDlg);

            case IDC_SET_EA:
                return OnSetEa(hDlg);
        }
    }

    return FALSE;
}

static int OnNotify(HWND hDlg, NMHDR * pNMHDR)
{
    switch(pNMHDR->code)
    {
        case PSN_SETACTIVE:
            return OnSetActive(hDlg);
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// Public functions

INT_PTR CALLBACK PageProc08(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // WM_INITDIALOG is special case, we need to call both init routines
    if(uMsg == WM_INITDIALOG)
    {
        ExtendedAttributesEditorProc(hDlg, uMsg, wParam, 0);
        OnInitDialog(hDlg, lParam);
        return TRUE;
    }

    // Call the shared part of EA editor
    if(ExtendedAttributesEditorProc(hDlg, uMsg, wParam, lParam))
        return TRUE;

    // Handlers specific to our dialog
    switch(uMsg)
    {
        case WM_SIZE:
        case WM_GETMINMAXINFO:
            return pAnchors->OnMessage(uMsg, wParam, lParam);

        case WM_COMMAND:
            return OnCommand(hDlg, HIWORD(wParam), LOWORD(wParam));

        case WM_NOTIFY:
            return OnNotify(hDlg, (NMHDR *)lParam);

        case WM_DESTROY:
            if(pAnchors != NULL)
                delete pAnchors;
            pAnchors = NULL;
            return FALSE;
    }
    return FALSE;
}
