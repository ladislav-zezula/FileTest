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
        pAnchors = new TAnchors();
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
        pAnchors->AddAnchor(hDlg, IDC_RESULT_STATUS_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_STATUS, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_LENGTH_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_LENGTH, akLeft | akRight | akBottom);
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
    PFILE_FULL_EA_INFORMATION EaBuffer = NULL;
    FILE_EA_INFORMATION FileEaInfo;
    TFileTestData * pData = GetDialogData(hDlg);
    IO_STATUS_BLOCK IoStatus = {0};
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG EaBufferSize = 0;

    //
    // Although it is possible to get the size of the extended attributes,
    // I've tried and the size is usually not enough for receiving EAs.
    // I don't know what the QueryFileInfo for FileEaInformation is good for then :-(
    //

    Status = NtQueryInformationFile(pData->hFile,
                                   &IoStatus, 
                                   &FileEaInfo,
                                    sizeof(FILE_EA_INFORMATION),
                                    FileEaInformation);
    
    // Allocate the buffer large enough to hold the EAs.
    if(Status == STATUS_SUCCESS && FileEaInfo.EaSize > 0)
    {
        EaBufferSize = FileEaInfo.EaSize;
        EaBuffer = (PFILE_FULL_EA_INFORMATION)HeapAlloc(g_hHeap, 0, EaBufferSize);
        if(EaBuffer == NULL)
            Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    // Query the EAs, if any. If the buffer is not large enough,
    // double its size and try again
    if(Status == STATUS_SUCCESS && EaBufferSize > 0)
    {
        BOOL bEndLoop = FALSE;

        while(bEndLoop == FALSE)
        {
            Status = NtQueryEaFile(pData->hFile,
                                  &IoStatus,
                                   EaBuffer,
                                   EaBufferSize,
                                   FALSE,
                                   NULL,
                                   0,
                                   NULL,
                                   TRUE);

            switch(Status)
            {
                // We succeeded or not "buffer too small" => break    
                case STATUS_SUCCESS:    
                default:
                    bEndLoop = TRUE;
                    break;

                // We need to increment buffer size
                case STATUS_BUFFER_OVERFLOW:
                case STATUS_BUFFER_TOO_SMALL:
                    EaBufferSize *= 2;
                    EaBuffer = (PFILE_FULL_EA_INFORMATION)HeapReAlloc(g_hHeap, 0, EaBuffer, EaBufferSize);
                    Status = STATUS_SUCCESS;
                    if(EaBuffer == NULL)
                    {
                        Status = STATUS_INSUFFICIENT_RESOURCES;
                        bEndLoop = TRUE;
                    }
                    break;
            }
        }
    }

    // If we got something, fill the listview
    if(Status == STATUS_SUCCESS)
    {
        ExtendedAttributesToListView(hDlg, EaBuffer);
    }

    // Set the result to the dialog
    SetResultInfo(hDlg, Status, NULL, IoStatus.Information);
    if(EaBuffer != NULL)
        HeapFree(g_hHeap, 0, EaBuffer);
    return TRUE;
}


static int OnSetEa(HWND hDlg)
{
    PFILE_FULL_EA_INFORMATION pFileEa = NULL;
    TFileTestData * pData = GetDialogData(hDlg);
    IO_STATUS_BLOCK IoStatus = {0};
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG dwEaLength = 0;

    // Get the EA buffer and size
    pFileEa = ListViewToExtendedAttributes(hDlg, dwEaLength);

    // Set the extended attributes to the file
    Status = NtSetEaFile(pData->hFile,
                        &IoStatus,
                         pFileEa,
                         dwEaLength);

    // Set the result to the dialog
    SetResultInfo(hDlg, Status, NULL, IoStatus.Information);

    // Delete buffers and exit
    if(pFileEa != NULL)
        delete [] pFileEa;
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
            if(pAnchors != NULL)
                pAnchors->OnSize();
            return FALSE;

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
