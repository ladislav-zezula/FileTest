/*****************************************************************************/
/* Page03ReadWrite.cpp                    Copyright (c) Ladislav Zezula 2004 */
/*---------------------------------------------------------------------------*/
/* This module handles both "ReadFile" and "WriteFile" pages                 */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 06.03.04  1.00  Lad  The first version of Page03ReadWrite.cpp             */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

#define INITIAL_DATA_BUFFER_SIZE 0x10000

//-----------------------------------------------------------------------------
// Helper functions

static int UpdateFileData(
    HWND hDlg,
    LPCSTR szDataToFill,
    size_t OffsetToFill,
    UINT FillPattern)
{
    TFileTestData * pData = GetDialogData(hDlg);
    LONGLONG ByteOffset;
    LPBYTE WritePattern = (LPBYTE)"BAADF00D";
    LPBYTE pbNewData;
    ULONG NewLength;
    ULONG i;
    size_t cchDataToFill = 0;
    HWND hWndChild = GetDlgItem(hDlg, IDC_FILE_DATA);

    // Get the byte offset
    DlgText2Hex64(hDlg, IDC_BYTE_OFFSET, &ByteOffset);
    DlgText2Hex32(hDlg, IDC_LENGTH, &NewLength);

    // Clear the file data from the data editor
    DataEditor_SetData(hWndChild, 0, NULL, 0);

    // Determine the new length of the data
    if(szDataToFill != NULL)
    {
        cchDataToFill = strlen(szDataToFill);
        NewLength = (ULONG)(OffsetToFill + cchDataToFill);
    }

    // If we need to increase the buffer size, do it
    if(NewLength > pData->cbFileDataMax)
    {
        // Allocate new data
        pbNewData = (LPBYTE)VirtualAlloc(NULL, NewLength, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if(pbNewData == NULL)
            return ERROR_NOT_ENOUGH_MEMORY;

        // Copy and free old data
        if(pData->pbFileData != NULL)
        {
            memcpy(pbNewData, pData->pbFileData, pData->cbFileData);
            VirtualFree(pData->pbFileData, pData->cbFileDataMax, MEM_RELEASE);
        }
        
        // Assign the new data
        pData->pbFileData = pbNewData;
        pData->cbFileDataMax = NewLength;
    }

    // If we shall fill the data with custom data, do it
    if(szDataToFill != NULL)
    {
        // Fill the gap after end of current data with zeros
        if(OffsetToFill > pData->cbFileData)
            memset(pData->pbFileData + pData->cbFileData, 0, OffsetToFill - pData->cbFileData);
        memcpy(pData->pbFileData + OffsetToFill, szDataToFill, cchDataToFill);
    }

    // If the caller required us to fill the data with pattern, do it
    else
    {
        // If the new pattern is zero, it means to fill the same pattern like before
        if(FillPattern == 0)
            FillPattern = pData->FillPattern;

        // If the pattern is the same like before, just fill the remaining part
        if(OffsetToFill < NewLength)
        {
            switch(FillPattern)
            {
                case IDC_FILL_DATA_ZEROS:
                    memset(pData->pbFileData + OffsetToFill, 0, NewLength - OffsetToFill);
                    break;

                case IDC_FILL_DATA_PATTERN:
                    for(i = (ULONG)OffsetToFill; i < NewLength; i++)
                        pData->pbFileData[i] = WritePattern[i % 8];
                    break;

                case IDC_FILL_DATA_RANDOM:
                    srand(GetTickCount());
                    for(i = (ULONG)OffsetToFill; i < NewLength; i++)
                        pData->pbFileData[i] = (BYTE)(rand() % 0x100);
                    break;
            }
        }

        // Remember the current pattern
        pData->FillPattern = FillPattern;
    }

    // Remember the new data length
    if(NewLength != pData->cbFileData)
    {
        Hex2DlgText32(hDlg, IDC_LENGTH, NewLength);
        pData->cbFileData = NewLength;
    }

    // Apply the new file data
    DataEditor_SetData(hWndChild, ByteOffset, pData->pbFileData, pData->cbFileData);
    return ERROR_SUCCESS;
}

static void CompleteReadWriteOperation(HWND hDlg, TApcReadWrite * pApc, int nError, DWORD dwTransferred)
{
    HWND hWndEditor;

    // Set the information about the operation
    SetResultInfo(hDlg, nError, NULL, dwTransferred);

    // If the operation has succeeded, update few UI elements
    if(nError == ERROR_SUCCESS)
    {
        // If the "increase position" is checked, increment the byte position
        if(pApc->bIncrementPosition)
        {
            pApc->ByteOffset.QuadPart += dwTransferred;
            Hex2DlgText64(hDlg, IDC_BYTE_OFFSET, pApc->ByteOffset.QuadPart);
        }

        // If we shall update the data view, do it
        if(pApc->bUpdateData)
        {
            hWndEditor = GetDlgItem(hDlg, IDC_FILE_DATA);
            InvalidateRect(hWndEditor, NULL, TRUE);
        }
    }
}

//-----------------------------------------------------------------------------
// Message handlers

static TAnchors * pAnchors = NULL;         // Anchors for ReadFile

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    PROPSHEETPAGE * pPage = (PROPSHEETPAGE *)lParam;
    TFileTestData * pData = (TFileTestData *)pPage->lParam;
    HWND hWndChild;

    SetDialogData(hDlg, pPage->lParam);

    // Configure dialog resizing
    if(pData->bEnableResizing)
    {
        pAnchors = new TAnchors();
        pAnchors->AddAnchor(hDlg, IDC_BYTE_OFFSET_TITLE, akLeft | akTop | akRightCenter);
        pAnchors->AddAnchor(hDlg, IDC_BYTE_OFFSET, akLeft | akTop | akRightCenter);
        pAnchors->AddAnchor(hDlg, IDC_BYTE_OFFSET_SPIN, akTop | akRightCenter);
        pAnchors->AddAnchor(hDlg, IDC_LENGTH_TITLE, akLeftCenter | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_LENGTH, akLeftCenter | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_LENGTH_SPIN, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_INCREASE_FILEPOS, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_READ_FILE, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_WRITE_FILE, akTop | akRightCenter);
        pAnchors->AddAnchor(hDlg, IDC_NTREAD_FILE, akLeftCenter | akTop);
        pAnchors->AddAnchor(hDlg, IDC_NTWRITE_FILE, akRight | akTop);
        pAnchors->AddAnchor(hDlg, IDC_LOCK_FILE, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_UNLOCK_FILE, akTop | akRightCenter);
        pAnchors->AddAnchor(hDlg, IDC_NTLOCK_FILE, akLeftCenter | akTop);
        pAnchors->AddAnchor(hDlg, IDC_NTUNLOCK_FILE, akRight | akTop);
        pAnchors->AddAnchor(hDlg, IDC_FILL_DATA_MENU, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_GET_FILE_SIZE, akTop | akRightCenter);
        pAnchors->AddAnchor(hDlg, IDC_SET_FILE_POINTER, akLeftCenter | akTop);
        pAnchors->AddAnchor(hDlg, IDC_SET_END_OF_FILE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_DATA, akAll);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_FRAME, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_LAST_ERROR_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_LAST_ERROR, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_IOSTATUS_INFO_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_IOSTATUS_INFO, akLeft | akRight | akBottom);
    }

    // Allocate the initial data. Make them aligned to sector alignment
    pData->cbFileDataMax = INITIAL_DATA_BUFFER_SIZE;
    pData->pbFileData = (LPBYTE)VirtualAlloc(NULL, pData->cbFileDataMax, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    pData->cbFileData = 0;

    // Zero the data
    if(pData->pbFileData != NULL)
        memset(pData->pbFileData, 0, pData->cbFileDataMax);

    // If there's field for data obtained by ReadFile, sets it to 8 bytes per line
    hWndChild = GetDlgItem(hDlg, IDC_FILE_DATA);
    if(hWndChild != NULL)
        DataEditor_SetBytesPerLine(hWndChild, 0x08);

    // Set initial values for file position and data
    Hex2DlgText64(hDlg, IDC_BYTE_OFFSET, 0);
    Hex2DlgText32(hDlg, IDC_LENGTH, INITIAL_DATA_BUFFER_SIZE);
    UpdateFileData(hDlg, NULL, 0, IDC_FILL_DATA_PATTERN);
    return TRUE;
}

static int OnSetActive(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    BOOL bEnable = FALSE;

    if(IsHandleValid(pData->hFile))
        bEnable = TRUE;

    EnableDlgItems(hDlg, bEnable, IDC_READ_FILE,
                                  IDC_WRITE_FILE,
                                  IDC_NTREAD_FILE,
                                  IDC_NTWRITE_FILE,
                                  IDC_LOCK_FILE,
                                  IDC_UNLOCK_FILE,
                                  IDC_NTLOCK_FILE,
                                  IDC_NTUNLOCK_FILE,
                                  IDC_GET_FILE_SIZE,
                                  IDC_SET_FILE_POINTER,
                                  IDC_SET_END_OF_FILE,
                                  0);
    return TRUE;
}

static int OnDeltaPos(HWND hDlg, NMUPDOWN * pNMUpDown)
{
    TFileTestData * pData = GetDialogData(hDlg);
    LONGLONG ByteOffset = 0;
    DWORD Length = 0;

    if(pNMUpDown->hdr.idFrom == IDC_BYTE_OFFSET_SPIN)
    {
        DlgText2Hex64(hDlg, IDC_BYTE_OFFSET, &ByteOffset);
        ByteOffset -= pNMUpDown->iDelta * 0x10000;
        if(ByteOffset < 0)
            ByteOffset = 0;
        Hex2DlgText64(hDlg, IDC_BYTE_OFFSET, ByteOffset);
        UpdateFileData(hDlg, NULL, pData->cbFileData, pData->FillPattern);
    }

    if(pNMUpDown->hdr.idFrom == IDC_LENGTH_SPIN)
    {
        DlgText2Hex32(hDlg, IDC_LENGTH, &Length);
        Length -= pNMUpDown->iDelta * 0x1000;
        if((int)Length < 0)
            Length = 0;
        Hex2DlgText32(hDlg, IDC_LENGTH, Length);
        UpdateFileData(hDlg, NULL, pData->cbFileData, pData->FillPattern);
    }

    return TRUE;
}

static int OnDataPaste(HWND hDlg, PDTE_PASTE_DATA pPasteData)
{
    // Ask the user whether to cut the data or not
    if(MessageBoxRc(hDlg, IDS_QUESTION, IDS_WANT_TRIM_DATA) == IDYES)
    {
        // Paste the data to the view
        UpdateFileData(hDlg, pPasteData->szPasteText, pPasteData->PasteOffset, 0);

        // Mark the request as handled, so the data editor stops fuhrter processing
        pPasteData->bHandled = TRUE;
    }

    return TRUE;
}

static int OnReadWriteFile(HWND hDlg, int nIDCtrl)
{
    IO_STATUS_BLOCK IoStatus = {0};
    TFileTestData * pData = GetDialogData(hDlg);
    TApcReadWrite * pApc;
    LARGE_INTEGER ByteOffset = {0};
    NTREADWRITE NtReadWrite;
    READWRITE ReadWrite;
    NTSTATUS Status;
    DWORD dwTransferred = 0;
    DWORD Length = 0;
    int nError = ERROR_SUCCESS;

    // Get the start position
    DlgText2Hex64(hDlg, IDC_BYTE_OFFSET, &ByteOffset.QuadPart);
    DlgText2Hex32(hDlg, IDC_LENGTH, &Length);
    assert(pData->cbFileData >= Length);

    // Create new APC entry
    pApc = (TApcReadWrite *)CreateApcEntry(pData, APC_TYPE_READ_WRITE, sizeof(TApcReadWrite));
    if(pApc != NULL)
    {   
        // Remember the state of "Increment position"
        pApc->ByteOffset = ByteOffset;
        pApc->bIncrementPosition = (IsDlgButtonChecked(hDlg, IDC_INCREASE_FILEPOS) == BST_CHECKED);

        // Perform the appropriate API
        switch(nIDCtrl)
        {
            case IDC_READ_FILE:
            case IDC_WRITE_FILE:

                // Get the pointer to the appropriate API
                ReadWrite = (nIDCtrl == IDC_READ_FILE) ? ReadFile : (READWRITE)WriteFile;
                pApc->bUpdateData = (nIDCtrl == IDC_READ_FILE);
                pApc->bNativeCall = false;

                // Prepare the OVERLAPPED structure in the APC
                pApc->Overlapped.OffsetHigh = ByteOffset.HighPart;
                pApc->Overlapped.Offset = ByteOffset.LowPart;

                // Perform the read operation using ReadFile
                if(!ReadWrite(pData->hFile, pData->pbFileData, Length, &dwTransferred, &pApc->Overlapped))
                    nError = GetLastError();

                // If the read operation ended with ERROR_IO_PENDING, queue the APC
                if(nError == ERROR_IO_PENDING)
                {
                    SetResultInfo(hDlg, ERROR_IO_PENDING);
                    InsertApcEntry(pData, pApc);
                    return TRUE;
                }
                break;

            case IDC_NTREAD_FILE:
            case IDC_NTWRITE_FILE:

                // Get the pointer to the appropriate API
                NtReadWrite = (nIDCtrl == IDC_NTREAD_FILE) ? NtReadFile : NtWriteFile;
                pApc->bUpdateData = (nIDCtrl == IDC_NTREAD_FILE);
                pApc->bNativeCall = true;

                // Perform the read/write operation
                Status = NtReadWrite(pData->hFile,
                                     pApc->hEvent,
                                     NULL,
                                     NULL,
                                    &pApc->IoStatus,
                                     pData->pbFileData,
                                     Length,
                                    &ByteOffset,
                                     NULL);

                // If the read operation ended with STATUS_PENDING, queue the APC
                if(Status == STATUS_PENDING)
                {
                    SetResultInfo(hDlg, ERROR_IO_PENDING);
                    InsertApcEntry(pData, pApc);
                    return TRUE;
                }

                // Fill the number of bytes transferred
                dwTransferred = (DWORD)IoStatus.Information;
                nError = RtlNtStatusToDosError(Status);
                break;
        }

        // Complete the read/write operation
        CompleteReadWriteOperation(hDlg, pApc, nError, dwTransferred);
        FreeApcEntry(pApc);
    }
    else
    {
        SetResultInfo(hDlg, GetLastError());
    }

    return TRUE;
}

static int OnLockUnlockFile(HWND hDlg, int nReadWriteType)
{
    TFileTestData * pData = GetDialogData(hDlg);
    TApcReadWrite * pApc;
    LARGE_INTEGER ByteOffset = {0};
    LARGE_INTEGER LockLength = {0};
    NTSTATUS Status;
    int nError = ERROR_SUCCESS;

    // Get the start position
    DlgText2Hex64(hDlg, IDC_BYTE_OFFSET, &ByteOffset.QuadPart);
    DlgText2Hex32(hDlg, IDC_LENGTH, &LockLength.LowPart);
    assert((LONGLONG)pData->cbFileData >= LockLength.QuadPart);

    // Create new APC entry
    pApc = (TApcReadWrite *)CreateApcEntry(pData, APC_TYPE_READ_WRITE, sizeof(TApcReadWrite));
    if(pApc != NULL)
    {
        // Perform the I/O operation
        switch(nReadWriteType)
        {
            case IDC_LOCK_FILE:

                // Perform the lock operation using LockFile
                if(!LockFile(pData->hFile, ByteOffset.LowPart, ByteOffset.HighPart, LockLength.LowPart, LockLength.HighPart))
                    nError = GetLastError();
                break;

            case IDC_UNLOCK_FILE:

                // Perform the unlock operation using UnlockFile
                if(!UnlockFile(pData->hFile, ByteOffset.LowPart, ByteOffset.HighPart, LockLength.LowPart, LockLength.HighPart))
                    nError = GetLastError();
                break;

            case IDC_NTLOCK_FILE:

                // Remember that this is a native call
                pApc->bNativeCall = false;

                // Perform the lock operation using NtLockFile
                Status = NtLockFile(pData->hFile,
                                    pApc->hEvent,
                                    NULL,
                                    NULL,
                                   &pApc->IoStatus,
                                   &ByteOffset,
                                   &LockLength,
                                    0,
                                    TRUE,
                                    TRUE);

                // If the lock operation ended with STATUS_PENDING, queue the APC
                if(Status == STATUS_PENDING)
                {
                    SetResultInfo(hDlg, ERROR_IO_PENDING);
                    InsertApcEntry(pData, pApc);
                    return TRUE;
                }

                // Save the error
                nError = RtlNtStatusToDosError(Status);
                break;

            case IDC_NTUNLOCK_FILE:

                // Perform the unlock operation using NtUnlockFile
                Status = NtUnlockFile(pData->hFile,
                                     &pApc->IoStatus,
                                     &ByteOffset,
                                     &LockLength,
                                      0);
                // Save the error
                assert(Status != STATUS_PENDING);
                nError = RtlNtStatusToDosError(Status);
                break;
        }

        // Set the information about the operation
        SetResultInfo(hDlg, nError);
        FreeApcEntry(pApc);
    }
    else
    {
        SetResultInfo(hDlg, GetLastError());
    }

    return TRUE;
}

static int OnGetFileSizeClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    LARGE_INTEGER FileSize = {0};
    int nError = ERROR_SUCCESS;

    // Get the file size
    SetLastError(ERROR_SUCCESS);
    FileSize.LowPart = GetFileSize(pData->hFile, (LPDWORD)&FileSize.HighPart);
    nError = GetLastError();

    SetResultInfo(hDlg, nError, NULL, 0, &FileSize);
    return TRUE;
}

static int OnSetFilePointerClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    LARGE_INTEGER ByteOffset;
    int nError = ERROR_SUCCESS;

    // Get the file offset from the dialog
    DlgText2Hex64(hDlg, IDC_BYTE_OFFSET, &ByteOffset.QuadPart);
    
    // Apply the file size
    SetLastError(ERROR_SUCCESS);
    SetFilePointer(pData->hFile, ByteOffset.LowPart, &ByteOffset.HighPart, FILE_BEGIN);
    nError = GetLastError();

    SetResultInfo(hDlg, nError);
    return TRUE;
}

static int OnSetEndOfFileClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    int nError = ERROR_SUCCESS;

    if(!SetEndOfFile(pData->hFile))
        nError = GetLastError();

    SetResultInfo(hDlg, nError);
    return TRUE;
}

static int OnApc(HWND hDlg, LPARAM lParam)
{
    TFileTestData * pData = GetDialogData(hDlg);
    TApcReadWrite * pApc = (TApcReadWrite *)lParam;
    DWORD dwTransferred = 0;
    int nError = ERROR_SUCCESS;

    // Sanity check
    assert(pApc->ApcType == APC_TYPE_READ_WRITE);

    // Get the result of the operation and number of bytes transferred
    if(pApc->bNativeCall == false)
    {
        if(!GetOverlappedResult(pData->hFile, &pApc->Overlapped, &dwTransferred, TRUE))
            nError = GetLastError();
    }
    else
    {
        nError = RtlNtStatusToDosError(pApc->IoStatus.Status);
        dwTransferred = (DWORD)pApc->IoStatus.Information;
    }

    // Complete the read/write operation
    CompleteReadWriteOperation(hDlg, pApc, nError, dwTransferred);
    return TRUE;
}

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    TFileTestData * pData;

    if(nNotify == BN_CLICKED)
    {
        switch(nIDCtrl)
        {
            case IDC_READ_FILE:
            case IDC_WRITE_FILE:
            case IDC_NTREAD_FILE:
            case IDC_NTWRITE_FILE:
                return OnReadWriteFile(hDlg, nIDCtrl);

            case IDC_LOCK_FILE:
            case IDC_UNLOCK_FILE:
            case IDC_NTLOCK_FILE:
            case IDC_NTUNLOCK_FILE:
                return OnLockUnlockFile(hDlg, nIDCtrl);

            case IDC_FILL_DATA_MENU:
                return ExecuteContextMenuForDlgItem(hDlg, g_hMenu_FillData, IDC_FILL_DATA_MENU);

            case IDC_FILL_DATA_ZEROS:
            case IDC_FILL_DATA_PATTERN:
            case IDC_FILL_DATA_RANDOM:
                return UpdateFileData(hDlg, NULL, 0, nIDCtrl);

            case IDC_GET_FILE_SIZE:
                return OnGetFileSizeClick(hDlg);

            case IDC_SET_FILE_POINTER:
                return OnSetFilePointerClick(hDlg);

            case IDC_SET_END_OF_FILE:
                return OnSetEndOfFileClick(hDlg);
        }
    }

    if(nNotify == EN_KILLFOCUS)
    {
        if(nIDCtrl == IDC_BYTE_OFFSET || nIDCtrl == IDC_LENGTH)
        {
            pData = GetDialogData(hDlg);
            UpdateFileData(hDlg, NULL, pData->cbFileData, 0);
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

        case UDN_DELTAPOS:
            return OnDeltaPos(hDlg, (NMUPDOWN *)pNMHDR);

        case DEN_PASTE:
            return OnDataPaste(hDlg, (PDTE_PASTE_DATA)pNMHDR);
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// Public functions

INT_PTR CALLBACK PageProc03(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
        case WM_INITDIALOG:
            return OnInitDialog(hDlg, lParam);

        case WM_SIZE:
            if(pAnchors != NULL)
                pAnchors->OnSize();
            return FALSE;

        case WM_APC:
            return OnApc(hDlg, lParam);

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
