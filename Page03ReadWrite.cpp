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

//-----------------------------------------------------------------------------
// Local defines

#define INITIAL_DATA_BUFFER_SIZE 0x10000

typedef NTSTATUS (NTAPI * NTREADWRITE)(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL
    );

typedef BOOL (WINAPI * READWRITE)(
    IN HANDLE hFile,
    IN LPVOID lpBuffer,
    IN DWORD nNumberOfBytesToRead,
    OUT LPDWORD lpNumberOfBytesRead,
    IN LPOVERLAPPED lpOverlapped
    );

//-----------------------------------------------------------------------------
// Helper functions

static void CompleteAsynchronousOperation(HWND hDlg, TApcEntry * pApc, DWORD dwErrCode, DWORD dwTransferred)
{
    TFileTestData * pData = GetDialogData(hDlg);
    HWND hWndEditor;

    // Convert the error code and number of bytes transferred
    if(pApc->bAsynchronousCompletion)
    {
        if(pApc->bHasIoStatus == false)
        {
            if(!GetOverlappedResult(pData->hFile, &pApc->Overlapped, &dwTransferred, TRUE))
                dwErrCode = GetLastError();
            else
                dwErrCode = ERROR_SUCCESS;
        }
        else
        {
            dwErrCode = RtlNtStatusToDosError(pApc->IoStatus.Status);
            dwTransferred = (DWORD)pApc->IoStatus.Information;
        }
    }

    // If the operation has succeeded, update few UI elements
    if(dwErrCode == ERROR_SUCCESS)
    {
        // If the "increase position" is checked, increment the byte position
        if(pApc->bIncrementPosition)
        {
            pApc->ByteOffset.QuadPart += dwTransferred;
            Hex2DlgText64(hDlg, IDC_BYTE_OFFSET, pApc->ByteOffset.QuadPart);
        }

        // If we have an output buffer, copy it to the data buffer
        if(pApc->BufferLength)
        {
            // Copy the data buffer from the APC to our user buffer
            pData->RdWrData.SetLength(pApc->BufferLength);
            memcpy(pData->RdWrData.pbData, (pApc + 1), pData->RdWrData.cbData);

            hWndEditor = GetDlgItem(hDlg, IDC_FILE_DATA);
            DataEditor_SetData(hWndEditor, 0, pData->RdWrData.pbData, pData->RdWrData.cbData);
        }
    }

    // Set the information about the operation
    if (pApc->bHasIoStatus)
    {
        SetResultInfo(hDlg, pApc->UserParam, pApc->IoStatus.Status, &pApc->IoStatus);
    }
    else
    {
        SetResultInfo(hDlg, pApc->UserParam, dwErrCode, dwTransferred);
    }

    // Free the APC entry
    FreeApcEntry(pApc);
}

//-----------------------------------------------------------------------------
// Message handlers

static TAnchors * pAnchors = NULL;

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
        pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_INFORMATION_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_INFORMATION, akLeft | akRight | akBottom);
    }

    // If there's field for data buffer, sets it to 8 bytes per line
    hWndChild = GetDlgItem(hDlg, IDC_FILE_DATA);
    if(hWndChild != NULL)
        DataEditor_SetDataFormat(hWndChild, PtrPointer32Bit, 0x08);

    // Set initial values for file position and data
    Hex2DlgText64(hDlg, IDC_BYTE_OFFSET, 0);
    Hex2DlgText32(hDlg, IDC_LENGTH, INITIAL_DATA_BUFFER_SIZE);
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

static int OnUpdateByteOffset(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    LONGLONG BaseAddress = 0;
    HWND hWndChild;

    // Convert the byte offset
    if(DlgText2Hex64(hDlg, IDC_BYTE_OFFSET, &BaseAddress) == ERROR_SUCCESS)
    {
        if((hWndChild = GetDlgItem(hDlg, IDC_FILE_DATA)) != NULL)
        {
            DataEditor_SetData(hWndChild, BaseAddress, pData->RdWrData.pbData, pData->RdWrData.cbData);
        }
    }

    return TRUE;
}

static int UpdateLength(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    DWORD DataLength = 0;
    HWND hWndChild;

    // Convert the length
    if(DlgText2Hex32(hDlg, IDC_LENGTH, &DataLength) == ERROR_SUCCESS)
    {
        if((hWndChild = GetDlgItem(hDlg, IDC_FILE_DATA)) != NULL)
        {
            pData->RdWrData.SetLength(DataLength);
            DataEditor_SetData(hWndChild, 0, pData->RdWrData.pbData, pData->RdWrData.cbData);
        }
    }

    return TRUE;
}

static int OnFillData(HWND hDlg, UINT FillPattern)
{
    TFileTestData * pData = GetDialogData(hDlg);
    LPCSTR WritePattern = "BAADF00D";
    HWND hWndChild;

    // If the new pattern is zero, it means to fill the same pattern like before
    if(FillPattern == 0)
        FillPattern = pData->FillPattern;

    switch(FillPattern)
    {
        case IDC_FILL_DATA_ZEROS:
            memset(pData->RdWrData.pbData, 0, pData->RdWrData.cbData);
            break;

        case IDC_FILL_DATA_PATTERN:
            for(ULONG i = 0; i < pData->RdWrData.cbData; i++)
                pData->RdWrData.pbData[i] = WritePattern[i % 8];
            break;

        case IDC_FILL_DATA_RANDOM:
            srand(GetTickCount());
            for(ULONG i = 0; i < pData->RdWrData.cbData; i++)
                pData->RdWrData.pbData[i] = (BYTE)(rand() % 0x100);
            break;
    }

    // Remember the current pattern
    pData->FillPattern = FillPattern;

    // Apply the new file data
    if((hWndChild = GetDlgItem(hDlg, IDC_FILE_DATA)) != NULL)
    {
        DataEditor_SetData(hWndChild, 0, pData->RdWrData.pbData, pData->RdWrData.cbData);
    }
    return ERROR_SUCCESS;
}

static int OnDeltaPos(HWND hDlg, NMUPDOWN * pNMUpDown)
{
    LONGLONG ByteOffset = 0;
    DWORD Length = 0;

    if(pNMUpDown->hdr.idFrom == IDC_BYTE_OFFSET_SPIN)
    {
        DlgText2Hex64(hDlg, IDC_BYTE_OFFSET, &ByteOffset);
        ByteOffset -= pNMUpDown->iDelta * 0x10000;
        if(ByteOffset < 0)
            ByteOffset = 0;
        Hex2DlgText64(hDlg, IDC_BYTE_OFFSET, ByteOffset);
    }

    if(pNMUpDown->hdr.idFrom == IDC_LENGTH_SPIN)
    {
        DlgText2Hex32(hDlg, IDC_LENGTH, &Length);
        Length -= pNMUpDown->iDelta * 0x1000;
        if((int)Length < 0)
            Length = 0;
        Hex2DlgText32(hDlg, IDC_LENGTH, Length);
    }

    return TRUE;
}

static int OnDataPaste(HWND hDlg, PDTE_PASTE_DATA pPasteData)
{
    // Ask the user whether to cut the data or not
    if(MessageBoxRc(hDlg, IDS_QUESTION, IDS_WANT_TRIM_DATA) == IDYES)
    {
        TFileTestData * pData = GetDialogData(hDlg);
        SIZE_T nLength = strlen(pPasteData->szPasteText);

        // Paste the data to the view
        if (pData->RdWrData.SetLength(pPasteData->PasteOffset + nLength) == ERROR_SUCCESS)
        {
            memcpy(pData->RdWrData.pbData + pPasteData->PasteOffset, pPasteData->szPasteText, nLength);
            DataEditor_SetData(GetDlgItem(hDlg, IDC_FILE_DATA), 0, pData->RdWrData.pbData, pData->RdWrData.cbData);
            Hex2DlgText32(hDlg, IDC_LENGTH, (DWORD)(pPasteData->PasteOffset + nLength));
        }

        // Mark the request as handled, so the data editor stops fuhrter processing
        pPasteData->bHandled = TRUE;
    }

    return TRUE;
}

static int OnReadWriteFile(HWND hDlg, int nIDCtrl)
{
    TFileTestData * pData = GetDialogData(hDlg);
    LARGE_INTEGER ByteOffset = {0};
    NTREADWRITE NtReadWrite;
    READWRITE ReadWrite;
    TApcEntry * pApc;
    NTSTATUS Status;
    LPBYTE DataBuffer;
    LPBYTE ApcBuffer;
    DWORD dwTransferred = 0;
    DWORD OutputLength = 0;
    DWORD dwErrCode = ERROR_SUCCESS;
    DWORD Length = 0;

    // Get the start position
    DlgText2Hex64(hDlg, IDC_BYTE_OFFSET, &ByteOffset.QuadPart);
    DlgText2Hex32(hDlg, IDC_LENGTH, &Length);
    assert(pData->RdWrData.cbData >= Length);

    // For read operation, we have data in the APC
    if(nIDCtrl == IDC_READ_FILE || nIDCtrl == IDC_NTREAD_FILE)
        OutputLength = Length;

    // Create new APC entry
    pApc = CreateApcEntry(pData, APC_TYPE_READ_WRITE, OutputLength);
    if(pApc != NULL)
    {   
        // Remember the state of "Increment position"
        pApc->ByteOffset = ByteOffset;
        pApc->bIncrementPosition = (IsDlgButtonChecked(hDlg, IDC_INCREASE_FILEPOS) == BST_CHECKED);
        pApc->BufferLength = OutputLength;
        ApcBuffer = (LPBYTE)(pApc + 1);

        // Prepare the OVERLAPPED structure
        pApc->Overlapped.OffsetHigh = ByteOffset.HighPart;
        pApc->Overlapped.Offset = ByteOffset.LowPart;

        // Perform the appropriate API
        switch(nIDCtrl)
        {
            case IDC_READ_FILE:
            case IDC_WRITE_FILE:

                // Set the data buffer and appropriate API function
                pApc->UserParam = (nIDCtrl == IDC_READ_FILE) ? (RSI_LAST_ERROR | RSI_READ) : (RSI_LAST_ERROR | RSI_WRITTEN);
                DataBuffer = (nIDCtrl == IDC_READ_FILE) ? ApcBuffer : pData->RdWrData.pbData;
                ReadWrite = (nIDCtrl == IDC_READ_FILE) ? ReadFile : (READWRITE)WriteFile;

                // Perform the read operation using ReadFile
                if(!ReadWrite(pData->hFile, DataBuffer, Length, &dwTransferred, &pApc->Overlapped))
                    dwErrCode = GetLastError();

                // If the read operation ended with ERROR_IO_PENDING, queue the APC
                if(dwErrCode == ERROR_IO_PENDING)
                {
                    SetResultInfo(hDlg, pApc->UserParam, ERROR_IO_PENDING, 0);
                    InsertApcEntry(pData, pApc);
                    return TRUE;
                }
                break;

            case IDC_NTREAD_FILE:
            case IDC_NTWRITE_FILE:

                // Set the data buffer and appropriate API function
                pApc->UserParam = RSI_NTSTATUS | RSI_INFORMATION;
                DataBuffer = (nIDCtrl == IDC_NTREAD_FILE) ? ApcBuffer : pData->RdWrData.pbData;
                NtReadWrite = (nIDCtrl == IDC_NTREAD_FILE) ? NtReadFile : NtWriteFile;
                pApc->bHasIoStatus = TRUE;

                // Perform the read/write operation
                Status = NtReadWrite(pData->hFile,
                                     pApc->hEvent,
                                     NULL,
                                     NULL,
                                    &pApc->IoStatus,
                                     DataBuffer,
                                     Length,
                                    &ByteOffset,
                                     NULL);

                // If the read operation ended with STATUS_PENDING, queue the APC
                if(Status == STATUS_PENDING)
                {
                    SetResultInfo(hDlg, pApc->UserParam, STATUS_PENDING, &pApc->IoStatus);
                    InsertApcEntry(pData, pApc);
                    return TRUE;
                }

                pApc->IoStatus.Status = Status;
                break;
        }

        // Complete the read/write operation
        CompleteAsynchronousOperation(hDlg, pApc, dwErrCode, dwTransferred);
    }
    else
    {
        SetResultInfo(hDlg, RSI_LAST_ERROR | RSI_NOINFO, GetLastError());
    }

    return TRUE;
}

static int OnLockUnlockFile(HWND hDlg, int nReadWriteType)
{
    TFileTestData * pData = GetDialogData(hDlg);
    LARGE_INTEGER ByteOffset = {0};
    LARGE_INTEGER LockLength = {0};
    TApcEntry * pApc;
    NTSTATUS Status;
    DWORD dwErrCode = ERROR_SUCCESS;

    // Get the start position
    DlgText2Hex64(hDlg, IDC_BYTE_OFFSET, &ByteOffset.QuadPart);
    DlgText2Hex32(hDlg, IDC_LENGTH, &LockLength.LowPart);
    assert((LONGLONG)pData->RdWrData.cbData >= LockLength.QuadPart);

    // Create new APC entry
    pApc = CreateApcEntry(pData, APC_TYPE_LOCK_UNLOCK);
    if(pApc != NULL)
    {
        // Perform the I/O operation
        switch(nReadWriteType)
        {
            case IDC_LOCK_FILE:

                // Prepare flags for completion
                pApc->UserParam = RSI_LAST_ERROR | RSI_NOINFO;

                // Perform the lock operation using LockFile
                if(!LockFile(pData->hFile, ByteOffset.LowPart, ByteOffset.HighPart, LockLength.LowPart, LockLength.HighPart))
                    dwErrCode = GetLastError();
                break;

            case IDC_UNLOCK_FILE:

                // Prepare flags for completion
                pApc->UserParam = RSI_LAST_ERROR | RSI_NOINFO;

                // Perform the unlock operation using UnlockFile
                if(!UnlockFile(pData->hFile, ByteOffset.LowPart, ByteOffset.HighPart, LockLength.LowPart, LockLength.HighPart))
                    dwErrCode = GetLastError();
                break;

            case IDC_NTLOCK_FILE:

                // Remember that this is a native call
                pApc->UserParam = RSI_NTSTATUS | RSI_NOINFO;
                pApc->bHasIoStatus = TRUE;

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
                    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_NOINFO, STATUS_PENDING);
                    InsertApcEntry(pData, pApc);
                    return TRUE;
                }

                // Save the error
                pApc->IoStatus.Status = Status;
                break;

            case IDC_NTUNLOCK_FILE:

                // Remember that this is a native call
                pApc->UserParam = RSI_NTSTATUS | RSI_NOINFO;
                pApc->bHasIoStatus = TRUE;

                // Perform the unlock operation using NtUnlockFile
                Status = NtUnlockFile(pData->hFile,
                                     &pApc->IoStatus,
                                     &ByteOffset,
                                     &LockLength,
                                      0);
                // Save the error
                assert(Status != STATUS_PENDING);
                pApc->IoStatus.Status = Status;
                break;
        }

        // Set the information about the operation
        CompleteAsynchronousOperation(hDlg, pApc, dwErrCode, 0);
    }
    else
    {
        SetResultInfo(hDlg, RSI_LAST_ERROR | RSI_NOINFO, GetLastError());
    }

    return TRUE;
}

static int OnGetFileSizeClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    LARGE_INTEGER FileSize = {0};
    DWORD dwErrCode = ERROR_SUCCESS;

    // Get the file size
    SetLastError(ERROR_SUCCESS);
    FileSize.LowPart = GetFileSize(pData->hFile, (LPDWORD)&FileSize.HighPart);
    dwErrCode = GetLastError();

    SetResultInfo(hDlg, RSI_LAST_ERROR | RSI_FILESIZE, dwErrCode, &FileSize);
    return TRUE;
}

static int OnSetFilePointerClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    LARGE_INTEGER ByteOffset;
    DWORD dwErrCode = ERROR_SUCCESS;

    // Get the file offset from the dialog
    DlgText2Hex64(hDlg, IDC_BYTE_OFFSET, &ByteOffset.QuadPart);
    
    // Apply the file size
    SetLastError(ERROR_SUCCESS);
    ByteOffset.LowPart = SetFilePointer(pData->hFile, ByteOffset.LowPart, &ByteOffset.HighPart, FILE_BEGIN);
    dwErrCode = GetLastError();

    SetResultInfo(hDlg, RSI_LAST_ERROR | RSI_FILEPOS, dwErrCode, &ByteOffset);
    return TRUE;
}

static int OnSetEndOfFileClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    DWORD dwErrCode = ERROR_SUCCESS;

    if(!SetEndOfFile(pData->hFile))
        dwErrCode = GetLastError();

    SetResultInfo(hDlg, RSI_LAST_ERROR | RSI_NOINFO, dwErrCode);
    return TRUE;
}

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
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
                return ExecuteContextMenuForDlgItem(hDlg, FindContextMenu(IDR_FILL_DATA_MENU), IDC_FILL_DATA_MENU);

            case IDC_FILL_DATA_ZEROS:
            case IDC_FILL_DATA_PATTERN:
            case IDC_FILL_DATA_RANDOM:
                return OnFillData(hDlg, nIDCtrl);

            case IDC_GET_FILE_SIZE:
                return OnGetFileSizeClick(hDlg);

            case IDC_SET_FILE_POINTER:
                return OnSetFilePointerClick(hDlg);

            case IDC_SET_END_OF_FILE:
                return OnSetEndOfFileClick(hDlg);
        }
    }

    if(nNotify == EN_CHANGE)
    {
        if(nIDCtrl == IDC_BYTE_OFFSET)
            return OnUpdateByteOffset(hDlg);
        if(nIDCtrl == IDC_LENGTH)
            UpdateLength(hDlg);
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
            CompleteAsynchronousOperation(hDlg, (TApcEntry *)lParam, 0, 0);
            return TRUE;

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
