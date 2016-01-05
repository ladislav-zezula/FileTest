/*****************************************************************************/
/* DlgCopyFile.cpp                        Copyright (c) Ladislav Zezula 2016 */
/*---------------------------------------------------------------------------*/
/* Description: Copy file dialog                                             */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 05.01.16  1.00  Lad  The first version of DlgCopyFile.cpp                 */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local structures

#define COPY_BLOCK_SIZE 0x100000

typedef BOOL (WINAPI * COPYFILEEX)(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName, LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData, LPBOOL pbCancel, DWORD dwCopyFlags);
typedef BOOL (WINAPI * COPYFILE)(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName, BOOL bFailIfExists);

struct TDialogData
{
    TFileTestData * pFileTestData;  // Pointer to the global FileTest data
    COPYFILEEX pfnCopyFileEx;       // Pointer to CopyFileEx function, if available
    COPYFILE pfnCopyFile;           // Pointer to CopyFile function, if available
    HANDLE hThread;                 // Worker thread handle
    HWND hDlg;                      // Copy dialog
    HWND hCopyMethod;               // Copy method window
    HWND hProgress;                 // Copy progress window
    HWND hCopyInfo;                 // Copy info window
    DWORD dwProgressShift;          // Shift to the progress value to fit in the 32-bit integer
    BOOL bProgressInitialized;      // If set to TRUE, the progress has already been initialized
    BOOL bCancelled;                // If set to TRUE, CopyFileEx will cancel the copy
    int nError;                     // Result of the operation
};

//-----------------------------------------------------------------------------
// Copy worker

static HANDLE OpenSourceFile(LPCTSTR lpFileName)
{
    HANDLE hFile;

    // Try with FILE_SHARE_READ
    hFile = CreateFile(lpFileName, FILE_READ_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
        return hFile;

    // Try with FILE_SHARE_READ+FILE_SHARE_WRITE
    hFile = CreateFile(lpFileName, FILE_READ_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
        return hFile;

    return INVALID_HANDLE_VALUE;
}

static HANDLE CreateOrOpenTargetFile(LPCTSTR lpFileName)
{
    HANDLE hFile;

    // Try to open an existing file for read/write
    hFile = CreateFile(lpFileName, FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
        return hFile;

    // If the target is a volume, we need to open it with OPEN_EXISTING
    hFile = CreateFile(lpFileName, FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
        return hFile;

    return INVALID_HANDLE_VALUE;
}

static int TryGetFileSize(HANDLE hFile, LARGE_INTEGER & TotalFileSize)
{
    DWORD dwBytesReturned = 0;

    // Try to retrieve the file size as file size
    SetLastError(ERROR_SUCCESS);
    TotalFileSize.LowPart = GetFileSize(hFile, (LPDWORD)&TotalFileSize.HighPart);
    if(GetLastError() == ERROR_SUCCESS)
        return ERROR_SUCCESS;

    // Try to retrieve the file size as volume
    if(DeviceIoControl(hFile,
                       IOCTL_DISK_GET_LENGTH_INFO,
                       NULL,
                       0,
                      &TotalFileSize,
                       sizeof(LARGE_INTEGER),
                      &dwBytesReturned,
                      NULL))
    {
        if(TotalFileSize.QuadPart && dwBytesReturned == sizeof(LARGE_INTEGER))
            return ERROR_SUCCESS;
    }

    // Unable to query the file size
    return ERROR_NOT_SUPPORTED;
}

static void SetCopyInfo(TDialogData * pData, LPCTSTR szCopyMethod, BOOL bMarquee)
{
    DWORD dwStyle = GetWindowLong(pData->hProgress, GWL_STYLE);

    // Set the copy method
    if(szCopyMethod != NULL)
        SetWindowTextRc(pData->hCopyMethod, 0, szCopyMethod);

    // Set the progress marquee, if needed
    if(bMarquee)
    {
        SetWindowLong(pData->hProgress, GWL_STYLE, dwStyle | PBS_MARQUEE);
        SendMessage(pData->hProgress, PBM_SETMARQUEE, TRUE, 100);
    }
    else
    {
        SetWindowLong(pData->hProgress, GWL_STYLE, dwStyle & ~PBS_MARQUEE);
    }
}

static DWORD CALLBACK CopyProgressRoutine(
    LARGE_INTEGER TotalFileSize,
    LARGE_INTEGER TotalBytesTransferred,
    LARGE_INTEGER StreamSize,
    LARGE_INTEGER StreamBytesTransferred,
    DWORD dwStreamNumber,
    DWORD dwCallbackReason,
    HANDLE hSourceFile,
    HANDLE hDestinationFile,
    LPVOID lpData)
{
    TDialogData * pData = (TDialogData *)lpData;
    LPCTSTR szFormat = _T("%I64u bytes copied");
    TCHAR szCopyInfo[0x200];

    // Keep compiler happy
    UNREFERENCED_PARAMETER(StreamSize);
    UNREFERENCED_PARAMETER(StreamBytesTransferred);
    UNREFERENCED_PARAMETER(dwStreamNumber);
    UNREFERENCED_PARAMETER(dwCallbackReason);
    UNREFERENCED_PARAMETER(hSourceFile);
    UNREFERENCED_PARAMETER(hDestinationFile);

    // Initialize the progress, if not initialized yet
    if(TotalFileSize.QuadPart != 0 && pData->bProgressInitialized == FALSE)
    {
        LONGLONG TotalSize = TotalFileSize.QuadPart;

        // Determine the shift value
        while(TotalSize > 0xFFFFFFF)
        {
            TotalSize = TotalSize >>= 1;
            pData->dwProgressShift++;
        }

        // Initialize the progress range
        SendMessage(pData->hProgress, PBM_SETRANGE32, 0, (ULONG)(TotalFileSize.QuadPart >> pData->dwProgressShift));
        pData->bProgressInitialized = TRUE;
    }

    // Set the copy progress in the progress bar
    if(pData->bProgressInitialized)
    {
        SendMessage(pData->hProgress, PBM_SETPOS, (WPARAM)(TotalBytesTransferred.QuadPart >> pData->dwProgressShift), 0);
        szFormat = _T("%I64u of %I64u bytes copied");
    }

    // Set the copy progress as text
    StringCchPrintf(szCopyInfo, _countof(szCopyInfo), szFormat, TotalBytesTransferred.QuadPart, TotalFileSize.QuadPart);
    SetWindowText(pData->hCopyInfo, szCopyInfo);

    // Keep copying or stop, depends on the cancelled flag
    return (pData->bCancelled) ? PROGRESS_STOP : PROGRESS_CONTINUE;
}

static int CopyLoop(
    TDialogData * pData,
    HANDLE hFile1,
    HANDLE hFile2,
    LPBYTE pbCopyBuffer,
    DWORD cbBlockSize,
    LARGE_INTEGER & TotalFileSize,
    LARGE_INTEGER & BytesCopied,
    DWORD dwCopyFlags)
{
    OVERLAPPED Overlapped = {0};
    DWORD dwProgressStep = 0;

    // Copy as long as we are not cancelled
    while(pData->bCancelled == FALSE)
    {
        DWORD dwTransferred = 0;
        DWORD dwRet;
        int nError = ERROR_SUCCESS;

        // Read the source file/drive
        Overlapped.OffsetHigh = BytesCopied.HighPart;
        Overlapped.Offset = BytesCopied.LowPart;
        if(!ReadFile(hFile1, pbCopyBuffer, cbBlockSize, &dwTransferred, &Overlapped))
        {
            switch(nError = GetLastError())
            {
                case ERROR_IO_DEVICE:   // If we shall skip the I/O errors, fill the source with zeros
                    if(dwCopyFlags & COPY_FILE_SKIP_IO_ERRORS)
                    {
                        memset(pbCopyBuffer, 0, cbBlockSize);
                        dwTransferred = cbBlockSize;
                        nError = ERROR_SUCCESS;
                    }
                    break;

                default:
                    break;
            }
        }

        // If we failed to read the data, do nothing
        if(nError != ERROR_SUCCESS || dwTransferred == 0)
            return nError;

        // Write the target file
        if(!WriteFile(hFile2, pbCopyBuffer, dwTransferred, &dwTransferred, &Overlapped))
            return GetLastError();

        // Report the copy progress
        BytesCopied.QuadPart += dwTransferred;
        dwProgressStep += dwTransferred;

        // Show the progress, but not too often
        if(dwProgressStep >= COPY_BLOCK_SIZE)
        {
            dwRet = CopyProgressRoutine(TotalFileSize, BytesCopied, TotalFileSize, BytesCopied, 0, 0, hFile1, hFile2, pData);
            if(dwRet != PROGRESS_CONTINUE)
                return ERROR_CANCELLED;
            dwProgressStep = 0;
        }
    }

    // All OK
    return ERROR_SUCCESS;
}

static void CopyFileWorker_ByHand(TDialogData * pData, LPCTSTR szFileName1, LPCTSTR szFileName2, DWORD dwCopyFlags)
{
    LARGE_INTEGER TotalFileSize = {0};
    LARGE_INTEGER BytesCopied = {0};
    FILETIME ft1;
    FILETIME ft2;
    FILETIME ft3;
    HANDLE hFile1 = INVALID_HANDLE_VALUE;
    HANDLE hFile2 = INVALID_HANDLE_VALUE;
    LPBYTE pbCopyBuffer = NULL;
    DWORD cbCopyBuffer = COPY_BLOCK_SIZE;
    bool bHasFileSize = false;
    bool bHasFileTime = false;
    int nError = ERROR_SUCCESS;

    // Initialize the copy info
    SetCopyInfo(pData, _T("ReadFile+WriteFile"), TRUE);

    // Open the source file file
    if(nError == ERROR_SUCCESS)
    {
        hFile1 = OpenSourceFile(szFileName1);
        if(IsHandleInvalid(hFile1))
            nError = GetLastError();
    }

    // Create or open the target file
    if(nError == ERROR_SUCCESS)
    {
        hFile2 = CreateOrOpenTargetFile(szFileName2);
        if(IsHandleInvalid(hFile2))
            nError = GetLastError();
    }

    // Try to get the file size
    if(nError == ERROR_SUCCESS)
    {
        bHasFileSize = (TryGetFileSize(hFile1, TotalFileSize) == ERROR_SUCCESS);
        SetCopyInfo(pData, NULL, bHasFileSize ? FALSE : TRUE);
    }

    // Get the file size and time of the original file
    // Note that the SetFileTime can fail if the second file
    // is actually a volume (\\.\GlobalRoot\Device\HarddiskVolume15)
    // Do not report the error
    if(nError == ERROR_SUCCESS)
    {
        if(GetFileTime(hFile1, &ft1, &ft2, &ft3))
            bHasFileTime = true;
    }

    // Allocate the buffer for holding copied data
    if(nError == ERROR_SUCCESS)
    {
        // Allocate buffer
        pbCopyBuffer = (LPBYTE)HeapAlloc(g_hHeap, 0, cbCopyBuffer);
        if(pbCopyBuffer == NULL)
            nError = ERROR_NOT_ENOUGH_MEMORY;
    }

    // Perform the copy
    if(nError == ERROR_SUCCESS)
    {
        nError = CopyLoop(pData, hFile1, hFile2, pbCopyBuffer, cbCopyBuffer, TotalFileSize, BytesCopied, 0);
        switch(nError)
        {
            case ERROR_SUCCESS:
            case ERROR_HANDLE_EOF:
                nError = ERROR_SUCCESS;
                break;

            case ERROR_IO_DEVICE:                                                                               
                if(dwCopyFlags & COPY_FILE_SKIP_IO_ERRORS)
                    nError = CopyLoop(pData, hFile1, hFile2, pbCopyBuffer, SECTOR_SIZE, TotalFileSize, BytesCopied, dwCopyFlags);
                break;
        }
    }

    // Set the file time of the copied file
    // Note that the SetFileTime can fail if the second file
    // is actually a volume (\\.\GlobalRoot\Device\HarddiskVolume15)
    // Do not report the error
    if(nError == ERROR_SUCCESS && bHasFileTime)
    {
        SetFileTime(hFile2, &ft1, &ft2, &ft3);
    }

    // Free resources
    if(pbCopyBuffer != NULL)
        HeapFree(g_hHeap, 0, pbCopyBuffer);
    if(IsHandleValid(hFile2))
        CloseHandle(hFile2);
    if(IsHandleValid(hFile1))
        CloseHandle(hFile1);
    
    // Remember the last error
    pData->nError = nError;
}

static void CopyFileWorker_CopyFileEx(TDialogData * pData, LPCTSTR szFileName1, LPCTSTR szFileName2, DWORD dwCopyFlags)
{
    // Setup the copy method
    SetCopyInfo(pData, _T("CopyFileEx"), FALSE);

    // Perform the copy
    if(!CopyFileEx(szFileName1, szFileName2, CopyProgressRoutine, pData, &pData->bCancelled, dwCopyFlags))
        pData->nError = GetLastError();
}

static void CopyFileWorker_CopyFile(TDialogData * pData, LPCTSTR szFileName1, LPCTSTR szFileName2, DWORD dwCopyFlags)
{
    // Setup the copy method
    SetCopyInfo(pData, _T("CopyFile"), TRUE);

    // Perform the copy
    if(!CopyFile(szFileName1, szFileName2, (dwCopyFlags & COPY_FILE_FAIL_IF_EXISTS) ? TRUE : FALSE))
        pData->nError = GetLastError();
}

static DWORD WINAPI CopyFileWorker(LPVOID lpParameter)
{
    TFileTestData * pFtData;
    TDialogData * pData = (TDialogData *)lpParameter;

    // Get the pointer to the main data
    pFtData = pData->pFileTestData;
    pData->nError = ERROR_SUCCESS;

    // Manual copy (ReadFile+WriteFile)?
    if(pFtData->dwCopyFileFlags & COPY_FILE_USE_READ_WRITE)
    {
        CopyFileWorker_ByHand(pData, pFtData->szFileName1, pFtData->szFileName2, pFtData->dwCopyFileFlags);
    }

    // Is CopyFileEx available?
    else if(pData->pfnCopyFileEx != NULL)
    {
        CopyFileWorker_CopyFileEx(pData, pFtData->szFileName1, pFtData->szFileName2, pFtData->dwCopyFileFlags);
    }

    // Is CopyFile available?
    else if(pData->pfnCopyFile != NULL)
    {
        CopyFileWorker_CopyFile(pData, pFtData->szFileName1, pFtData->szFileName2, pFtData->dwCopyFileFlags);
    }

    // None available?
    else
    {
        pData->nError = ERROR_NOT_SUPPORTED;
    }

    // Work is complete
    PostMessage(pData->hDlg, WM_WORK_COMPLETE, 0, 0);
    return 0;
}

//-----------------------------------------------------------------------------
// Event handlers

static INT_PTR OnInitDialog(HWND hDlg, LPARAM lParam)
{
    TDialogData * pData = (TDialogData *)lParam;
    HMODULE hKernel32 = GetModuleHandle(_T("Kernel32.dll"));

    // Set the dialog icon
    SetDialogIcon(hDlg, IDI_FILE_TEST);

    // Set the copy options
    pData->pfnCopyFileEx = (COPYFILEEX)GetProcAddress(hKernel32, "CopyFileExW");
    pData->pfnCopyFile   = (COPYFILE)GetProcAddress(hKernel32, "CopyFileW");
    pData->hDlg          = hDlg;
    pData->hCopyMethod   = GetDlgItem(hDlg, IDC_COPY_METHOD);
    pData->hProgress     = GetDlgItem(hDlg, IDC_COPY_PROGRESS);
    pData->hCopyInfo     = GetDlgItem(hDlg, IDC_COPY_INFO);
    SetWindowLongPtr(hDlg, DWLP_USER, lParam);
    
    // Initiate the copy
    PostMessage(hDlg, WM_START_WORK, 0, 0);
    return TRUE;
}

static INT_PTR OnStartWork(HWND hDlg)
{
    TDialogData * pData = (TDialogData *)GetWindowLongPtr(hDlg, DWLP_USER);
    DWORD dwThreadId;

    // Create the worker thread
    pData->hThread = CreateThread(NULL, 0, CopyFileWorker, pData, 0, &dwThreadId);
    if(pData->hThread == NULL)
        EndDialog(hDlg, GetLastError());

    return FALSE;
}

static INT_PTR OnWorkComplete(HWND hDlg)
{
    TDialogData * pData = (TDialogData *)GetWindowLongPtr(hDlg, DWLP_USER);

    // Close the worker thread handle
    if(pData->hThread != NULL)
        CloseHandle(pData->hThread);
    pData->hThread = NULL;

    // End the dialog
    EndDialog(hDlg, IDOK);
    return FALSE;
}

static INT_PTR OnCommand(HWND hDlg, UINT nNotifyCode, UINT nCtrlID)
{
    TDialogData * pData = (TDialogData *)GetWindowLongPtr(hDlg, DWLP_USER);

    if(nNotifyCode == BN_CLICKED)
    {
        // Do we have a copy operation running?
        pData = (TDialogData *)GetWindowLongPtr(hDlg, DWLP_USER);
        if(pData->hThread != NULL)
        {
            SetWindowTextRc(pData->hCopyMethod, IDS_COPY_CANCELLED);
            pData->bCancelled = TRUE;
            return FALSE;
        }

        // Any other button closes the dialog
        pData->nError = ERROR_CANCELLED;
        EndDialog(hDlg, nCtrlID);
    }
    
    return FALSE;
}

//-----------------------------------------------------------------------------
// Message handler

static INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
        case WM_INITDIALOG:
            return OnInitDialog(hDlg, lParam);

        case WM_START_WORK:
            return OnStartWork(hDlg);

        case WM_WORK_COMPLETE:
            return OnWorkComplete(hDlg);

        case WM_COMMAND:
            return OnCommand(hDlg, HIWORD(wParam), LOWORD(wParam));
    }

    return FALSE;
}

//-----------------------------------------------------------------------------
// Dialog functions

INT_PTR CopyFileDialog(HWND hParent, TFileTestData * pData)
{
    TDialogData Data;

    // Prepare the copy data
    memset(&Data, 0, sizeof(TDialogData));
    Data.pFileTestData = pData;
    DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_COPY_FILE), hParent, DialogProc, (LPARAM)&Data);

    // Return the error code
    return Data.nError;
}
