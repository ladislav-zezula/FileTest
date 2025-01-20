/*****************************************************************************/
/* DlgCopyFile.cpp                        Copyright (c) Ladislav Zezula 2016 */
/*---------------------------------------------------------------------------*/
/* Description: Copy file dialog                                             */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 05.01.16  1.00  Lad  Created                                              */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local structures

#define COPY_BLOCK_SIZE             0x00100000
#define CALLBACK_READ_BAD_SECTOR    0x80000001
#define STRING_FROM_BYTES_LENGTH    0x20

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
    DWORD dwErrCode;                // Result of the operation
    BOOL bProgressInitialized;      // If set to TRUE, the progress has already been initialized
    BOOL bCancelled;                // If set to TRUE, CopyFileEx will cancel the copy

    ULARGE_INTEGER TotalBytes;      // Total bytes attempted to read
    ULARGE_INTEGER BytesRead;       // Bytes that have been read succefssfully
    HANDLE hLogFile;                // Log file handle
};

//-----------------------------------------------------------------------------
// Local variables

static LPCTSTR szReadErrorFmt = _T("Offset %I64X: Read Error %u\r\n");

//-----------------------------------------------------------------------------
// Copy worker

#define LOG_BUFFER_SIZE   0x1000

static LPCTSTR StringFromBytes(LARGE_INTEGER & ByteCount, LPTSTR szBuffer)
{
    ULONGLONG Value64 = ByteCount.QuadPart;
    LPTSTR szSaveBuffer = szBuffer;
    LPTSTR szBufferEnd = szBuffer + STRING_FROM_BYTES_LENGTH - 1;
    int nDigitIndex = 0;

    // Keep copying
    while(szBuffer < szBufferEnd)
    {
        // Put one digit
        if(szBuffer > szSaveBuffer && (nDigitIndex % 3) == 0)
            *szBuffer++ = _T(' ');
        *szBuffer++ = (TCHAR)((Value64 % 10) + _T('0'));

        // Shift the input value
        if((Value64 = Value64 / 10) == 0)
            break;
        nDigitIndex++;
    }

    // Terminate the buffer
    szBuffer[0] = 0;

    // Revert the buffer and return its begin
    _tcsrev(szSaveBuffer);
    return szSaveBuffer;
}

static void LogPrintf(HANDLE hLogFile, LPCTSTR szFormat, ...)
{
    LPBYTE pbBuffer;
    va_list argList;
    DWORD dwWritten;
    int nLength;

    // Only if we have a log file open
    if(IsHandleValid(hLogFile))
    {
        // Allocate buffer for printf
        pbBuffer = (LPBYTE)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, (LOG_BUFFER_SIZE * sizeof(TCHAR)) + (LOG_BUFFER_SIZE * sizeof(CHAR)));
        if(pbBuffer != NULL)
        {
            LPTSTR szBufferT = (LPTSTR)pbBuffer;
            LPSTR szBufferA = (LPSTR)(szBufferT + LOG_BUFFER_SIZE);

            // Format the string
            va_start(argList, szFormat);
            StringCchVPrintf(szBufferT, LOG_BUFFER_SIZE, szFormat, argList);
            va_end(argList);

            // Convert to ANSI
            nLength = WideCharToMultiByte(CP_ACP, 0, szBufferT, -1, szBufferA, LOG_BUFFER_SIZE, NULL, NULL);
            if(nLength != 0)
                WriteFile(hLogFile, szBufferA, (DWORD)(nLength - 1), &dwWritten, NULL);

            // Free the buffers
            HeapFree(g_hHeap, 0, pbBuffer);
        }
    }
}

static HANDLE OpenSourceFile(LPCTSTR lpFileName, ULONG dwCopyFlags)
{
    HANDLE hFile;
    DWORD dwFlagsAndAttributes = 0;

    // If we are supposed to skip I/O errors, open the source with no buffering
    // in order to be able to read sector-by-sector
    if(dwCopyFlags & (COPY_FILE_SKIP_IO_ERRORS | COPY_FILE_PER_SECTOR))
        dwFlagsAndAttributes |= FILE_FLAG_NO_BUFFERING;

    // Try with FILE_SHARE_READ
    hFile = CreateFile(lpFileName,
                       FILE_READ_DATA | FILE_READ_ATTRIBUTES,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       dwFlagsAndAttributes,
                       NULL);
    if(hFile != INVALID_HANDLE_VALUE)
        return hFile;

    // Try with FILE_SHARE_READ+FILE_SHARE_WRITE
    hFile = CreateFile(lpFileName,
                       FILE_READ_DATA | FILE_READ_ATTRIBUTES,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL,
                       OPEN_EXISTING,
                       dwFlagsAndAttributes,
                       NULL);
    if(hFile != INVALID_HANDLE_VALUE)
        return hFile;

    return INVALID_HANDLE_VALUE;
}

static HANDLE CreateOrOpenTargetFile(LPCTSTR lpFileName)
{
    HANDLE hFile;
    ULONG dwShareMode;

    // Try to open an existing file for read/write
    hFile = CreateFile(lpFileName, FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
        return hFile;

    // If the target is a volume, we need to open it with OPEN_EXISTING
    // Make sure we try all possible sharing modes
    for(dwShareMode = 0; dwShareMode <= (FILE_SHARE_READ|FILE_SHARE_WRITE); dwShareMode++)
    {
        hFile = CreateFile(lpFileName, FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, dwShareMode, NULL, OPEN_EXISTING, 0, NULL);
        if(hFile != INVALID_HANDLE_VALUE)
            return hFile;
        if(GetLastError() != ERROR_SHARING_VIOLATION)
            break;
    }

    return INVALID_HANDLE_VALUE;
}

static int TryGetFileSize(HANDLE hFile, LARGE_INTEGER & TotalFileSize)
{
    PARTITION_INFORMATION PartitionInfo;
    ULARGE_INTEGER FileSize;
    DISK_GEOMETRY DiskGeometry;
    DWORD dwBytesReturned = 0;

    // Try to retrieve the file size as file size
    SetLastError(ERROR_SUCCESS);
    FileSize.LowPart = GetFileSize(hFile, &FileSize.HighPart);
    if(GetLastError() == ERROR_SUCCESS)
    {
        TotalFileSize.QuadPart = FileSize.QuadPart;
        return ERROR_SUCCESS;
    }

    // Try to retrieve the partition information
    if(DeviceIoControl(hFile,
                       IOCTL_DISK_GET_PARTITION_INFO,
                       NULL,
                       0,
                      &PartitionInfo,
                       sizeof(PARTITION_INFORMATION),
                      &dwBytesReturned,
                       NULL))
    {
        TotalFileSize.QuadPart = PartitionInfo.PartitionLength.QuadPart;
        return ERROR_SUCCESS;
    }

    // Try to retrieve the drive layout
    if(DeviceIoControl(hFile,
                       IOCTL_DISK_GET_DRIVE_GEOMETRY,
                       NULL,
                       0,
                      &DiskGeometry,
                       sizeof(DISK_GEOMETRY),
                      &dwBytesReturned,
                      NULL))
    {
        TotalFileSize.QuadPart = DiskGeometry.Cylinders.QuadPart * 
                                 DiskGeometry.TracksPerCylinder *
                                 DiskGeometry.SectorsPerTrack *
                                 DiskGeometry.BytesPerSector;
        return ERROR_SUCCESS;
    }

    // Unable to query the file size
    return ERROR_NOT_SUPPORTED;
}

static void SetCopyMethodAndProgress(TDialogData * pData, LPCTSTR szCopyMethod, BOOL bMarquee)
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

static void SetCopyInfo(TDialogData * pData, LPCTSTR szFormat, ...)
{
    TCHAR szCopyInfo[MAX_PATH+0x80];
    va_list argList;

    va_start(argList, szFormat);
    StringCchVPrintf(szCopyInfo, _countof(szCopyInfo), szFormat, argList);
    SetWindowText(pData->hCopyInfo, szCopyInfo);
    va_end(argList);
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
    LPCTSTR szFormat = _T("%s bytes copied");
    TCHAR szCopyInfo[0x200];
    TCHAR szBytes1[STRING_FROM_BYTES_LENGTH];
    TCHAR szBytes2[STRING_FROM_BYTES_LENGTH];

    // Keep compiler happy
    UNREFERENCED_PARAMETER(StreamSize);
    UNREFERENCED_PARAMETER(StreamBytesTransferred);
    UNREFERENCED_PARAMETER(dwStreamNumber);
    UNREFERENCED_PARAMETER(hSourceFile);
    UNREFERENCED_PARAMETER(hDestinationFile);

    // If we are trying to recover a bad sector, show it
    if(dwCallbackReason == CALLBACK_READ_BAD_SECTOR)
    {
        StringCchPrintf(szCopyInfo, _countof(szCopyInfo), _T("Reading damaged file at %s..."), StringFromBytes(TotalBytesTransferred, szBytes1));
        SetWindowText(pData->hCopyInfo, szCopyInfo);
        return PROGRESS_CONTINUE;
    }

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
        szFormat = _T("%s of %s bytes copied");
    }

    // Set the copy progress as text
    StringCchPrintf(szCopyInfo, _countof(szCopyInfo), szFormat,
                                                      StringFromBytes(TotalBytesTransferred, szBytes1),
                                                      StringFromBytes(TotalFileSize, szBytes2));
    SetWindowText(pData->hCopyInfo, szCopyInfo);

    // Keep copying or stop, depends on the cancelled flag
    return (pData->bCancelled) ? PROGRESS_STOP : PROGRESS_CONTINUE;
}

static BOOL ReadFileSkipErrors(
    TDialogData * pData,
    HANDLE hFile,
    LARGE_INTEGER & SrcByteOffset,
    LPBYTE pbCopyBuffer,
    DWORD cbBlockSize,
    PDWORD pcbTransferred)
{
    LARGE_INTEGER ByteOffset = SrcByteOffset;
    OVERLAPPED Overlapped = {0};
    DWORD dwBytesTransferred = 0;
    DWORD dwBytesToRead;
    DWORD dwBytesRead;

    // First, reset the entire buffer with zeros
    memset(pbCopyBuffer, 0, cbBlockSize);

    // Now try to read the file sector-by-sector
    while(cbBlockSize > 0)
    {
        DWORD dwErrCode = ERROR_SUCCESS;

        // Inform the user that we are attempting to read a damaged sector
        CopyProgressRoutine(ByteOffset, ByteOffset, ByteOffset, ByteOffset, 0, CALLBACK_READ_BAD_SECTOR, hFile, NULL, pData);

        // Setup reading
        Overlapped.OffsetHigh = ByteOffset.HighPart;
        Overlapped.Offset = ByteOffset.LowPart;
        dwBytesToRead = min(cbBlockSize, SECTOR_SIZE);

        // Read the file, up to one sector
        if(!ReadFile(hFile, pbCopyBuffer, dwBytesToRead, &dwBytesRead, &Overlapped))
        {
            // Handle two cases which we know that can mean an end of file/drive
            if((dwErrCode = GetLastError()) == ERROR_HANDLE_EOF || dwErrCode == ERROR_SECTOR_NOT_FOUND)
                break;

            // Write the error to the log file
            LogPrintf(pData->hLogFile, szReadErrorFmt, ByteOffset.QuadPart, dwErrCode);
        }

        // Increment the stat counters. Use the number of bytes REALLY read
        pData->TotalBytes.QuadPart += dwBytesToRead;
        pData->BytesRead.QuadPart += dwBytesRead;

        // Move pointers
        ByteOffset.QuadPart += dwBytesToRead;
        dwBytesTransferred += dwBytesToRead;
        pbCopyBuffer += dwBytesToRead;
        cbBlockSize -= dwBytesToRead;
    }

    // Give the caller the number of bytes read
    if(pcbTransferred != NULL)
        pcbTransferred[0] = dwBytesTransferred;
    return TRUE;
}

static DWORD CopyLoop(
    TDialogData * pData,
    HANDLE hFile1,
    HANDLE hFile2,
    LPBYTE pbCopyBuffer,
    DWORD cbBlockSize,
    LARGE_INTEGER & TotalFileSize,
    LARGE_INTEGER & ByteOffset,
    DWORD dwCopyFlags)
{
    OVERLAPPED Overlapped = {0};
    DWORD dwLastTickCount = 0;

    // Shall we copy per sector?
    if(dwCopyFlags & COPY_FILE_PER_SECTOR)
    {
        assert(cbBlockSize >= SECTOR_SIZE);
        cbBlockSize = SECTOR_SIZE;
    }

    // Copy as long as we are not cancelled
    while(pData->bCancelled == FALSE)
    {
        DWORD dwTransferred = 0;
        DWORD dwErrCode = ERROR_SUCCESS;
        DWORD dwRet;

        // Read the source file/drive
        Overlapped.OffsetHigh = ByteOffset.HighPart;
        Overlapped.Offset = ByteOffset.LowPart;
        if(!ReadFile(hFile1, pbCopyBuffer, cbBlockSize, &dwTransferred, &Overlapped))
        {
            switch(dwErrCode = GetLastError())
            {
                case ERROR_HANDLE_EOF:          // At or beyond the end of the file
                    dwErrCode = ERROR_SUCCESS;
                    break;

                case ERROR_SECTOR_NOT_FOUND:    // Example: Reading 0x400 bytes from \\.\PhysicalDrive0, 0x200 bytes before end
                    ReadFileSkipErrors(pData, hFile1, ByteOffset, pbCopyBuffer, cbBlockSize, &dwTransferred);
                    dwErrCode = ERROR_SUCCESS;
                    break;

                default:    // ERROR_CRC, ERROR_IO_DEVICE
                    
                    // Shall we skip the I/O errors?
                    if(dwCopyFlags & COPY_FILE_SKIP_IO_ERRORS)
                    {
                        // If we are NOT copying per sector, do this block sector-by-sector
                        if(cbBlockSize > SECTOR_SIZE)
                        {
                            ReadFileSkipErrors(pData, hFile1, ByteOffset, pbCopyBuffer, cbBlockSize, &dwTransferred);
                            dwErrCode = ERROR_SUCCESS;
                            break;
                        }

                        // If we already have been copying per sector, fill the buffer with zeros
                        memset(pbCopyBuffer, 0, SECTOR_SIZE);
                        dwTransferred = cbBlockSize;
                    }
                    
                    // Log the error.
                    LogPrintf(pData->hLogFile, szReadErrorFmt, ByteOffset.QuadPart, dwErrCode);
                    pData->TotalBytes.QuadPart += cbBlockSize;
                    
                    // If we are supposed to skip read errors, reset the error code
                    dwErrCode = (dwCopyFlags & COPY_FILE_SKIP_IO_ERRORS) ? ERROR_SUCCESS : dwErrCode;
                    break;
            }
        }
        else
        {
            pData->TotalBytes.QuadPart += dwTransferred;
            pData->BytesRead.QuadPart += dwTransferred;
        }

        // If we failed to read the data, do nothing
        if(dwErrCode != ERROR_SUCCESS || dwTransferred == 0)
            return dwErrCode;

        // Write the target file
        if(!WriteFile(hFile2, pbCopyBuffer, dwTransferred, &dwTransferred, &Overlapped))
            return GetLastError();

        // Report the copy progress
        ByteOffset.QuadPart += dwTransferred;

        // Show the progress twice per second 
        if(GetTickCount() > (dwLastTickCount + 500))
        {
            dwRet = CopyProgressRoutine(TotalFileSize, ByteOffset, TotalFileSize, ByteOffset, 0, 0, hFile1, hFile2, pData);
            if(dwRet != PROGRESS_CONTINUE)
                return ERROR_CANCELLED;

            dwLastTickCount = GetTickCount();
        }
    }

    // Cancelled?
    return (pData->bCancelled) ? ERROR_CANCELLED : ERROR_SUCCESS;
}

static void CopyFileWorker_ByHand(TDialogData * pData, LPCTSTR szFileName1, LPCTSTR szFileName2, DWORD dwCopyFlags)
{
    LARGE_INTEGER TotalFileSize = {0};
    LARGE_INTEGER ByteOffset = {0};
    FILETIME ft1;
    FILETIME ft2;
    FILETIME ft3;
    HANDLE hFile1 = INVALID_HANDLE_VALUE;
    HANDLE hFile2 = INVALID_HANDLE_VALUE;
    LPBYTE pbCopyBuffer = NULL;
    TCHAR szLogFile[MAX_PATH];
    DWORD cbCopyBuffer = COPY_BLOCK_SIZE;
    DWORD dwErrCode = ERROR_SUCCESS;
    bool bHasFileSize = false;
    bool bHasFileTime = false;

    // Initialize the copy info
    SetCopyMethodAndProgress(pData, _T("ReadFile+WriteFile"), TRUE);

    // Open the log file, if required.
    if(dwCopyFlags & COPY_FILE_LOG_IO_ERRORS)
    {
        GetModuleFileName(NULL, szLogFile, _countof(szLogFile));
        ReplaceFileExt(szLogFile, _T(".log"));
        pData->hLogFile = CreateFile(szLogFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
        if(IsHandleInvalid(pData->hLogFile))
            dwErrCode = GetLastError();
    }

    // Open the source file file
    if(dwErrCode == ERROR_SUCCESS)
    {
        SetCopyInfo(pData, _T("Opening file %s ..."), szFileName1);
        hFile1 = OpenSourceFile(szFileName1, dwCopyFlags);
        if(IsHandleInvalid(hFile1))
            dwErrCode = GetLastError();
    }

    // Create or open the target file
    if(dwErrCode == ERROR_SUCCESS)
    {
        SetCopyInfo(pData, _T("Opening file %s ..."), szFileName2);
        hFile2 = CreateOrOpenTargetFile(szFileName2);
        if(IsHandleInvalid(hFile2))
            dwErrCode = GetLastError();
    }

    // Try to get the file size
    if(dwErrCode == ERROR_SUCCESS)
    {
        bHasFileSize = (TryGetFileSize(hFile1, TotalFileSize) == ERROR_SUCCESS);
        SetCopyMethodAndProgress(pData, NULL, bHasFileSize ? FALSE : TRUE);
    }

    // Get the file size and time of the original file
    // Note that the SetFileTime can fail if the second file
    // is actually a volume (\\.\GlobalRoot\Device\HarddiskVolume15)
    // Do not report the error
    if(dwErrCode == ERROR_SUCCESS)
    {
        if(GetFileTime(hFile1, &ft1, &ft2, &ft3))
            bHasFileTime = true;
    }

    // Allocate the buffer for holding copied data
    // Use VirtualAlloc to ensure that the buffer is sector aligned 
    if(dwErrCode == ERROR_SUCCESS)
    {
        // Allocate buffer
        pbCopyBuffer = (LPBYTE)VirtualAlloc(NULL, cbCopyBuffer, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if(pbCopyBuffer == NULL)
            dwErrCode = ERROR_NOT_ENOUGH_MEMORY;
    }

    // Perform the copy
    if(dwErrCode == ERROR_SUCCESS)
    {
        LogPrintf(pData->hLogFile, _T("--- Starting file copy -------\r\n")
                                   _T("Source File: %s\r\n")
                                   _T("Target File: %s\r\n")
                                   _T("Copy Flags : %08X\r\n"), szFileName1, szFileName2, dwCopyFlags);

        dwErrCode = CopyLoop(pData,
                          hFile1,
                          hFile2,
                          pbCopyBuffer,
                          cbCopyBuffer,
                          TotalFileSize,
                          ByteOffset,
                          dwCopyFlags);

        LogPrintf(pData->hLogFile, _T("Total bytes copied: %I64u\r\n")
                                   _T("Successfully read : %I64u\r\n")
                                   _T("--- Copy Complete ------------\r\n"), pData->TotalBytes, pData->BytesRead);
    }

    // Set the file time of the copied file
    // Note that the SetFileTime can fail if the second file
    // is actually a volume (\\.\GlobalRoot\Device\HarddiskVolume15)
    // Do not report the error
    if(dwErrCode == ERROR_SUCCESS && bHasFileTime)
    {
        SetFileTime(hFile2, &ft1, &ft2, &ft3);
    }

    if(IsHandleValid(hFile2))
    {
        SetCopyInfo(pData, _T("Closing file %s ..."), szFileName2);
        CloseHandle(hFile2);
    }

    if(IsHandleValid(hFile1))
    {
        SetCopyInfo(pData, _T("Closing file %s ..."), szFileName1);
        CloseHandle(hFile1);
    }

    // Free resources
    if(pbCopyBuffer != NULL)
        VirtualFree(pbCopyBuffer, cbCopyBuffer, MEM_RELEASE);
    if(IsHandleValid(pData->hLogFile))
        CloseHandle(pData->hLogFile);

    // Remember the last error
    pData->dwErrCode = dwErrCode;
}

static void CopyFileWorker_CopyFileEx(TDialogData * pData, LPCTSTR szFileName1, LPCTSTR szFileName2, DWORD dwCopyFlags)
{
    // Setup the copy method
    SetCopyMethodAndProgress(pData, _T("CopyFileEx"), FALSE);
    assert(pData->pfnCopyFileEx != NULL);

    // Perform the copy
    if(!pData->pfnCopyFileEx(szFileName1, szFileName2, CopyProgressRoutine, pData, &pData->bCancelled, dwCopyFlags))
        pData->dwErrCode = GetLastError();
}

static void CopyFileWorker_CopyFile(TDialogData * pData, LPCTSTR szFileName1, LPCTSTR szFileName2, DWORD dwCopyFlags)
{
    // Setup the copy method
    SetCopyMethodAndProgress(pData, _T("CopyFile"), TRUE);
    assert(pData->pfnCopyFile != NULL);

    // Perform the copy
    if(!pData->pfnCopyFile(szFileName1, szFileName2, (dwCopyFlags & COPY_FILE_FAIL_IF_EXISTS) ? TRUE : FALSE))
        pData->dwErrCode = GetLastError();
}

static DWORD WINAPI CopyFileWorker(LPVOID lpParameter)
{
    TFileTestData * pFtData;
    TDialogData * pData = (TDialogData *)lpParameter;

    // Get the pointer to the main data
    pFtData = pData->pFileTestData;
    pData->dwErrCode = ERROR_SUCCESS;

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
        pData->dwErrCode = ERROR_NOT_SUPPORTED;
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

    // Set the dialog icon
    SetDialogIcon(hDlg, IDI_FILE_TEST);

    // Set the copy options
    ResolveAPIs(g_szKernel32Dll, "CopyFileExW", (FARPROC *)(&pData->pfnCopyFileEx),
                                 "CopyFileW", (FARPROC *)(&pData->pfnCopyFile), NULL);
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
        pData->dwErrCode = ERROR_CANCELLED;
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
    return Data.dwErrCode;
}
