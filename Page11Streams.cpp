/*****************************************************************************/
/* Page11Streams.cpp                      Copyright (c) Ladislav Zezula 2005 */
/*---------------------------------------------------------------------------*/
/* Description :                                                             */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 15.08.05  1.00  Lad  The first version of Page11Streams.cpp               */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local structures

#define MAX_STREAM_LENGTH 0x10000000

#define STREAM_TYPE_NONE           0
#define STREAM_TYPE_ADS            1
#define STREAM_TYPE_EA             2

struct TFileStream
{
    LIST_ENTRY Entry;
    LPTSTR szStreamName;                    // Pointer to stream name (variable length)
    LPBYTE pbStreamData;                    // Pointer to stream data (variable length)
    DWORD cbStreamData;                     // Length of the stream data
    DWORD dwStreamType;                     // Stream type

    BYTE Buffer[1];
};

//-----------------------------------------------------------------------------
// Local variables

static TListViewColumns Columns[] =
{
    {IDS_STREAM_TYPE,  60},
    {IDS_STREAM_NAME, 100},
    {IDS_STREAM_DATA, -1},
    {0, 0}
};

static LPCTSTR StreamTypes[] =
{
    _T("NONE"),
    _T("ADS"),
    _T("EA")
};

static TAnchors * pAnchors = NULL;

//-----------------------------------------------------------------------------
// Local functions

static LPTSTR StringFromAnsi(LPCSTR szStringA, ULONG nLength)
{
    LPTSTR szStringT;

    szStringT = new TCHAR[nLength+1];
    if(szStringT != NULL)
    {
#ifdef _UNICODE
        MultiByteToWideChar(CP_ACP, 0, szStringA, nLength, szStringT, nLength);
        szStringT[nLength] = 0;
#else
        _tcsncpy(szStringT, szStringA, nLength);
        szStringT[nLength] = 0;
#endif
    }

    return szStringT;
}

static LPTSTR StringFromWide(LPCWSTR szStringW, ULONG nLength)
{
    LPTSTR szStringT;

    szStringT = new TCHAR[nLength+1];
    if(szStringT != NULL)
    {
#ifdef _UNICODE
        _tcsncpy(szStringT, szStringW, nLength);
        szStringT[nLength] = 0;
#else
        WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, szStringW, nLength, szStringT, nLength, 0, 0);
        szStringT[nLength] = 0;
#endif
    }

    return szStringT;
}

static void NormalizeStreamName(LPTSTR szStreamName)
{
    LPTSTR szSrc = szStreamName;
    LPTSTR szTrg = szStreamName;

    // Skip the initial ':'
    if(szSrc[0] == _T(':'))
        szSrc++;

    // Copy everything until a colon or end of string
    while(szSrc[0] != 0 && szSrc[0] != _T(':'))
        *szTrg++ = *szSrc++;
    *szTrg = 0;
}

static void ItemDataToString(
    LPTSTR szStreamData,
    size_t nMaxChars,
    LPBYTE pbStreamData,
    ULONG cbStreamData)
{
    LPBYTE pbStreamDataEnd = pbStreamData + cbStreamData;
    LPTSTR szStreamDataEnd = szStreamData + nMaxChars;

    // Preset with default string
    LoadString(g_hInst, IDS_EMPTY_STREAM, szStreamData, (int)nMaxChars);

    // Iterate over all data
    while(pbStreamData < pbStreamDataEnd)
    {
        // Is there enough space for the text data?
        if(szStreamData + 3 > szStreamDataEnd)
            break;

        // Print the data bytes
        szStreamData += _stprintf(szStreamData, _T("%02X "), (DWORD)pbStreamData[0]);
        pbStreamData++;
    }
}

static int InsertStreamToListView(
    HWND hListView,
    LPCTSTR szStreamName,
    LPBYTE pbStreamData,
    DWORD dwStreamType,
    ULONG cbStreamData)
{
    LVITEM lvi;
    TCHAR szStreamData[0x100];

    // Insert the item type
    ZeroMemory(&lvi, sizeof(LVITEM));
    lvi.mask     = LVIF_TEXT;
    lvi.iItem    = 0x7FFFFFFF;
    lvi.iSubItem = 0;
    lvi.pszText  = (LPTSTR)StreamTypes[dwStreamType];
    lvi.iItem = ListView_InsertItem(hListView, &lvi);
    lvi.iSubItem++;

    // Insert the stream name
    lvi.pszText  = (LPTSTR)((szStreamName[0] != 0) ? szStreamName : _T("<default>"));
    ListView_SetItem(hListView, &lvi);
    lvi.iSubItem++;

    // Insert the item data
    ItemDataToString(szStreamData, _tsize(szStreamData), pbStreamData, cbStreamData);
    lvi.pszText  = (LPTSTR)szStreamData;
    ListView_SetItem(hListView, &lvi);

    return lvi.iItem;
}

/*
static TFileStream * CreateStream(PFILE_FULL_EA_INFORMATION pFileEa)
{
    TFileStream * pStream;
    size_t nSize;
    ULONG i;

    // Allocate stream
    nSize = sizeof(TFileStream) + (pFileEa->EaNameLength + 1) * sizeof(TCHAR) + pFileEa->EaValueLength;
    pStream = (TFileStream *)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, nSize);
    if(pStream != NULL)
    {
        // Copy the stream name
        pStream->szStreamName = (LPTSTR)&pStream->Buffer;
        for(i = 0; i < pFileEa->EaNameLength; i++)
            pStream->szStreamName[i] = pFileEa->EaName[i];
        pStream->szStreamName[i] = 0;

        // Copy the EA data
        memcpy(&pStream->szStreamName[i+1], pFileEa->





    }
}
*/

NTSTATUS NtCreateFileStream(PUNICODE_STRING SourceName, TFileStream * pStream)
{
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING FileName;
    NTSTATUS Status;
    LPWSTR szStreamName;
    HANDLE FileHandle = NULL;
    int nLength;

    // Create the full name of the stream
    FileName.MaximumLength = SourceName->MaximumLength;
    FileName.Length = SourceName->Length;
    FileName.Buffer = SourceName->Buffer;
    if(pStream->szStreamName[0] != 0)
    {
        szStreamName = (LPWSTR)((LPBYTE)FileName.Buffer + FileName.Length);
        nLength = swprintf(szStreamName, L":%s", pStream->szStreamName);
        FileName.Length = FileName.Length + (USHORT)(nLength * sizeof(WCHAR));
    }

    // Open the stream
    InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(&FileHandle, 
                           FILE_WRITE_DATA | SYNCHRONIZE,
                          &ObjAttr,
                          &IoStatus,
                           NULL,
                           FILE_ATTRIBUTE_NORMAL,
                           FILE_SHARE_READ,
                           FILE_OPEN_IF,
                           FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT,
                           NULL,
                           0);

    // Write the stream data
    if(NT_SUCCESS(Status))
    {
        Status = NtWriteFile(FileHandle,
                             NULL,
                             NULL,
                             NULL,
                            &IoStatus,
                             pStream->pbStreamData,
                             pStream->cbStreamData,
                             NULL,
                             NULL);
    }

    // Close the handle
    if(FileHandle != NULL)
        NtClose(FileHandle);
    return Status;
}

static PFILE_FULL_EA_INFORMATION ConvertStreamsToEaList(
    PLIST_ENTRY pHeadEntry,
    LPDWORD pcbFileEa)
{
    PFILE_FULL_EA_INFORMATION pFileEa = NULL;
    PFILE_FULL_EA_INFORMATION pLastEa = NULL;
    PFILE_FULL_EA_INFORMATION pEa = NULL;
    TFileStream * pStream;
    PLIST_ENTRY pListEntry;
    DWORD cbEntryLength = 0;
    DWORD cbEaLength = 0;
    size_t i;

    // Calculate total size needed for holding all EAs
    for(pListEntry = pHeadEntry->Flink; pListEntry != pHeadEntry; pListEntry = pListEntry->Flink)
    {
        pStream = CONTAINING_RECORD(pListEntry, TFileStream, Entry);
        if(pStream->dwStreamType == STREAM_TYPE_EA)
        {
            cbEntryLength = (DWORD)(FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + _tcslen(pStream->szStreamName) + 1 + pStream->cbStreamData);
            cbEaLength = cbEaLength + ((cbEntryLength + 7) & ~7);
        }
    }

    // Allocate space for complete EAs
    pFileEa = pEa = (PFILE_FULL_EA_INFORMATION)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, cbEaLength);
    if(pFileEa == NULL)
        return NULL;
    cbEaLength = 0;

    // Parse the list again and store all EAs
    for(pListEntry = pHeadEntry->Flink; pListEntry != pHeadEntry; pListEntry = pListEntry->Flink)
    {
        // Get the entry and the next entry
        pStream = CONTAINING_RECORD(pListEntry, TFileStream, Entry);
        if(pStream->dwStreamType == STREAM_TYPE_EA)
        {
            // Convert to the EA
            pEa->NextEntryOffset = 0;
            pEa->Flags           = 0;
            pEa->EaNameLength    = (UCHAR)_tcslen(pStream->szStreamName);
            pEa->EaValueLength   = (USHORT)pStream->cbStreamData;

            // Copy the file name
            for(i = 0; pStream->szStreamName[i] != 0; i++)
                pEa->EaName[i] = (CHAR)pStream->szStreamName[i];
            pEa->EaName[i] = 0;

            // Copy the EA data
            memcpy(&pEa->EaName[i + 1], pStream->pbStreamData, pStream->cbStreamData);

            // Calculate the length of the entry
            cbEntryLength = GetEaEntrySize(pEa);
            cbEaLength += cbEntryLength;

            // If this is not the last entry, put the next entry offset
            pLastEa = pEa;
            pEa->NextEntryOffset = cbEntryLength;
            pEa = (PFILE_FULL_EA_INFORMATION)((LPBYTE)pEa + cbEntryLength);
        }
    }

    // Clear next entry offset for the last EA
    if(pLastEa != NULL)
        pLastEa->NextEntryOffset = 0;

    // Give EA list and its size to the caller
    if(pcbFileEa != NULL)
        *pcbFileEa = cbEaLength; 
    return pFileEa;
}

static NTSTATUS LoadStreamFromFile(
    PUNICODE_STRING FileName,
    LPCWSTR szPlainName,
    TFileStream ** ppStream)
{
    FILE_STANDARD_INFORMATION StdInfo = {0};
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    TFileStream * pStream = NULL;
    NTSTATUS Status;
    LPCTSTR szStreamType = NULL;
    LPCTSTR szStreamName = NULL;
    HANDLE FileHandle;
    DWORD dwStreamType = STREAM_TYPE_NONE;
    size_t nSize;

    // Extract the stream type from the file name
    szStreamType = _tcschr(szPlainName, _T('#'));
    if(szStreamType == NULL)
        return STATUS_OBJECT_NAME_INVALID;
    szStreamType++;

    // Extract the stream name from the file name
    szStreamName = _tcschr(szStreamType, _T('#'));
    if(szStreamName == NULL)
        return STATUS_OBJECT_NAME_INVALID;
    szStreamName++;

    // Verify the stream types
    if(!_wcsnicmp(szStreamType, L"ADS", 3))
    {
        dwStreamType = STREAM_TYPE_ADS;
    }
    else if(!_wcsnicmp(szStreamType, L"EA", 2))
    {
        dwStreamType = STREAM_TYPE_EA;
    }
    else
        return STATUS_UNSUCCESSFUL;

    // Open the file and get its size
    InitializeObjectAttributes(&ObjAttr, FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&FileHandle,
                         FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                        &ObjAttr,
                        &IoStatus,
                         FILE_SHARE_READ,
                         FILE_SYNCHRONOUS_IO_ALERT);

    // Query the file size
    if(NT_SUCCESS(Status))
    {
        Status = NtQueryInformationFile(FileHandle,
                                       &IoStatus,
                                       &StdInfo,
                                        sizeof(FILE_STANDARD_INFORMATION),
                                        FileStandardInformation);
    }

    // Check against the maximum stream size
    if(NT_SUCCESS(Status))
    {        
        if(StdInfo.EndOfFile.HighPart != 0 || StdInfo.EndOfFile.LowPart > MAX_STREAM_LENGTH)
            Status = STATUS_BAD_FILE_TYPE;
    }

    // Create new stream
    if(NT_SUCCESS(Status))
    {
        nSize = sizeof(TFileStream) + (_tcslen(szStreamName) + 1) * sizeof(TCHAR) + StdInfo.EndOfFile.LowPart;
        pStream = (TFileStream *)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, nSize);
        if(pStream == NULL)
            Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    // Fill the stream structure
    if(NT_SUCCESS(Status))
    {
        pStream->szStreamName = (LPTSTR)(pStream + 1);
        _tcscpy(pStream->szStreamName, szStreamName);

        pStream->pbStreamData = (LPBYTE)(pStream->szStreamName + _tcslen(pStream->szStreamName) + 1);
        pStream->cbStreamData = StdInfo.EndOfFile.LowPart;
        pStream->dwStreamType = dwStreamType;

        Status = NtReadFile(FileHandle,
                            NULL,
                            NULL,
                            NULL,
                           &IoStatus,
                            pStream->pbStreamData,
                            pStream->cbStreamData,
                            NULL,
                            NULL);
    }

    if(!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlProcessHeap(), 0, pStream);
        pStream = NULL;
    }

    if(FileHandle != NULL)
        NtClose(FileHandle);
    if(ppStream != NULL)
        *ppStream = pStream;
    return Status;
}

static NTSTATUS SaveStreamToFile(
    LPTSTR szMainFileName,
    LPCTSTR szStreamName,
    LPBYTE pbStreamData,
    DWORD dwStreamType,
    DWORD dwStreamIndex,
    DWORD cbStreamData)
{
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING FileName;
    NTSTATUS Status;
    HANDLE FileHandle = NULL;
    TCHAR szFileName[MAX_PATH];
    
    // Construct the new file name
    _stprintf(szFileName, _T("%s#%s%02u#%s"), szMainFileName, StreamTypes[dwStreamType], dwStreamIndex, szStreamName);
    Status = FileNameToUnicodeString(&FileName, szFileName);

    // Create the stream file
    if(NT_SUCCESS(Status))
    {
        InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = NtCreateFile(&FileHandle,
                               GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                              &ObjAttr,
                              &IoStatus,
                               NULL,
                               FILE_ATTRIBUTE_NORMAL,
                               FILE_SHARE_READ,
                               FILE_OVERWRITE_IF,
                               FILE_SYNCHRONOUS_IO_ALERT,
                               NULL,
                               0);
    }
                               
    // Write the data
    if(NT_SUCCESS(Status))
    {
        Status = NtWriteFile(FileHandle,
                             NULL,
                             NULL,
                             NULL,
                            &IoStatus,
                             pbStreamData,
                             cbStreamData,
                             NULL,
                             NULL);
    }

    if(FileHandle != NULL)
        NtClose(FileHandle);
    return Status;
}

NTSTATUS LoadStreamsFromDirectory(
    PLIST_ENTRY pStreamLinks,    
    PUNICODE_STRING SourceName)
{
    PFILE_DIRECTORY_INFORMATION DirBuffer = NULL;
    PFILE_DIRECTORY_INFORMATION DirEntry = NULL;
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING FolderName = {0, 0, NULL};
    UNICODE_STRING FileName;
    UNICODE_STRING FileMask;
    TFileStream * pStream;
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE DirHandle = NULL;
    LPWSTR szPlainName = NULL;
    ULONG Length = 0x8000;

    // Now get pointer to plain file name
    szPlainName = wcsrchr(SourceName->Buffer, L'\\');
    if(szPlainName == NULL)
        Status = STATUS_OBJECT_PATH_SYNTAX_BAD;
    else
        szPlainName++;

    // Now get pointer to directory name and to file name
    if(NT_SUCCESS(Status))
    {
        // Get the folder name
        FolderName.MaximumLength = SourceName->MaximumLength;
        FolderName.Length = (USHORT)((szPlainName - SourceName->Buffer) * sizeof(WCHAR));
        FolderName.Buffer = SourceName->Buffer;

        // Get the file mask
        FileMask.MaximumLength = SourceName->MaximumLength - FolderName.Length;
        FileMask.Length = SourceName->Length - FolderName.Length + 4;
        FileMask.Buffer = SourceName->Buffer + (FolderName.Length / sizeof(WCHAR));
        wcscat(szPlainName, L"#*");
        
        // Open the directory
        InitializeObjectAttributes(&ObjAttr, &FolderName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = NtOpenFile(&DirHandle,
                             FILE_LIST_DIRECTORY | SYNCHRONIZE,
                            &ObjAttr,
                            &IoStatus,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             FILE_SYNCHRONOUS_IO_ALERT);
    }

    // Query the directory
    while(NT_SUCCESS(Status))
    {
        // Allocate space for directory info
        DirBuffer = DirEntry = (PFILE_DIRECTORY_INFORMATION)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, Length);
        if(DirBuffer == NULL)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // Query the directory
        Status = NtQueryDirectoryFile(DirHandle,
                                      NULL,
                                      NULL,
                                      NULL,
                                     &IoStatus,
                                      DirBuffer,
                                      Length,
                                      FileDirectoryInformation,
                                      FALSE,
                                     &FileMask,
                                      FALSE);
        if(NT_SUCCESS(Status))
            break;

        // If the buffer is not enough, reallocate the buffer and do again
        if(Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL)
        {
            Length = Length << 1;
            RtlFreeHeap(RtlProcessHeap(), 0, DirBuffer);
            DirBuffer = NULL;
            Status = STATUS_SUCCESS;
        }
    }

    // Now read each file
    if(NT_SUCCESS(Status))
    {
        for(;;)
        {
            // Skip directories
            if((DirEntry->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
            {
                // Construct the full file name for that directory entry
                FileName.MaximumLength = FolderName.MaximumLength;
                FileName.Length = (USHORT)(FolderName.Length + DirEntry->FileNameLength);
                FileName.Buffer = FolderName.Buffer;
                memcpy(szPlainName, DirEntry->FileName, DirEntry->FileNameLength);
                FileName.Buffer[FileName.Length / sizeof(WCHAR)] = 0;

                // Load that stream from the file
                Status = LoadStreamFromFile(&FileName, szPlainName, &pStream);
                if(!NT_SUCCESS(Status))
                    break;

                // Insert the stream from the list
                InsertTailList(pStreamLinks, &pStream->Entry);
            }

            // Move to the next directory entry
            if(DirEntry->NextEntryOffset == 0)
                break;
            DirEntry = (PFILE_DIRECTORY_INFORMATION)((LPBYTE)DirEntry + DirEntry->NextEntryOffset);
        }
    }

    if(NT_SUCCESS(Status))
    {
        if(IsListEmpty(pStreamLinks))
            Status = STATUS_NO_SUCH_FILE;
    }

    return Status;
}

static NTSTATUS EaListToListView(
    TFileTestData * pData,
    HWND hDlg, 
    HWND hListView,
    PFILE_FULL_EA_INFORMATION EaBuffer,
    bool bExportAsWell)
{
    NTSTATUS Status = STATUS_SUCCESS;
    LPTSTR szEaName;
    LPBYTE pbEaValue;
    DWORD dwStreamIndex = 1;

    // Iterate over all file EAs and show them/save them
    for(;;)
    {
        // Get the name and value from the EA
        szEaName  = StringFromAnsi(EaBuffer->EaName, EaBuffer->EaNameLength);
        pbEaValue = (LPBYTE)(&EaBuffer->EaName[EaBuffer->EaNameLength + 1]);

        // Fill them into the list view
        InsertStreamToListView(hListView, szEaName, pbEaValue, STREAM_TYPE_EA, EaBuffer->EaValueLength);

        // If we shall also save to the file, do it
        if(bExportAsWell)
        {
            Status = SaveStreamToFile(pData->szFileName1,
                                      szEaName,
                                      pbEaValue,
                                      STREAM_TYPE_EA,
                                      dwStreamIndex++,
                                      EaBuffer->EaValueLength);
            if(!NT_SUCCESS(Status))
            {
                MessageBoxError(hDlg, IDS_FAILED_TO_SAVE_FILE, RtlNtStatusToDosError(Status), _T("EA"));
                break;
            }
        }

        // Free the converted name
        delete [] szEaName;

        // Move to tne next entry
        if(EaBuffer->NextEntryOffset == 0)
            break;
        EaBuffer = (PFILE_FULL_EA_INFORMATION)((LPBYTE)EaBuffer + EaBuffer->NextEntryOffset);
    }

    return Status;
}

static NTSTATUS StreamsToListView(
    TFileTestData * pData,
    HWND hDlg, 
    HWND hListView,
    PFILE_STREAM_INFORMATION StrmBuffer,
    bool bExportAsWell)
{
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING FileName;
    NTSTATUS Status = STATUS_SUCCESS;
    LPCTSTR szFormat;
    TCHAR szFileName[MAX_PATH * 2];
    HANDLE hFile;
    LPTSTR szStreamName;
    LPBYTE pbStreamData;
    DWORD cbStreamData;
    DWORD dwStreamIndex = 1;

    // Iterate over all file streams and show them/save them
    for(;;)
    {
        // Get the name and value from the EA
        szStreamName = StringFromWide(StrmBuffer->StreamName, StrmBuffer->StreamNameLength);
        NormalizeStreamName(szStreamName);

        // Get the stream size
        cbStreamData = StrmBuffer->StreamSize.LowPart;
        if(StrmBuffer->StreamSize.QuadPart > MAX_STREAM_LENGTH)
            cbStreamData = StrmBuffer->StreamSize.LowPart;

        // Allocate buffer for stream data
        pbStreamData = (LPBYTE)RtlAllocateHeap(RtlProcessHeap(), 0, cbStreamData);
        if(pbStreamData != NULL)
        {
            // Prepare the ADS name
            szFormat = (szStreamName[0] != 0) ? _T("%s:%s") : _T("%s");
            _stprintf(szFileName, szFormat, pData->szFileName1, szStreamName);
            Status = FileNameToUnicodeString(&FileName, szFileName);
            if(!NT_SUCCESS(Status))
                break;

            // Open the ADS
            InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
            Status = NtOpenFile(&hFile,
                                 FILE_READ_DATA | SYNCHRONIZE,
                                &ObjAttr,
                                &IoStatus,
                                 FILE_SHARE_READ,
                                 FILE_SYNCHRONOUS_IO_ALERT);
            FreeFileNameString(&FileName);
            if(!NT_SUCCESS(Status))
            {
                MessageBoxError(hDlg, IDS_FAILED_TO_OPEN_STREAM, RtlNtStatusToDosError(Status), szFileName);
                break;
            }

            // Read the data from the stream
            Status = NtReadFile(hFile, NULL, NULL, NULL, &IoStatus, pbStreamData, cbStreamData, NULL, NULL);
            if(!NT_SUCCESS(Status))
                break;

            // Close the file
            NtClose(hFile);

            // Fill them into the list view
            InsertStreamToListView(hListView,
                                   szStreamName,
                                   pbStreamData,
                                   STREAM_TYPE_ADS,
                                   cbStreamData);

            // If we shall also save to the file, do it
            if(bExportAsWell)
            {
                Status = SaveStreamToFile(pData->szFileName1,
                                          szStreamName,
                                          pbStreamData,
                                          STREAM_TYPE_ADS,
                                          dwStreamIndex++,
                                          cbStreamData);
                if(!NT_SUCCESS(Status))
                {
                    MessageBoxError(hDlg, IDS_FAILED_TO_SAVE_FILE, RtlNtStatusToDosError(Status), _T("ADS"));
                    break;
                }
            }
        }

        // Free the converted name
        delete [] szStreamName;

        // Move to tne next entry
        if(StrmBuffer->NextEntryOffset == 0)
            break;
        StrmBuffer = (PFILE_STREAM_INFORMATION)((LPBYTE)StrmBuffer + StrmBuffer->NextEntryOffset);
    }

    return Status;
}

//-----------------------------------------------------------------------------
// Message handlers

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    PROPSHEETPAGE * pPage = (PROPSHEETPAGE *)lParam;
    TFileTestData * pData = (TFileTestData *)pPage->lParam;
    HWND hListView = GetDlgItem(hDlg, IDC_STREAMS_LIST);

    UNREFERENCED_PARAMETER(lParam);
    UNREFERENCED_PARAMETER(hDlg);

    SetDialogData(hDlg, pPage->lParam);

    // Initialize the listview
    ListView_CreateColumns(hListView, Columns);
    ListView_SetExtendedListViewStyle(hListView, LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

    // Configure dialog resizing
    if(pData->bEnableResizing)
    {
        pAnchors = new TAnchors();
        pAnchors->AddAnchor(hDlg, IDC_STREAMS_TITLE, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_STREAMS_LIST, akAll);
        pAnchors->AddAnchor(hDlg, IDC_QUERY_STREAMS, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_EXPORT_STREAMS, akLeftCenter | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_IMPORT_STREAMS, akRight | akBottom);
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
    BOOL bEnabled;

    if((pData->dwCreateOptions & FILE_OPEN_BY_FILE_ID) == 0)
    {
        SetDlgItemText(hDlg, IDC_FILE_NAME, pData->szFileName1);
        ConvertToWin32Name(hDlg, IDC_FILE_NAME);
    }

    // Enable/disable the buttons
    bEnabled = (IsHandleValid(pData->hFile)) ? TRUE : FALSE;
    EnableDlgItems(hDlg, bEnabled, IDC_QUERY_STREAMS, IDC_EXPORT_STREAMS, IDC_IMPORT_STREAMS, 0);

    bEnabled = (IsHandleInvalid(pData->hFile) && pData->szFileName1[0] != 0) ? TRUE : FALSE;
    EnableDlgItems(hDlg, bEnabled, IDC_IMPORT_STREAMS, 0);
    return TRUE;
}

static int OnExportStreams(HWND hDlg, bool bExportAsWell)
{
    PFILE_FULL_EA_INFORMATION EaBuffer = NULL;
    PFILE_STREAM_INFORMATION StrmBuffer = NULL;
    FILE_EA_INFORMATION FileEaInfo;
    TFileTestData * pData = GetDialogData(hDlg);
    IO_STATUS_BLOCK IoStatus = {0};
    NTSTATUS Status;
    ULONG StrmBufferSize = sizeof(FILE_STREAM_INFORMATION);
    ULONG EaBufferSize;
    HWND hListView = GetDlgItem(hDlg, IDC_STREAMS_LIST);

    // Delete all items from the list view
    ListView_DeleteAllItems(hListView);

    // Retrieve the initial guess of the EAs on the file
    Status = NtQueryInformationFile(pData->hFile, &IoStatus, &FileEaInfo, sizeof(FILE_EA_INFORMATION), FileEaInformation);
    EaBufferSize = FileEaInfo.EaSize;

    // Query the extended attributes file
    while(Status == STATUS_SUCCESS)
    {
        // Allocate buffer for extended attributes
        EaBuffer = (PFILE_FULL_EA_INFORMATION)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, EaBufferSize);
        if(EaBuffer == NULL)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // Try to query the extended attributes
        Status = NtQueryEaFile(pData->hFile,
                              &IoStatus,
                               EaBuffer,
                               EaBufferSize,
                               FALSE,
                               NULL,
                               0,
                               NULL,
                               TRUE);
        if(NT_SUCCESS(Status) || Status == STATUS_NO_EAS_ON_FILE)
            break;

        // If the buffer is not enough, reallocate the buffer and do again
        if(Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL)
        {
            EaBufferSize = EaBufferSize << 1;
            RtlFreeHeap(RtlProcessHeap(), 0, EaBuffer);
            EaBuffer = NULL;
            Status = STATUS_SUCCESS;
        }
    }

    // Put the EAs in the list view
    if(NT_SUCCESS(Status) && EaBuffer != NULL)
        EaListToListView(pData, hDlg, hListView, EaBuffer, bExportAsWell);
    Status = STATUS_SUCCESS;

    // Now query the stream list
    while(Status == STATUS_SUCCESS)
    {
        // Allocate buffer for extended attributes
        StrmBuffer = (PFILE_STREAM_INFORMATION)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, StrmBufferSize);
        if(StrmBuffer == NULL)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // Try to query the extended attributes
        Status = NtQueryInformationFile(pData->hFile,
                                       &IoStatus,
                                        StrmBuffer,
                                        StrmBufferSize,
                                        FileStreamInformation);
        if(NT_SUCCESS(Status))
            break;

        // If the buffer is not enough, reallocate the buffer and do again
        if(Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL)
        {
            StrmBufferSize = StrmBufferSize << 1;
            RtlFreeHeap(RtlProcessHeap(), 0, StrmBuffer);
            StrmBuffer = NULL;
            Status = STATUS_SUCCESS;
        }
    }

    // If succeeded, we insert the stream list to the list view
    if(NT_SUCCESS(Status) && StrmBuffer != NULL)
        StreamsToListView(pData, hDlg, hListView, StrmBuffer, bExportAsWell);

    // Set the status info
    SetResultInfo(hDlg, Status, NULL, IoStatus.Information);

    // Free buffers
    if(StrmBuffer != NULL)
        RtlFreeHeap(RtlProcessHeap(), 0, StrmBuffer);
    if(EaBuffer != NULL)
        RtlFreeHeap(RtlProcessHeap(), 0, EaBuffer);
    return TRUE;
}

static int OnImportStreams(HWND hDlg)
{
    PFILE_FULL_EA_INFORMATION pFileEa = NULL;
    OBJECT_ATTRIBUTES ObjAttr = {0};
    IO_STATUS_BLOCK IoStatus;
    TFileTestData * pData = GetDialogData(hDlg);
    UNICODE_STRING FileName;
    TFileStream * pStream;
    PLIST_ENTRY pHeadEntry;
    PLIST_ENTRY pListEntry;
    LIST_ENTRY StreamLinks;
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE FileHandle = NULL;
    DWORD cbFileEa = 0;
    HWND hListView = GetDlgItem(hDlg, IDC_STREAMS_LIST);
    int nError = ERROR_SUCCESS;

    // Delete all items from the list view
    ListView_DeleteAllItems(hListView);
    InitializeListHead(&StreamLinks);
    pHeadEntry = &StreamLinks;

    // Prepare the file name
    InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = FileNameToUnicodeString(&FileName, pData->szFileName1);

    // Now reallocate the buffer so we have enough space
    if(NT_SUCCESS(Status))
    {
        ULONG NewMaxLengh = (ULONG)FileName.MaximumLength + 255;

        if(NewMaxLengh > 0xFFFE)
            NewMaxLengh = 0xFFFE;
        
        FileName.MaximumLength = (USHORT)NewMaxLengh;
        FileName.Buffer = (PWSTR)RtlReAllocateHeap(RtlProcessHeap(), 0, FileName.Buffer, FileName.MaximumLength);
        if(FileName.Buffer == NULL)
            Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    // Query the directory and load all streams from all files
    if(NT_SUCCESS(Status))
        Status = LoadStreamsFromDirectory(&StreamLinks, &FileName); 

    // Delete the file
    if(NT_SUCCESS(Status))
    {
        Status = NtDeleteFile(&ObjAttr);
        if(Status == STATUS_OBJECT_NAME_NOT_FOUND || nError == STATUS_OBJECT_PATH_INVALID)
            Status = STATUS_SUCCESS;
    }

    // Now we have to create the main data stream
    if(NT_SUCCESS(Status))
    {
        // Write all ADSs to the file
        for(pListEntry = pHeadEntry->Flink; pListEntry != pHeadEntry; pListEntry = pListEntry->Flink)
        {
            // Get the file stream
            pStream = CONTAINING_RECORD(pListEntry, TFileStream, Entry);

            // Write the entry. After this, the entry no longer exists!!!
            if(pStream->dwStreamType == STREAM_TYPE_ADS)
            {
                Status = NtCreateFileStream(&FileName, pStream);
                if(!NT_SUCCESS(Status))
                    break;
            }
        }
    }

    // Now open the file
    if(NT_SUCCESS(Status))
    {
        Status = NtCreateFile(&FileHandle,
                               FILE_WRITE_EA | SYNCHRONIZE,
                              &ObjAttr,
                              &IoStatus,
                               NULL,
                               FILE_ATTRIBUTE_NORMAL,
                               FILE_SHARE_READ,
                               FILE_OPEN_IF,
                               FILE_SYNCHRONOUS_IO_ALERT,
                               NULL,
                               0);
    }

    // Convert the remaining streams to list of extended attributes
    if(NT_SUCCESS(Status))
    {
        pFileEa = ConvertStreamsToEaList(&StreamLinks, &cbFileEa);
        if(pFileEa == NULL)
            nError = STATUS_INSUFFICIENT_RESOURCES;
    }

    // Now apply the EAs to the file
    if(NT_SUCCESS(Status))
    {
        Status = NtSetEaFile(FileHandle, &IoStatus, pFileEa, cbFileEa);
    }

    // Set the streams to the list view
    while(!IsListEmpty(&StreamLinks))
    {
        // Get the file stream
        pStream = CONTAINING_RECORD(StreamLinks.Flink, TFileStream, Entry);

        // Insert the stream to the listview
        if(nError == ERROR_SUCCESS)
        {
            InsertStreamToListView(hListView, pStream->szStreamName,
                                              pStream->pbStreamData,
                                              pStream->dwStreamType,
                                              pStream->cbStreamData);
        }
        
        // Free the stream structure
        RemoveEntryList(&pStream->Entry);
        RtlFreeHeap(RtlProcessHeap(), 0, pStream);
    }

    // Close the file
    if(FileHandle != NULL)
        NtClose(FileHandle);

    // Set the result of the operation
    SetResultInfo(hDlg, Status);
    return TRUE;
}

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    if(nNotify == BN_CLICKED)
    {
        switch(nIDCtrl)
        {
            case IDC_QUERY_STREAMS:
                return OnExportStreams(hDlg, false);

            case IDC_EXPORT_STREAMS:
                return OnExportStreams(hDlg, true);

            case IDC_IMPORT_STREAMS:
                return OnImportStreams(hDlg);
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

INT_PTR CALLBACK PageProc11(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // Handlers specific to our dialog
    switch(uMsg)
    {
        case WM_INITDIALOG:
            OnInitDialog(hDlg, lParam);
            return TRUE;

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
