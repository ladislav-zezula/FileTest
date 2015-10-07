/*****************************************************************************/
/* Page10Links.cpp                        Copyright (c) Ladislav Zezula 2009 */
/*---------------------------------------------------------------------------*/
/* Description:                                                              */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 19.10.09  1.00  Lad  The first version of Page10Links.cpp                 */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local structures

#define FSCTL_SET_REPARSE_POINT         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // REPARSE_DATA_BUFFER,
#define FSCTL_GET_REPARSE_POINT         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED, FILE_ANY_ACCESS) // REPARSE_DATA_BUFFER
#define FSCTL_DELETE_REPARSE_POINT      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // REPARSE_DATA_BUFFER,

typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR  DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

#define REPARSE_DATA_BUFFER_HEADER_SIZE   FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer)

//-----------------------------------------------------------------------------
// Helper functions

static PREPARSE_DATA_BUFFER Dlg2ReparseData(HWND hDlg, PULONG pTotalLength)
{
    PREPARSE_DATA_BUFFER ReparseData = NULL;
    UNICODE_STRING SubstName = {0};
    NTSTATUS Status;
    LPBYTE pbTargetPtr = NULL;
    TCHAR szSubstName[MAX_PATH];
    TCHAR szPrintName[MAX_PATH];
    ULONG cchSubstName;
    ULONG cchPrintName;
    USHORT cbPrintName;
    ULONG TotalLength = 0;
    HWND hWndChild;

    // Get the substitute name and the printable name
    cchSubstName = GetDlgItemText(hDlg, IDC_SUBST_NAME, szSubstName, _maxchars(szSubstName));
    cchPrintName = GetDlgItemText(hDlg, IDC_PRINT_NAME, szPrintName, _maxchars(szPrintName));
    if(cchSubstName == 0)
        return NULL;

    // Also calculate the byte length
    Status = FileNameToUnicodeString(&SubstName, szSubstName);
    if(NT_SUCCESS(Status))
    {
        // Get the printable name length in bytes
        cbPrintName = (USHORT)(cchPrintName * sizeof(WCHAR));

        // Get the type of the reparse point
        hWndChild = GetDlgItem(hDlg, IDC_JUNCTION_TYPE);
        switch(ComboBox_GetCurSel(hWndChild))
        {
            case 0: // IO_REPARSE_TAG_MOUNT_POINT

                // Calculate the total memory needed for the reparse data buffer
                TotalLength = FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) +
                              SubstName.Length + sizeof(WCHAR) +
                              cbPrintName + sizeof(WCHAR);
                ReparseData = (PREPARSE_DATA_BUFFER)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, TotalLength);
                if(ReparseData != NULL)
                {
                    //
                    // Prepare the header of REPARSE_DATA_BUFFER:
                    //
                    // - Total data length must be REPARSE_DATA_BUFFER_HEADER_SIZE + sizeof(MountPointReparseBuffer) - sizeof(WCHAR) + filenames
                    // - ReparseDataLength + REPARSE_DATA_BUFFER_HEADER_SIZE must be equal to total data length
                    // - There must be both NT name and DOS name. Both names will be zero-terminated
                    //

                    ReparseData->ReparseTag        = IO_REPARSE_TAG_MOUNT_POINT;
                    ReparseData->ReparseDataLength = (USHORT)(TotalLength - REPARSE_DATA_BUFFER_HEADER_SIZE);
                    ReparseData->MountPointReparseBuffer.SubstituteNameOffset = 0;
                    ReparseData->MountPointReparseBuffer.SubstituteNameLength = SubstName.Length;
                    ReparseData->MountPointReparseBuffer.PrintNameOffset = SubstName.Length + sizeof(WCHAR);
                    ReparseData->MountPointReparseBuffer.PrintNameLength = cbPrintName;
                    pbTargetPtr = (LPBYTE)ReparseData->MountPointReparseBuffer.PathBuffer;
                }
                break;

            case 1: // IO_REPARSE_TAG_SYMLINK

                // Calculate the total memory needed for the reparse data buffer
                TotalLength = FIELD_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer) +
                              SubstName.Length + sizeof(WCHAR) +
                              cbPrintName + sizeof(WCHAR);
                ReparseData = (PREPARSE_DATA_BUFFER)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, TotalLength);
                if(ReparseData != NULL)
                {
                    //
                    // Prepare the header of REPARSE_DATA_BUFFER:
                    //
                    // - Total data length must be REPARSE_DATA_BUFFER_HEADER_SIZE + sizeof(MountPointReparseBuffer) - sizeof(WCHAR) + filenames
                    // - ReparseDataLength + REPARSE_DATA_BUFFER_HEADER_SIZE must be equal to total data length
                    // - There must be both NT name and DOS name. Both names will be zero-terminated
                    //

                    ReparseData->ReparseTag        = IO_REPARSE_TAG_SYMLINK;
                    ReparseData->ReparseDataLength = (USHORT)(TotalLength - REPARSE_DATA_BUFFER_HEADER_SIZE);
                    ReparseData->SymbolicLinkReparseBuffer.SubstituteNameOffset = 0;
                    ReparseData->SymbolicLinkReparseBuffer.SubstituteNameLength = SubstName.Length;
                    ReparseData->SymbolicLinkReparseBuffer.PrintNameOffset = SubstName.Length + sizeof(WCHAR);
                    ReparseData->SymbolicLinkReparseBuffer.PrintNameLength = cbPrintName;
                    pbTargetPtr = (LPBYTE)ReparseData->SymbolicLinkReparseBuffer.PathBuffer;
                }
                break;

            default:
                return NULL;
        }

        // Copy the substitute name
        memcpy(pbTargetPtr, SubstName.Buffer, SubstName.Length);
        pbTargetPtr += SubstName.Length + sizeof(WCHAR);

        // Copy the printable name
        memcpy(pbTargetPtr, szPrintName, cbPrintName);

        // Give the total length
        if(pTotalLength != NULL)
            *pTotalLength = TotalLength;
        FreeFileNameString(&SubstName);
    }
    return ReparseData;
}

static void ReparseData2Dlg(HWND hDlg, PREPARSE_DATA_BUFFER ReparseData)
{
    TCHAR szNameBuffer[MAX_PATH];
    PBYTE pbNameBuffer;
    PWSTR szSubstName = NULL;
    PWSTR szPrintName = NULL;
    USHORT SubstituteNameLength = 0;
    USHORT PrintNameLength = 0;
    HWND hWndChild = GetDlgItem(hDlg, IDC_JUNCTION_TYPE);
    int ReparseTagIndex = -1;

    switch(ReparseData->ReparseTag)
    {
        case IO_REPARSE_TAG_MOUNT_POINT:
            
            // Get the pointer to name buffer
            pbNameBuffer = (PBYTE)(ReparseData->MountPointReparseBuffer.PathBuffer);
            szSubstName  = (PWSTR)(pbNameBuffer + ReparseData->MountPointReparseBuffer.SubstituteNameOffset);
            SubstituteNameLength = ReparseData->MountPointReparseBuffer.SubstituteNameLength;
            szPrintName  = (PWSTR)(pbNameBuffer + ReparseData->MountPointReparseBuffer.PrintNameOffset);
            PrintNameLength = ReparseData->MountPointReparseBuffer.PrintNameLength;
            ReparseTagIndex = 0;
            break;

        case IO_REPARSE_TAG_SYMLINK:

            // Get the pointer to name buffer
            pbNameBuffer = (PBYTE)(ReparseData->SymbolicLinkReparseBuffer.PathBuffer);
            szSubstName  = (PWSTR)(pbNameBuffer + ReparseData->SymbolicLinkReparseBuffer.SubstituteNameOffset);
            SubstituteNameLength = ReparseData->SymbolicLinkReparseBuffer.SubstituteNameLength;
            szPrintName  = (PWSTR)(pbNameBuffer + ReparseData->SymbolicLinkReparseBuffer.PrintNameOffset);
            PrintNameLength = ReparseData->SymbolicLinkReparseBuffer.PrintNameLength;
            ReparseTagIndex = 1;
            break;
    }

    // Did we manage to extract something from the buffer?
    if(ReparseTagIndex != -1)
    {
        // Set the reparse point type
        ComboBox_SetCurSel(hWndChild, ReparseTagIndex);

        // Set the substitute name
        if(szSubstName != NULL)
        {
            wcsncpy(szNameBuffer, szSubstName, SubstituteNameLength / sizeof(WCHAR));
            szNameBuffer[SubstituteNameLength / sizeof(WCHAR)] = 0;
            SetDlgItemText(hDlg, IDC_SUBST_NAME, szNameBuffer);
        }

        // Set the printable name
        if(szPrintName != NULL)
        {
            wcsncpy(szNameBuffer, szPrintName, PrintNameLength / sizeof(WCHAR));
            szNameBuffer[PrintNameLength / sizeof(WCHAR)] = 0;
            SetDlgItemText(hDlg, IDC_PRINT_NAME, szNameBuffer);
        }
    }
    else
    {
        ComboBox_SetCurSel(hWndChild, 2);
        _stprintf(szNameBuffer, _T("Unknown reparse tag: %08lX"), ReparseData->ReparseTag);
        SetDlgItemText(hDlg, IDC_SUBST_NAME, szNameBuffer);
        SetDlgItemText(hDlg, IDC_PRINT_NAME, _T(""));
    }
}

LPTSTR GetFullHardLinkName(PFILE_LINK_ENTRY_INFORMATION pLinkInfo, LPTSTR szFileName)
{
    PFILE_NAME_INFORMATION pNameInfo = NULL;
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING FileName;
    NTSTATUS Status;
    LPTSTR szHardLinkName = NULL;
    LPTSTR szTemp;
    HANDLE hVolume = NULL;
    HANDLE hParent;
    TCHAR szVolumeName[MAX_PATH];
    ULONG BackSlashCount = 0;
    ULONG BackSlashMax = 1;
    ULONG CharIndex = 0;
    ULONG NameLength;

    // Extract volume name from the file name
    if(szFileName[0] == _T('\\'))
        BackSlashMax = 3;
    while(BackSlashCount < BackSlashMax)
    {
        if(szFileName[CharIndex] == _T('\\'))
            BackSlashCount++;
        szVolumeName[CharIndex] = szFileName[CharIndex];
        CharIndex++;
    }
    szVolumeName[CharIndex] = 0;

    // Open the volume
    InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = FileNameToUnicodeString(&FileName, szVolumeName);
    if(NT_SUCCESS(Status))
    {
        Status = NtOpenFile(&hVolume,
                             SYNCHRONIZE,
                            &ObjAttr,
                            &IoStatus,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             FILE_SYNCHRONOUS_IO_ALERT);
        FreeFileNameString(&FileName);
    }
    
    if(NT_SUCCESS(Status))
    {
        // Now open the target directory by ID
        InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, hVolume, NULL);
        FileName.MaximumLength = sizeof(LARGE_INTEGER);
        FileName.Length = sizeof(LARGE_INTEGER);
        FileName.Buffer = (PWSTR)&pLinkInfo->ParentFileId;
        Status = NtOpenFile(&hParent,
                             FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                            &ObjAttr,
                            &IoStatus,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             FILE_OPEN_BY_FILE_ID | FILE_SYNCHRONOUS_IO_ALERT);

        // Now query name of the directory
        if(NT_SUCCESS(Status))
        {
            pNameInfo = (PFILE_NAME_INFORMATION)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, 0x1000);
            if(pNameInfo != NULL)
            {
                Status = NtQueryInformationFile(hParent,
                                               &IoStatus,
                                                pNameInfo,
                                                0x1000,
                                                FileNameInformation);
                if(NT_SUCCESS(Status))
                {
                    NameLength = (ULONG)_tcslen(szVolumeName) * sizeof(WCHAR) +
                                 pNameInfo->FileNameLength +
                                 (pLinkInfo->FileNameLength + 1) * sizeof(WCHAR);
                    szHardLinkName = szTemp = (LPTSTR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, NameLength);
                    if(szHardLinkName != NULL)
                    {
                        // Copy the volume name
                        _tcscpy(szTemp, szVolumeName);
                        szTemp = _tcsrchr(szTemp, _T('\\'));

                        // Copy the directory name
                        memcpy(szTemp, pNameInfo->FileName, pNameInfo->FileNameLength);
                        szTemp += pNameInfo->FileNameLength / sizeof(WCHAR);

                        // Append backslash
                        if(pNameInfo->FileNameLength > 2)
                            *szTemp++ = _T('\\');

                        // Copy the link name
                        memcpy(szTemp, pLinkInfo->FileName, (pLinkInfo->FileNameLength * sizeof(WCHAR)));
                        szTemp[pLinkInfo->FileNameLength] = 0;
                    }
                }

                HeapFree(g_hHeap, 0, pNameInfo);
            }
            NtClose(hParent);
        }
        NtClose(hVolume);
    }

    return szHardLinkName;
}

//-----------------------------------------------------------------------------
// Message handlers

static TAnchors * pAnchors = NULL;

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    PROPSHEETPAGE * pPage = (PROPSHEETPAGE *)lParam;
    TFileTestData * pData = (TFileTestData *)pPage->lParam;
    HWND hComboBox;

    SetDialogData(hDlg, pPage->lParam);

    // Configure dialog resizing
    if(pData->bEnableResizing)
    {
        pAnchors = new TAnchors();
        pAnchors->AddAnchor(hDlg, IDC_SYMLINK_FRAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SYMLINK, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SYMLINK_TARGET, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SYMLINK_QUERY, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_SYMLINK_CREATE, akLeftCenter | akTop);
        pAnchors->AddAnchor(hDlg, IDC_SYMLINK_DELETE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_HARDLINK_FRAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_HARDLINK_LIST, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_NEW_HARDLINK, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_HARDLINK_CREATE, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_HARDLINK_QUERY, akLeftCenter | akTop);
        pAnchors->AddAnchor(hDlg, IDC_HARDLINK_DELETE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_REPARSE_FRAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_REPARSE, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SUBST_NAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_PRINT_NAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_JUNCTION_TYPE, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_REPARSE_CREATE, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_REPARSE_QUERY, akLeftCenter | akTop);
        pAnchors->AddAnchor(hDlg, IDC_REPARSE_DELETE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_FRAME, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_STATUS_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_STATUS, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_IOSTATUS_INFO_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_IOSTATUS_INFO, akLeft | akRight | akBottom);
    }

    // We need this in order to create symbolic link
    EnablePrivilege(_T("SeCreateSymbolicLinkPrivilege"));

    // Default number of characters for combo box's edit field is 46.
    // We have to increase it.
    hComboBox = GetDlgItem(hDlg, IDC_HARDLINK_LIST);
    ComboBox_LimitText(hComboBox, MAX_PATH);

    // Pre-fill the dialog
    SetDlgItemText(hDlg, IDC_SYMLINK, _T("\\??\\C:"));

    SetDlgItemText(hDlg, IDC_HARDLINK_LIST, _T("C:\\TestFile.bin"));
    SetDlgItemText(hDlg, IDC_NEW_HARDLINK, _T("C:\\TestFile_HardLink.bin"));

    SetDlgItemText(hDlg, IDC_REPARSE, _T("C:\\Windows_Reparse"));
    SetDlgItemText(hDlg, IDC_SUBST_NAME, _T("C:\\Windows"));
    SetDlgItemText(hDlg, IDC_PRINT_NAME, _T("C:\\Windows"));
    InitDialogControls(hDlg, MAKEINTRESOURCE(IDD_PAGE10_LINKS));
    hComboBox = GetDlgItem(hDlg, IDC_JUNCTION_TYPE);
    ComboBox_SetCurSel(hComboBox, 0);

    return TRUE;
}                                                                         

static int OnSetActive(HWND /* hDlg */)
{
    return FALSE;
}

static int OnKillActive(HWND /* hDlg */)
{
    return FALSE;
}

static int OnSymlinkCreate(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    OBJECT_ATTRIBUTES ObjAttr;
    UNICODE_STRING SymlinkName;
    UNICODE_STRING TargetName;
    NTSTATUS Status;
    TCHAR szSymlinkName[MAX_PATH];
    TCHAR szTargetName[MAX_PATH];

    // Get the name of the symbolic link
    GetDlgItemText(hDlg, IDC_SYMLINK, szSymlinkName, _maxchars(szSymlinkName));
    GetDlgItemText(hDlg, IDC_SYMLINK_TARGET, szTargetName, _maxchars(szTargetName));

    // Query the symbolic link
    InitializeObjectAttributes(&ObjAttr,
                               &SymlinkName,
                                OBJ_CASE_INSENSITIVE,
                                NULL,
                                NULL);
    RtlInitUnicodeString(&SymlinkName, szSymlinkName);
    RtlInitUnicodeString(&TargetName, szTargetName);

    // Create the symbolic link
    Status = NtCreateSymbolicLinkObject(&pData->hSymLink,
                                         SYMBOLIC_LINK_ALL_ACCESS,
                                        &ObjAttr,
                                        &TargetName);
    if(NT_SUCCESS(Status))
    {
        EnableDlgItems(hDlg, TRUE, IDC_SYMLINK_DELETE, 0);
    }

    SetResultInfo(hDlg, Status);
    return TRUE;
}

static int OnSymlinkQuery(HWND hDlg)
{
    OBJECT_ATTRIBUTES ObjAttr;
    UNICODE_STRING SymlinkName;
    UNICODE_STRING TargetName;
    NTSTATUS Status;
    HANDLE Handle;
    TCHAR szSymlinkName[MAX_PATH];
    ULONG Length = 0;

    // Get the name of the symbolic link
    GetDlgItemText(hDlg, IDC_SYMLINK, szSymlinkName, _maxchars(szSymlinkName));

    // Query the symbolic link
    InitializeObjectAttributes(&ObjAttr, &SymlinkName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&SymlinkName, szSymlinkName);
    Status = NtOpenSymbolicLinkObject(&Handle, SYMBOLIC_LINK_QUERY, &ObjAttr);
    if(NT_SUCCESS(Status))
    {
        TargetName.MaximumLength = 0x1000;
        TargetName.Length = 0;
        TargetName.Buffer = (PWSTR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, TargetName.MaximumLength + 2);
        if(TargetName.Buffer != NULL)
        {
            Status = NtQuerySymbolicLinkObject(Handle, &TargetName, &Length);
            if(NT_SUCCESS(Status))
            {
                SetDlgItemText(hDlg, IDC_SYMLINK_TARGET, TargetName.Buffer);
            }

            HeapFree(g_hHeap, 0, TargetName.Buffer);
        }
        else
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }

        NtClose(Handle);
    }

    SetResultInfo(hDlg, Status);
    return TRUE;
}

static int OnSymlinkDelete(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    if(IsHandleValid(pData->hSymLink))
        NtClose(pData->hSymLink);
    pData->hSymLink = NULL;

    EnableDlgItems(hDlg, FALSE, IDC_SYMLINK_DELETE, 0);
    return TRUE;
}

static void OnShowHardlinks(HWND hDlg)
{
    HWND hCombo = GetDlgItem(hDlg, IDC_HARDLINK_LIST);

    ComboBox_ShowDropdown(hCombo, TRUE);
}

static int OnHardlinkCreate(HWND hDlg)
{
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING FileName;
    NTSTATUS Status = STATUS_SUCCESS;
    LPTSTR szPlainName;
    HANDLE hDirectory = NULL;
    HANDLE hFile = NULL;
    TCHAR szHardlinkName[MAX_PATH];
    TCHAR szFileName[MAX_PATH];
    TCHAR szDirectory[MAX_PATH];
    BYTE LinkInfoBuff[0x500];

    // Get the name of the symbolic link
    GetDlgItemText(hDlg, IDC_HARDLINK_LIST, szFileName, _maxchars(szFileName));
    GetDlgItemText(hDlg, IDC_NEW_HARDLINK, szHardlinkName, _maxchars(szHardlinkName));

    // Get the plain file name of the hardlink
    szPlainName = _tcsrchr(szHardlinkName, _T('\\'));
    if(szPlainName != NULL)
    {
        // Extract directory name from the hardlink path
        _tcsncpy(szDirectory, szHardlinkName, (szPlainName - szHardlinkName + 1));
        szDirectory[szPlainName - szHardlinkName + 1] = 0;

        // Open the directory
        InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = FileNameToUnicodeString(&FileName, szDirectory);
        if(NT_SUCCESS(Status))
        {
            Status = NtOpenFile(&hDirectory,
                                 SYNCHRONIZE,
                                &ObjAttr,
                                &IoStatus,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 FILE_SYNCHRONOUS_IO_ALERT);
            FreeFileNameString(&FileName);
        }
    }

    if(NT_SUCCESS(Status))
    {
        // Open the file in order to set symlink
        InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = FileNameToUnicodeString(&FileName, szFileName);
        if(NT_SUCCESS(Status))
        {
            Status = NtOpenFile(&hFile, 
                                 FILE_WRITE_ATTRIBUTES,
                                &ObjAttr,
                                &IoStatus,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 0);
            FreeFileNameString(&FileName);
        }

        // Set the new hardlink to the file
        if(NT_SUCCESS(Status))
        {
            PFILE_LINK_INFORMATION pLinkInfo = (PFILE_LINK_INFORMATION)LinkInfoBuff;

            // Get the plain name of the directory
            szPlainName = GetPlainName(szHardlinkName);

            // Prepare the structure for creating hardlink
            pLinkInfo->ReplaceIfExists = FALSE;
            pLinkInfo->RootDirectory   = hDirectory;
            pLinkInfo->FileNameLength  = (ULONG)(_tcslen(szPlainName) * sizeof(TCHAR));
            wcscpy(pLinkInfo->FileName, szPlainName);

            // Create the hard link
            Status = NtSetInformationFile(hFile,
                                         &IoStatus,
                                          pLinkInfo,
                                          sizeof(FILE_LINK_INFORMATION) + pLinkInfo->FileNameLength,
                                          FileLinkInformation);
            NtClose(hFile);
        }
    }

    if(hDirectory != NULL)
        NtClose(hDirectory);
    SetResultInfo(hDlg, Status);
    return TRUE;
}


static int OnHardlinkQuery(HWND hDlg)
{
    PFILE_LINK_ENTRY_INFORMATION pLinkInfo = NULL;
    PFILE_LINKS_INFORMATION pLinksInfo = NULL;
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING FileName;
    NTSTATUS Status = STATUS_SUCCESS;
    LPTSTR szHardLinkName;
    HANDLE hFile = NULL;
    TCHAR szFileName[MAX_PATH];
    ULONG HardLinkCount = 0;
    ULONG Length = 0x100;
    HWND hCombo = GetDlgItem(hDlg, IDC_HARDLINK_LIST);

    // Get the name of the symbolic link
    GetDlgItemText(hDlg, IDC_HARDLINK_LIST, szFileName, _maxchars(szFileName));

    // Open the hardlink as if it was file
    InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = FileNameToUnicodeString(&FileName, szFileName);
    if(NT_SUCCESS(Status))
    {
        Status = NtOpenFile(&hFile, 
                             FILE_READ_ATTRIBUTES,
                            &ObjAttr,
                            &IoStatus,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             0);
        FreeFileNameString(&FileName);
    }

    // Query the file name
    if(NT_SUCCESS(Status))
    {
        for(;;)
        {
            // Allocate a chink of memory, that (we hope) will be enough
            pLinksInfo = (PFILE_LINKS_INFORMATION)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, Length);
            if(pLinksInfo == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            // Query all hardlinks
            Status = NtQueryInformationFile(hFile,
                                           &IoStatus,
                                            pLinksInfo,
                                            Length,
                                            FileHardLinkInformation);
            if(Status != STATUS_INFO_LENGTH_MISMATCH && Status != STATUS_BUFFER_OVERFLOW)
                break;

            // Free the buffer and double the length
            HeapFree(g_hHeap, 0, pLinksInfo);
            Length *= 2;
        }

        if(NT_SUCCESS(Status))
        {
            ComboBox_ResetContent(hCombo);
            if(pLinksInfo->EntriesReturned != 0)
            {
                pLinkInfo = &pLinksInfo->Entry;
                for(;;)
                {
                    szHardLinkName = GetFullHardLinkName(pLinkInfo, szFileName);
                    if(szHardLinkName != NULL)
                    {
                        // First hardlink will also be added to the combo box main field
                        if(HardLinkCount == 0)
                            SetWindowText(hCombo, szHardLinkName);

                        // Add the hardlink to the list
                        ComboBox_InsertString(hCombo, -1, szHardLinkName);
                        HeapFree(g_hHeap, 0, szHardLinkName);
                        HardLinkCount++;
                    }

                    if(pLinkInfo->NextEntryOffset == 0)
                        break;
                    pLinkInfo = (PFILE_LINK_ENTRY_INFORMATION)((LPBYTE)pLinkInfo + pLinkInfo->NextEntryOffset);
                }
            }
        }
        
        // Free the buffer and close file handle
        if(pLinksInfo != NULL)
            HeapFree(g_hHeap, 0, pLinksInfo);
        NtClose(hFile);
    }

    // Open the drop list to show all links
    if(HardLinkCount != 0)
        PostMessage(hDlg, WM_SHOW_HARDLINKS, 0, 0);
    SetResultInfo(hDlg, Status);
    return TRUE;
}

static int OnHardlinkDelete(HWND hDlg)
{
    OBJECT_ATTRIBUTES ObjAttr;
    UNICODE_STRING FileName;
    NTSTATUS Status = STATUS_SUCCESS;
    TCHAR szHardlinkName[MAX_PATH];

    // Get the name of the symbolic link
    GetDlgItemText(hDlg, IDC_HARDLINK_LIST, szHardlinkName, _maxchars(szHardlinkName));

    // Open the symlink and delete it
    InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = FileNameToUnicodeString(&FileName, szHardlinkName);
    if(NT_SUCCESS(Status))
    {
        Status = NtDeleteFile(&ObjAttr);
        FreeFileNameString(&FileName);
    }

    SetResultInfo(hDlg, Status);
    return TRUE;
}

static int OnReparseCreate(HWND hDlg)
{
    PREPARSE_DATA_BUFFER pReparseData = NULL;
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING FileName;
    NTSTATUS Status;
    HANDLE hReparse = NULL;
    TCHAR szReparseName[MAX_PATH];
    TCHAR szTargetName[MAX_PATH];
    ULONG CreateOptions = FILE_SYNCHRONOUS_IO_ALERT | FILE_OPEN_REPARSE_POINT;
    ULONG FileAttributes;
    ULONG Length;

    // Get the name of the reparse point
    GetDlgItemText(hDlg, IDC_REPARSE, szReparseName, _maxchars(szReparseName));
    GetDlgItemText(hDlg, IDC_REPARSE_TARGET, szTargetName, _maxchars(szTargetName));

    // Verify if the reparse point dir/file exists
    FileAttributes = GetFileAttributes(szTargetName);
    if(FileAttributes != INVALID_FILE_ATTRIBUTES && (FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        CreateOptions |= FILE_DIRECTORY_FILE;

    // Open the reparse point
    InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = FileNameToUnicodeString(&FileName, szReparseName);
    if(NT_SUCCESS(Status))
    {
        Status = NtCreateFile(&hReparse,
                               GENERIC_WRITE | SYNCHRONIZE,
                              &ObjAttr,
                              &IoStatus,
                               NULL,
                               0,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               FILE_OPEN_IF,
                               CreateOptions,
                               NULL,
                               0);
        FreeFileNameString(&FileName);
    }

    // Set the reparse point
    if(NT_SUCCESS(Status))
    {
        pReparseData = Dlg2ReparseData(hDlg, &Length);
        if(pReparseData != NULL)
        {
            // Fire the IOCTL
            Status = NtFsControlFile(hReparse,
                                     NULL,
                                     NULL,
                                     NULL,
                                    &IoStatus,
                                     FSCTL_SET_REPARSE_POINT,
                                     pReparseData,
                                     Length,
                                     NULL,
                                     0);

            HeapFree(g_hHeap, 0, pReparseData);
        }
        else
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }

        NtClose(hReparse);
    }

    SetResultInfo(hDlg, Status);
    return TRUE;
}

static int OnReparseQuery(HWND hDlg)
{
    PREPARSE_DATA_BUFFER pReparseData = NULL;
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING FileName;
    NTSTATUS Status;
    HANDLE hFile = NULL;
    TCHAR szReparseName[MAX_PATH];
    ULONG Length = 0x1000;

    // Get the name of the reparse point
    GetDlgItemText(hDlg, IDC_REPARSE, szReparseName, _maxchars(szReparseName));

    // Open the reparse point
    InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = FileNameToUnicodeString(&FileName, szReparseName);
    if(NT_SUCCESS(Status))
    {
        Status = NtOpenFile(&hFile,
                             FILE_READ_ATTRIBUTES,
                            &ObjAttr,
                            &IoStatus,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             FILE_OPEN_REPARSE_POINT);
        FreeFileNameString(&FileName);
    }

    if(NT_SUCCESS(Status))
    {
        // Allocate buffer for the reparse data
        pReparseData = (PREPARSE_DATA_BUFFER)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, Length);
        if(pReparseData != NULL)
        {
            // Query the reparse point 
            Status = NtFsControlFile(hFile, 
                                     NULL,
                                     NULL,
                                     NULL,
                                    &IoStatus,
                                     FSCTL_GET_REPARSE_POINT,
                                     NULL,
                                     0,
                                     pReparseData,
                                     Length);
            if(NT_SUCCESS(Status))
            {
                ReparseData2Dlg(hDlg, pReparseData);
            }
            HeapFree(g_hHeap, 0, pReparseData);
        }
        else
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
        NtClose(hFile);
    }

    SetResultInfo(hDlg, Status);
    return TRUE;
}

static int OnReparseDelete(HWND hDlg)
{
    PREPARSE_DATA_BUFFER pReparseData = NULL;
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING FileName;
    NTSTATUS Status;
    HANDLE hFile = NULL;
    TCHAR szReparseName[MAX_PATH];
    ULONG Length = 0x1000;

    // Get the name of the reparse point
    GetDlgItemText(hDlg, IDC_REPARSE, szReparseName, _maxchars(szReparseName));

    // Open the reparse point
    InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = FileNameToUnicodeString(&FileName, szReparseName);
    if(NT_SUCCESS(Status))
    {
        Status = NtOpenFile(&hFile,
                             FILE_WRITE_DATA,
                            &ObjAttr,
                            &IoStatus,
                             0,
                             FILE_OPEN_REPARSE_POINT);
        FreeFileNameString(&FileName);
    }

    if(NT_SUCCESS(Status))
    {
        // Allocate buffer for the reparse data
        pReparseData = (PREPARSE_DATA_BUFFER)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, Length);
        if(pReparseData != NULL)
        {
            // Query the reparse point 
            Status = NtFsControlFile(hFile, 
                                     NULL,
                                     NULL,
                                     NULL,
                                    &IoStatus,
                                     FSCTL_GET_REPARSE_POINT,
                                     NULL,
                                     0,
                                     pReparseData,
                                     Length);
            // ... and delete it
            if(NT_SUCCESS(Status))
            {
                pReparseData->ReparseDataLength = 0;
                Status = NtFsControlFile(hFile,
                                         NULL,
                                         NULL,
                                         NULL,
                                        &IoStatus,
                                         FSCTL_DELETE_REPARSE_POINT,
                                         pReparseData,
                                         REPARSE_GUID_DATA_BUFFER_HEADER_SIZE,
                                         NULL,
                                         0);
            }
            HeapFree(g_hHeap, 0, pReparseData);
        }
        else
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
        NtClose(hFile);
    }

    SetResultInfo(hDlg, Status);
    return TRUE;
}

static int OnSubstNameKillFocus(HWND hDlg)
{
    TCHAR szWindowText[MAX_PATH];

    GetDlgItemText(hDlg, IDC_SUBST_NAME, szWindowText, _maxchars(szWindowText));
    SetDlgItemText(hDlg, IDC_PRINT_NAME, szWindowText);
    return TRUE;
}

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    if(nNotify == BN_CLICKED)
    {
        switch(nIDCtrl)
        {
            case IDC_SYMLINK_CREATE:
                return OnSymlinkCreate(hDlg);

            case IDC_SYMLINK_QUERY:
                return OnSymlinkQuery(hDlg);

            case IDC_SYMLINK_DELETE:
                return OnSymlinkDelete(hDlg);

            case IDC_HARDLINK_CREATE:
                return OnHardlinkCreate(hDlg);

            case IDC_HARDLINK_QUERY:
                return OnHardlinkQuery(hDlg);

            case IDC_HARDLINK_DELETE:
                return OnHardlinkDelete(hDlg);

            case IDC_REPARSE_CREATE:
                return OnReparseCreate(hDlg);

            case IDC_REPARSE_QUERY:
                return OnReparseQuery(hDlg);

            case IDC_REPARSE_DELETE:
                return OnReparseDelete(hDlg);
        }
    }

    if(nNotify == EN_KILLFOCUS && nIDCtrl == IDC_SUBST_NAME)
    {
        OnSubstNameKillFocus(hDlg);
    }

    return FALSE;
}

static int OnNotify(HWND hDlg, NMHDR * pNMHDR)
{
    switch(pNMHDR->code)
    {
        case PSN_SETACTIVE:
            return OnSetActive(hDlg);

        case PSN_KILLACTIVE:
            return OnKillActive(hDlg);
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// Public functions

INT_PTR CALLBACK PageProc10(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
        case WM_INITDIALOG:
            return OnInitDialog(hDlg, lParam);

        case WM_SIZE:
            if(pAnchors != NULL)
                pAnchors->OnSize();
            return FALSE;

        case WM_SHOW_HARDLINKS:
            OnShowHardlinks(hDlg);
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
