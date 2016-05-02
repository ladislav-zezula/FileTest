/*****************************************************************************/
/* WinMain.cpp                            Copyright (c) Ladislav Zezula 2003 */
/*---------------------------------------------------------------------------*/
/* A file that simulates access on a file                                    */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 14.07.03  1.00  Lad  The first version of WinMain.cpp                     */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

#pragma comment(lib, "Comctl32.lib")

//-----------------------------------------------------------------------------
// Local defines

#define INITIAL_FILEINFO_BUFFER_SIZE 0x10000

//-----------------------------------------------------------------------------
// Global variables

HINSTANCE g_hInst;
TToolTip g_Tooltip;
HANDLE g_hHeap;
DWORD g_dwWinVer;
TCHAR g_szInitialDirectory[MAX_PATH];

HMENU g_hMenu_NtCreate = NULL;          // IDR_NTCREATE_MENU
HMENU g_hMenu_FillData = NULL;          // IDR_FILL_DATA_MENU
HMENU g_hMenu_DelDirectory = NULL;      // IDR_DELETE_DIRECTORY_MENU
HMENU g_hMenu_ReqOplock = NULL;         // IDR_REQUEST_OPLOCK_MENU
HMENU g_hMenu_AclType = NULL;           // IDR_ACL_TYPE_MENU
HMENU g_hMenu_Ace = NULL;               // IDR_ACE_MENU

//-----------------------------------------------------------------------------
// Local functions

inline bool IsCommandSwitch(LPCTSTR szArg)
{
    return (szArg[0] == _T('/') || szArg[0] == _T('-'));
}

static void SetTokenObjectIntegrityLevel(DWORD dwIntegrityLevel)
{
    SID_IDENTIFIER_AUTHORITY Sia = SECURITY_MANDATORY_LABEL_AUTHORITY;
    SECURITY_DESCRIPTOR sd;
    HANDLE hToken;
    DWORD dwLength;
    PACL pAcl;
    PSID pSid;

    // Do nothing on OSes where mandatory ACEs are not supported
    if(pfnAddMandatoryAce == NULL)
        return;

    // Initialize blank security descriptor
    if(!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
        return;

    // Allocate mandatory label SID
    if(!AllocateAndInitializeSid(&Sia, 1, dwIntegrityLevel, 0, 0, 0, 0, 0, 0, 0, &pSid))
        return;

    // Open current token
    if(!OpenThreadToken(GetCurrentThread(), WRITE_OWNER, TRUE, &hToken))
    {
        if(GetLastError() == ERROR_NO_TOKEN)
            OpenProcessToken(GetCurrentProcess(), WRITE_OWNER, &hToken);
    }
    
    // If succeeded, set the integrity level
    if(hToken != NULL)
    {
        // Create ACL
        dwLength = sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) - sizeof(DWORD) + GetLengthSid(pSid);
        pAcl = (PACL)HeapAlloc(g_hHeap, 0, dwLength);
        if(pAcl != NULL)
        {
            if(InitializeAcl(pAcl, dwLength, ACL_REVISION))
            {
                if(pfnAddMandatoryAce(pAcl, ACL_REVISION, 0, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, pSid))
                {
                    NtSetSecurityObject(hToken, LABEL_SECURITY_INFORMATION, &sd);
                }
            }

            HeapFree(g_hHeap, 0, pAcl);
        }
    }

    FreeSid(pSid);
}

#ifdef _DEBUG
//static TFlagInfo ReparseTags[] =
//{
//    FLAG_INFO_ENTRY(IO_REPARSE_TAG_MOUNT_POINT),
//    FLAG_INFO_ENTRY(IO_REPARSE_TAG_SYMLINK),
//    FLAG_INFO_ENTRY(IO_REPARSE_TAG_WIM),
//    FLAG_INFO_END
//};

static void DebugCode_TEST()
{
    //DWORD dwValue = 0x123;
    //
    //ValuesDialog(NULL, &dwValue, IDS_CHOOSE_REPARSE_TAG, ReparseTags);
    //ExitProcess(dwValue);

    //{
    //    OBJECT_ATTRIBUTES ObjAttr;
    //    IO_STATUS_BLOCK IoStatus;
    //    UNICODE_STRING FileName;

    //    EnablePrivilege(SE_SECURITY_NAME);
    //    EnablePrivilege(SE_TAKE_OWNERSHIP_NAME);
    //    InitializeObjectAttributes(&ObjAttr, &FileName, 0, NULL, NULL);
    //    RtlInitUnicodeString(&FileName, L"\\??\\y:\\WINDOWS\\$NtUninstallKB25256$");
    //    NtCreateFile(&pData->hFile, READ_CONTROL, &ObjAttr, &IoStatus, NULL, 0, 0x07, FILE_OPEN, FILE_OPEN_REPARSE_POINT | FILE_DIRECTORY_FILE, NULL, 0);
    //}
}
#endif

//-----------------------------------------------------------------------------
// WinMain

int WINAPI _tWinMain(HINSTANCE hInstance, HINSTANCE, LPTSTR, int)
{
    TFileTestData * pData;
    DWORD dwDesiredAccess = GENERIC_READ;
    DWORD dwShareAccess = FILE_SHARE_READ;
    DWORD dwCreateOptions = 0;
    DWORD dwCopyFileFlags = 0;
    DWORD dwMoveFileFlags = 0;
    bool bAsynchronousOpen = false;
    int nFileNameIndex = 0;

    // Save the instance
    g_hInst = hInstance;
    g_hHeap = GetProcessHeap();
    InitCommonControls();

    // Get the Windows version
    g_dwWinVer = GetWindowsVersion();

    // Allocate and fill our working structure with command line parameters
    pData = (TFileTestData *)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, sizeof(TFileTestData));

    // Parse command line arguments
    for(int i = 1; i < __argc; i++)
    {
        // If the argument a file name?
        if(!IsCommandSwitch(__targv[i]))
        {
            switch(nFileNameIndex)
            {
                case 0: // The first file name argument
                    StringCchCopy(pData->szFileName1, _countof(pData->szFileName1), __targv[i]);
                    nFileNameIndex++;
                    break;

                case 1: // The second file name argument
                    StringCchCopy(pData->szFileName2, _countof(pData->szFileName2), __targv[i]);
                    nFileNameIndex++;
                    break;

                case 2: // The directory file name argument
                    StringCchCopy(pData->szDirName, _countof(pData->szFileName2), __targv[i]);
                    nFileNameIndex++;
                    break;
            }
        }
        else
        {
            LPCTSTR szArg = __targv[i] + 1;

            // Check for default read+write access
            if(!_tcsnicmp(szArg, _T("DesiredAccess:"), 14))
                Text2Hex32(szArg+14, &dwDesiredAccess);
            
            // Check for default share read+write
            if(!_tcsnicmp(szArg, _T("ShareAccess:"), 12))
                Text2Hex32(szArg+12, &dwShareAccess);

            // Check for changed create options
            if(!_tcsnicmp(szArg, _T("CreateOptions:"), 14))
                Text2Hex32(szArg+14, &dwCreateOptions);

            if(!_tcsnicmp(szArg, _T("CopyFileFlags:"), 14))
                Text2Hex32(szArg+14, &dwCopyFileFlags);

            if(!_tcsnicmp(szArg, _T("MoveFileFlags:"), 14))
                Text2Hex32(szArg+14, &dwMoveFileFlags);

            // Check for asynchronous open
            if(!_tcsicmp(szArg, _T("AsyncOpen")))
                bAsynchronousOpen = true;
        }
    }

    // Set default file name
    if(pData->szFileName1[0] == 0)
        StringCchCopy(pData->szFileName1, _countof(pData->szFileName1), _T("C:\\TestFile.bin"));

    //
    // DEVELOPMENT CODE: Build the NT status table from the NTSTATUS.h
    //

//  BuildNtStatusTableFromNTSTATUS_H();
//  VerifyNtStatusTable();

    //
    // Resolve the dynamic loaded APIs
    //

    ResolveDynamicLoadedAPIs();

    //
    // On Vista or newer, set the required integrity level of our token object
    // to lowest possible value. This will allow us to open our token even if the user
    // lowers the integrity level.
    //
    
    SetTokenObjectIntegrityLevel(SECURITY_MANDATORY_UNTRUSTED_RID);

    //
    // Save the application initial directory
    //

    GetCurrentDirectory(_maxchars(g_szInitialDirectory), g_szInitialDirectory);

    //
    // Register the data editor window
    //

    RegisterDataEditor(hInstance);

    //
    // To make handles obtained by NtCreateFile usable for calling ReadFile and WriteFile,
    // we have to set the FILE_SYNCHRONOUS_IO_NONALERT into CreateOptions
    // and SYNCHRONIZE into DesiredAccess.
    //

    // Pre-load menus so they don't generate any FS requests when loaded
    g_hMenu_NtCreate     = LoadMenu(g_hInst, MAKEINTRESOURCE(IDR_NTCREATE_MENU));
    g_hMenu_FillData     = LoadMenu(g_hInst, MAKEINTRESOURCE(IDR_FILL_DATA_MENU));
    g_hMenu_DelDirectory = LoadMenu(g_hInst, MAKEINTRESOURCE(IDR_DELETE_DIRECTORY_MENU));
    g_hMenu_ReqOplock    = LoadMenu(g_hInst, MAKEINTRESOURCE(IDR_REQUEST_OPLOCK_MENU));
    g_hMenu_AclType      = LoadMenu(g_hInst, MAKEINTRESOURCE(IDR_ACL_TYPE_MENU));
    g_hMenu_Ace          = LoadMenu(g_hInst, MAKEINTRESOURCE(IDR_ACE_MENU));

    // Allocate default size for the FileInfo.
    pData->pbNtInfoBuff = (LPBYTE)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, INITIAL_FILEINFO_BUFFER_SIZE);
    pData->cbNtInfoBuff = INITIAL_FILEINFO_BUFFER_SIZE;

    // Set default values for opening relative file by NtOpenFile
    pData->dwDesiredAccessRF     = FILE_READ_DATA;
    pData->dwOpenOptionsRF       = 0;
    pData->dwShareAccessRF       = FILE_SHARE_READ | FILE_SHARE_WRITE;

    // Set default values for CreateFile and NtCreateFile
    pData->dwCreateDisposition1  = OPEN_ALWAYS;
    pData->dwCreateDisposition2  = FILE_OPEN_IF;
    pData->dwDesiredAccess       = dwDesiredAccess;
    pData->dwFileAttributes      = FILE_ATTRIBUTE_NORMAL;
    pData->dwShareAccess         = dwShareAccess;
    pData->dwCreateOptions       = dwCreateOptions;
    pData->dwObjAttrFlags        = OBJ_CASE_INSENSITIVE;
    pData->dwMoveFileFlags       = MOVEFILE_COPY_ALLOWED;
    pData->dwOplockLevel         = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE;
    pData->dwCopyFileFlags       = dwCopyFileFlags;
    pData->dwMoveFileFlags       = dwMoveFileFlags;

    // Modify for synchronous open, if required
    if(bAsynchronousOpen == false)
    {
        pData->dwCreateOptions |= FILE_SYNCHRONOUS_IO_NONALERT;
        pData->dwDesiredAccess |= SYNCHRONIZE;
    }

    // Set default values for NtCreateSection/NtOpenSection
    pData->dwSectDesiredAccess   = SECTION_MAP_READ;
    pData->dwSectPageProtection  = PAGE_READONLY;
    pData->dwSectAllocAttributes = SEC_COMMIT;
    pData->dwSectWin32Protect    = PAGE_READONLY;

#ifdef _DEBUG
    DebugCode_TEST();    
#endif

    // Call the dialog
    FileTestDialog(NULL, pData);

    // Cleanup the TFileTestData structure and exit
    if(pData->pFileEa != NULL)
        delete [] pData->pFileEa;
    if(pData->pbFileData != NULL)
        VirtualFree(pData->pbFileData, pData->cbFileDataMax, MEM_RELEASE);
    if(pData->pbNtInfoBuff != NULL)
        HeapFree(g_hHeap, 0, pData->pbNtInfoBuff);
    if(pData->ReparseData != NULL)
        HeapFree(g_hHeap, 0, pData->ReparseData);
    HeapFree(g_hHeap, 0, pData);

    UnloadDynamicLoadedAPIs();
    return 0;
}
