/*****************************************************************************/
/* TestFile.h                             Copyright (c) Ladislav Zezula 2003 */
/*---------------------------------------------------------------------------*/
/* Definitions for file access testing application                           */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 14.07.03  1.00  Lad  The first version of TestFile.h                      */
/*****************************************************************************/

#ifndef __TESTFILE_H__
#define __TESTFILE_H__

#ifndef UNICODE
#define UNICODE
#define _UNICODE
#endif

#include <tchar.h>
#include <stdio.h>

#define WIN32_NO_STATUS 
#include <windows.h>
#include <windowsx.h>
#include <ShlObj.h>
#include <winioctl.h>
#include <strsafe.h>

#undef WIN32_NO_STATUS 
#include "ntstatus.h"
#include "ntdll.h"
#include "Utils.h"
#include "TAnchors.h"
#include "TToolTip.h"
#include "TDataEditor.h"
#include "WinSDK.h"

//-----------------------------------------------------------------------------
// Defines

#define IsHandleValid(h)   (h != NULL && h != INVALID_HANDLE_VALUE)
#define IsHandleInvalid(h) (h == NULL || h == INVALID_HANDLE_VALUE)

#define ALIGN_INT32(Address) ((ULONG) ((Address + 3) & ~3))
#define ALIGN_INT64(Address) ((ULONG) ((Address + 7) & ~7))
#define ALIGN_EX(x, a)       (((x) + (a)-1) & ~((a)-1))

#define MAX_NT_PATH                 32767           // Maximum path name length in NT is 32767
#define MAX_FILEID_PATH             0x24            // Maximum path name length of File ID string (C:\################ or C:\################################)

#define OSVER_WINDOWS_NT4           0x0400
#define OSVER_WINDOWS_2000          0x0500
#define OSVER_WINDOWS_XP            0x0501
#define OSVER_WINDOWS_2003          0x0502
#define OSVER_WINDOWS_VISTA         0x0600
#define OSVER_WINDOWS_SEVEN         0x0601
#define OSVER_WINDOWS_8             0x0602
#define OSVER_WINDOWS_8_1           0x0603          // Make sure you have proper manifest to see this
#define OSVER_WINDOWS_10            0x0A00          // Make sure you have proper manifest to see this

#define WM_SHOW_HARDLINKS           (WM_USER + 0x1000)
#define WM_TIMER_BLINK              (WM_USER + 0x1001)
#define WM_TIMER_TOOLTIP            (WM_USER + 0x1002)
#define WM_TIMER_CHECK_MOUSE        (WM_USER + 0x1003)
#define WM_APC                      (WM_USER + 0x1004)
#define WM_START_WORK               (WM_USER + 0x1005)
#define WM_WORK_COMPLETE            (WM_USER + 0x1006)
#define WM_UPDATE_VIEW              (WM_USER + 0x1007)

#define STATUS_INVALID_DATA_FORMAT  0xC1110001
#define STATUS_CANNOT_EDIT_THIS     0xC1110002
#define STATUS_FILE_ID_CONVERSION   0xC1110003
#define STATUS_COPIED_TO_CLIPBOARD  0xC1110004

#define SEVERITY_PENDING            2

#define APC_TYPE_NONE               0
#define APC_TYPE_READ_WRITE         1
#define APC_TYPE_FSCTL              2

#define COPY_FILE_USE_READ_WRITE    0x01000000      // Manual file copy - use ReadFile + WriteFile
#define COPY_FILE_SKIP_IO_ERRORS    0x02000000      // On I/O errors, replace loaded data with zeros if failed
#define COPY_FILE_LOG_IO_ERRORS     0x04000000      // Log the I/O errors to FileTest.log
#define COPY_FILE_PER_SECTOR        0x08000000      // Copy sector-per-sector (512 bytes)

#ifndef SECTOR_SIZE
#define SECTOR_SIZE                 0x200           // Sector size for disk drives
#endif

//-----------------------------------------------------------------------------
// Structures

#define FLAG_SEPARATOR                  0xFFFFFFFF
#define FLAG_INFO_CTRLID(flag)          {{(LPCTSTR)IDC_##flag}, flag, flag}
#define FLAG_INFO_ENTRY(flag)           {{_T(#flag)}, flag, flag}
#define FLAG_INFO_MASK(mask, flag)      {{(LPCTSTR)IDC_##flag}, mask, flag}
#define FLAG_INFO_SEPARATOR()           {{_T("")}, FLAG_SEPARATOR, FLAG_SEPARATOR}
#define FLAG_INFO_END                   {{NULL}, 0, 0}
#define IS_FLAG_SET(FlagInfo, flag)     ((flag & FlagInfo->dwMask) == FlagInfo->dwValue)

struct TFlagInfo
{
    union
    {
        LPCTSTR szFlagText;                 // Text of the checkbox/radio button
        UINT    nIDCtrl;                    // ID of the checkbox/radio button
    };

    DWORD   dwMask;                         // Item is checked when (dwFlags & dwMask) == dwValue
    DWORD   dwValue;                        // - || -
};

// Common structure for APCs. Keep its size 8-byte aligned
struct TApcEntry
{
    // Common APC entry members
    IO_STATUS_BLOCK IoStatus;               // IO_STATUS_BLOCK for the entry
    OVERLAPPED Overlapped;                  // Overlapped structure for the Win32 APIs
    LIST_ENTRY Entry;                       // Links to other APC entries
    HANDLE hEvent;                          // When signalled, triggers this APC
    HWND hWndPage;                          // Page that initiated the APC
    UINT ApcType;                           // Common member for determining type of the APC
    UINT UserParam;                         // Any user-defined 32-bit value (e.g. FSCTL code)
};

// Extended structure for read/write APCs
struct TApcReadWrite : public TApcEntry
{
    LARGE_INTEGER ByteOffset;               // Starting offset of the operation
    bool bIncrementPosition;                // If true, the file position will be incremented when complete
    bool bNativeCall;                       // If true, the native function has been called (NtReadFile / NtWriteFile)
    bool bUpdateData;                       // If true, data need to be updated after operation is complete
};

// Structure used by main dialog to hold all its data
struct TWindowData
{
    HWND hDlg;                              // Handle to ourself
    HWND hWndPage;                          // HWND of the current page

    CRITICAL_SECTION ApcLock;               // A critical section protecting APC data
    LIST_ENTRY ApcList;                     // List of queued APC calls
    HANDLE hApcThread;                      // Handle to a thread sending messages
    HANDLE hAlertEvent;                     // Handle to a watcher event
    DWORD dwAlertReason;                    // A reason why the watcher was stopped
    int nApcCount;                          // Number of queued APCs

    int  nTabInnerLeft;                     // Inner space tab control <==> dialog client edge
    int  nTabInnerTop;
    int  nTabInnerRight;
    int  nTabInnerBottom;
    int  nButtonInnerRight;                 // Button distance from right-bottom corner
    int  nButtonInnerBottom;

    UINT_PTR CheckMouseTimer;               // Timer for checking mouse
    RECT ScreenRect;                        // Size of the screen
    RECT DialogRect;                        // Size of the dialog
    bool bInitialResizeDone;                // If TRUE, the first resize has already completed
    bool bDialogBiggerThanScreen;           // true = the main dialog is bigger than the screen

    HANDLE hThread;                         // Thread that moves the dialog
    int nStartX;                            // The dialog's starting X position
    int nStartY;                            // The dialog's starting Y position
    int nEndY;                              // The dialog's final Y position
    int nAddY;                              // The dialog's movement direction
};

struct TFileTestData : public TWindowData
{
    TCHAR         szDirName[MAX_NT_PATH];   // Directory name
    TCHAR         szFileName1[MAX_NT_PATH]; // First file name
    TCHAR         szFileName2[MAX_NT_PATH]; // Second file name
    TCHAR         szTemplate[MAX_NT_PATH];  // Template file for CreateFileW
    TCHAR         szSectionName[MAX_NT_PATH];  // Section name for NtCreateSection
    HANDLE        hTransaction;             // Handle to the current transaction (NULL if none)
    HANDLE        hDirectory;               // Handle to the open directory
    HANDLE        hFile;                    // Handle to the open file
    HANDLE        hSection;                 // Section handle
    HANDLE        hSymLink;                 // Handle to the symbolic link
    PFILE_FULL_EA_INFORMATION pFileEa;      // Extended attributes for NtCreate
    ACCESS_MASK   dwDesiredAccess;
    LONGLONG      AllocationSize;
    
    ULONG         dwDesiredAccessRF;        // Desired Access for the relative file
    ULONG         dwOpenOptionsRF;          // Create Options for the relative file
    ULONG         dwShareAccessRF;          // Share Access for the relative file

    ULONG         dwObjAttrFlags;           // ObjAttr.Attributes
    ULONG         dwFileAttributes;
    ULONG         dwShareAccess;
    ULONG         dwCreateDisposition1;     // For CreateFile
    ULONG         dwCreateDisposition2;     // For NtCreateFile
    ULONG         dwCreateOptions;
    ULONG         dwEaSize;                 // Length of data in pEaFile

    LARGE_INTEGER SectionOffset;            // Section Offset for NtCreateSection
    LARGE_INTEGER MaximumSize;              // Maximum size of section for NtCreateSection
    PVOID         pvSectionMappedView;      // BaseAddress
    ULONG         dwSectDesiredAccess;      // DesiredAccess
    ULONG         dwSectPageProtection;     // PageProtection
    ULONG         dwSectAllocAttributes;    // AllocationAttributes
    size_t        cbSectCommitSize;
    size_t        cbSectViewSize;
    ULONG         dwSectAllocType;          // AllocationType for NtMapViewOfSection
    ULONG         dwSectWin32Protect;       // Win32Protect for NtMapViewOfSection

    ULONG         dwCopyFileFlags;          // For file copying
    ULONG         dwMoveFileFlags;          // For MoveFileEx
    ULONG         dwOplockLevel;            // For requesting Win7 oplock
    BOOL          bTransactionActive;
    BOOL          bUseTransaction;
    BOOL          bSectionViewMapped;
    
    UINT_PTR      BlinkTimer;               // If nonzero, this is ID of the blink timer
    HWND          hWndBlink;                // It not NULL, this is the handle of blink window
    BOOL          bEnableResizing;          // TRUE if the dialog is allowed to be resized

    LPBYTE        pbFileData;               // Buffer for ReadFile/WriteFile
    ULONG         cbFileData;               // Size of pbNtInfoBuff in bytes
    ULONG         cbFileDataMax;            // Size of the buffer pointed by pbFileData
    UINT          FillPattern;              // Fill data pattern type

    LPBYTE        pbNtInfoBuff;             // Buffer for NtQueryInformationFile/NtSetInformationFile
    ULONG         cbNtInfoBuff;             // Size of pbNtInfoBuff in bytes

    PREPARSE_DATA_BUFFER ReparseData;       // Buffer for reparse points
    ULONG         cbReparseData;            // Size of pbReparseBuffer in bytes
};

#define GetDialogData(hDlg) ((TFileTestData *)GetWindowLongPtr(hDlg, DWLP_USER))
#define SetDialogData(hDlg,pData) SetWindowLongPtr(hDlg, DWLP_USER, (LONG_PTR)pData)

//-----------------------------------------------------------------------------
// Data types and strctures for NtQueryInformationFile and NtSetInformationFile

#define TYPE_NONE             0
#define TYPE_BOOLEAN          1
#define TYPE_UINT8            2
#define TYPE_UINT16           3
#define TYPE_UINT32           4
#define TYPE_UINT64           5
#define TYPE_STRING           6
#define TYPE_WSTRING          7
#define TYPE_ARRAY8_FIXED     8             // Array of bytes, fixed length
#define TYPE_ARRAY8_VARIABLE  9             // Array of bytes, variable length
#define TYPE_HANDLE          10             // Handle
#define TYPE_POINTER         11             // pointer
#define TYPE_FILETIME        12             // FILETIME
#define TYPE_CNAME_L8B       13             // Array of CHARs, var length, length is 8-bit value in bytes
#define TYPE_WNAME_L32B      14             // Array of WCHARs, var length, length is 32-bit value in bytes
#define TYPE_WNAME_L32W      15             // Array of WCHARs, var length, length is 32-bit value in WCHARs
#define TYPE_VNAME_FBDI      16             // ShortName in FILE_BOTH_DIRECTORY_INFORMATION
#define TYPE_VNAME_FIBD      17             // ShortName in FILE_ID_BOTH_DIRECTORY_INFORMATION
#define TYPE_FILEID64        18             // 8-byte file ID
#define TYPE_DIR_HANDLE      19             // Directory handle for certain file operations
#define TYPE_STRUCT         100             // Sub-structure, nMemberSize must be sizeof(structure) !!!
#define TYPE_CHAINED_STRUCT 101             // Chain of structures first 32-bit number is "NextEntryOffset"
#define TYPE_ARRAY_HANDLE   102             // Array of handles, variable length, length is 32-bit number
#define TYPE_PADDING       1000             // Padding for the next member. The "nMemberSize" contains alignment

#define MEMBER_SIZE_SPECIAL (UINT)-1        // For variable length data items

struct TStructMember
{
    LPCTSTR szMemberName;                   // Name of the member
    UINT    nDataType;                      // Data type
    UINT    nMemberSize;                    // Size (in bytes) of the structure member
    PBYTE   pbStructPtr;                    // Pointer to the begin of the structure
    union
    {
        TStructMember * pSubItems;          // Subitems, if this is structure too
        PBYTE pbDataPtr;                    // If this describes data item, pointer to binary data
    };
};

struct TInfoData
{
    int                    InfoClass;       // Value for NtSetInformationFile
    LPCTSTR                szInfoClass;     // Text for the value
    LPCTSTR                szStructName;    // Name of the input/output structure 
    TStructMember        * pStructMembers;  // Description of the data structure
                                            // (NULL = not implemented)
    BOOL                   bIsChain;        // if TRUE, it is a chain of structures
                                            // (with ULONG NextEntryOffset as first member)
    BOOL                   bIsEditable;     // If TRUE, the structu is editable
                                            // and able to send to NtSetInfo
};

#define FILE_INFO_READONLY(classname, structname, ischain)   \
    {(int)classname, _T(#classname), _T(#structname), classname##Members, ischain, FALSE}

#define FILE_INFO_EDITABLE(classname, structname, ischain)   \
    {(int)classname, _T(#classname), _T(#structname), classname##Members, ischain, TRUE}

#define FILE_INFO_NOTIMPL(classname, structname, ischain)   \
    {(int)classname, _T(#classname), NULL, NULL, FALSE, FALSE}


//-----------------------------------------------------------------------------
// Prototypes for read/write APIs

typedef BOOL (WINAPI * READWRITE)(
    IN HANDLE hFile,
    IN LPVOID lpBuffer,
    IN DWORD nNumberOfBytesToRead,
    OUT LPDWORD lpNumberOfBytesRead,
    IN LPOVERLAPPED lpOverlapped
    );

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

//-----------------------------------------------------------------------------
// Prototypes for transaction APIs

typedef HANDLE (WINAPI * CREATETRANSACTION)(
    LPSECURITY_ATTRIBUTES lpTransactionAttributes,
    LPGUID TransactionGuid,
    DWORD CreateOptions,
    DWORD IsolationLevel,
    DWORD IsolationFlags,
    DWORD dwMilliseconds,
    LPWSTR Description
    );

typedef BOOL (WINAPI * SETCURRENTTRANSACTION)(
    HANDLE hTransaction
    );
    
typedef BOOL (WINAPI * COMMITTRANSACTION)(
    HANDLE hTransaction
    );

typedef BOOL (WINAPI * ROLLBACKTRANSACTION)(
    HANDLE hTransaction
    );

typedef HANDLE (WINAPI * RTLGETCURRENTTRANSACTION)(
    );

typedef VOID (WINAPI * RTLSETCURRENTTRANSACTION)(
    HANDLE TransactionHandle
    );

typedef BOOL (WINAPI * CREATEDIRTRANSACTED)(
    LPCTSTR lpTemplateDirectory,
    LPCTSTR lpNewDirectory,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    HANDLE hTransaction
    );

typedef HANDLE (WINAPI * CREATEFILETRANSACTED)(
    LPCTSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile,
    HANDLE hTransaction,
    PUSHORT pusMiniVersion, 
    PVOID  lpExtendedParameter);

//-----------------------------------------------------------------------------
// Global variables

extern HINSTANCE g_hInst;
extern TToolTip g_Tooltip;
extern HANDLE g_hHeap;
extern DWORD g_dwWinVer;
extern TCHAR g_szInitialDirectory[MAX_PATH];

extern RTLGETCURRENTTRANSACTION pfnRtlGetCurrentTransaction;
extern RTLSETCURRENTTRANSACTION pfnRtlSetCurrentTransaction;
extern CREATETRANSACTION        pfnCreateTransaction;
extern COMMITTRANSACTION        pfnCommitTransaction;
extern ROLLBACKTRANSACTION      pfnRollbackTransaction;
extern CREATEDIRTRANSACTED      pfnCreateDirectoryTransacted;
extern CREATEFILETRANSACTED     pfnCreateFileTransacted;
extern ADDMANDATORYACE          pfnAddMandatoryAce;

//-----------------------------------------------------------------------------
// NTSTATUS conversion

void BuildNtStatusTree();
LPCTSTR NtStatus2Text(NTSTATUS Status);
void FreeNtStatusTree();

//-----------------------------------------------------------------------------
// Utilities (in Utils.cpp)

DWORD StrToInt(LPCTSTR ptr, LPTSTR * szEnd, int nRadix);

int  Text2Bool(LPCTSTR szText, bool * pValue);

int  Text2Hex32(LPCTSTR szText, PDWORD pValue);
int  DlgText2Hex32(HWND hDlg, UINT nIDCtrl, PDWORD pValue);
void Hex2Text32(LPTSTR szBuffer, DWORD Value);
void Hex2DlgText32(HWND hDlg, UINT nIDCtrl, DWORD Value);

int  Text2HexPtr(LPCTSTR szText, PDWORD_PTR pValue);
int  DlgText2HexPtr(HWND hDlg, UINT nIDCtrl, PDWORD_PTR pValue);
void Hex2TextPtr(LPTSTR szBuffer, DWORD_PTR Value);
void Hex2DlgTextPtr(HWND hDlg, UINT nIDCtrl, DWORD_PTR Value);

int  Text2Hex64(LPCTSTR szText, PLONGLONG pValue);
int  DlgText2Hex64(HWND hDlg, UINT nIDCtrl, PLONGLONG pValue);
void Hex2Text64(LPTSTR szBuffer, LONGLONG Value);
void Hex2DlgText64(HWND hDlg, UINT nIDCtrl, LONGLONG Value);

LPTSTR FindDirectoryPathPart(LPTSTR szFullPath);
LPTSTR FindNextPathSeparator(LPTSTR szPathPart);

ULONG GetEaEntrySize(PFILE_FULL_EA_INFORMATION EaInfo);

DWORD TreeView_GetChildCount(HWND hTreeView, HTREEITEM hItem);
HTREEITEM InsertTreeItem(HWND hTreeView, HTREEITEM hParentItem, HTREEITEM hInsertAfter, LPCTSTR szText, PVOID pParam);
HTREEITEM InsertTreeItem(HWND hTreeView, HTREEITEM hParentItem, LPCTSTR szText, PVOID pParam);

BOOL GetTokenElevation(PBOOL pbElevated);
BOOL GetTokenVirtualizationEnabled(PBOOL pbEnabled);
BOOL SetTokenVirtualizationEnabled(BOOL bEnabled);

HWND AttachIconToEdit(HWND hDlg, HWND hWndChild, UINT nIDIcon);
void SetResultInfo(HWND hDlg, NTSTATUS Status, HANDLE hHandle = NULL, UINT_PTR ResultLength = 0, PLARGE_INTEGER pResultLength = NULL);

void ResolveDynamicLoadedAPIs();
void UnloadDynamicLoadedAPIs();

BOOLEAN  IsNativeName(LPCTSTR szFileName);

NTSTATUS FileNameToUnicodeString(PUNICODE_STRING FileName, LPCTSTR szFileName);
void     FreeFileNameString(PUNICODE_STRING FileName);

NTSTATUS ConvertToNtName(HWND hDlg, UINT nIDEdit);
int      ConvertToWin32Name(HWND hDlg, UINT nIDEdit);

LPTSTR FlagsToString(TFlagInfo * pFlags, LPTSTR szBuffer, size_t cchBuffer, DWORD dwFlags, bool bNewLineSeparated);

void FileIDToString(TFileTestData * pData, ULONGLONG FileId, LPTSTR szBuffer);
void ObjectIDToString(PBYTE pbObjId, LPCTSTR szFileName, LPTSTR szObjectID);
int  StringToFileID(LPCTSTR szFileOrObjId, LPTSTR szVolume, PVOID pvFileObjId, PDWORD pLength);

int ExecuteContextMenu(HWND hWndParent, UINT nIDMenu, LPARAM lParam);
int ExecuteContextMenuForDlgItem(HWND hDlg, UINT nIDCtrl, UINT nIDMenu);

NTSTATUS NtDeleteReparsePoint(HANDLE ObjectHandle);
NTSTATUS NtDeleteReparsePoint(POBJECT_ATTRIBUTES PtrObjectAttributes);

//-----------------------------------------------------------------------------
// Conversion of FILETIME to text and back

LPTSTR FileTimeToText(
    LPTSTR szBuffer,
    LPTSTR szEndChar,
    PFILETIME pFt,
    BOOL bTextForEdit);

NTSTATUS TextToFileTime(
    LPCTSTR szText,
    PFILETIME pFt);

BOOL GetSupportedDateTimeFormats(
    LPCTSTR szDateFormatPrefix,
    LPCTSTR szTimeFormatPrefix,
    LPTSTR szBuffer,
    int nMaxChars);

//-----------------------------------------------------------------------------
// Dialogs

INT_PTR HelpAboutDialog(HWND hParent);
INT_PTR ValuesDialog(HWND hWndParent, PDWORD pdwValue, UINT nIDTitle, TFlagInfo * pFlags);
INT_PTR FlagsDialog(HWND hWndParent, LPDWORD pdwFlags, UINT nIDTitle, TFlagInfo * pFlags);
INT_PTR FlagsDialog(HWND hWndParent, UINT nIDValue, UINT nIDTitle, TFlagInfo * pFlags);
INT_PTR FlagsDialog2(HWND hWndParent, UINT nIDDialog, UINT nIDCtrl, TFlagInfo * pFlags);
INT_PTR EaEditorDialog(HWND hParent, PFILE_FULL_EA_INFORMATION * pEaInfo);
INT_PTR PrivilegesDialog(HWND hParent);
INT_PTR ObjectIDActionDialog(HWND hParent);
INT_PTR FileActionDialog(HWND hParent);
INT_PTR DirectoryActionDialog(HWND hParent);
INT_PTR CopyFileDialog(HWND hParent, TFileTestData * pData);

TApcEntry * CreateApcEntry(TWindowData * pData, UINT ApcType, size_t cbApcSize);
bool InsertApcEntry(TWindowData * pData, TApcEntry * pApc);
void FreeApcEntry(TApcEntry * pApc);

int NtUseFileId(HWND hDlg, LPCTSTR szFileId);
void DisableCloseDialog(HWND hDlg, BOOL bDisable);
INT_PTR FileTestDialog(HWND hParent, TFileTestData * pData);

//-----------------------------------------------------------------------------
// Extended attributes dialog (shared functions)

void ExtendedAttributesToListView(HWND hDlg, PFILE_FULL_EA_INFORMATION pFileEa);
PFILE_FULL_EA_INFORMATION ListViewToExtendedAttributes(HWND hDlg, DWORD & dwOutEaLength);
INT_PTR CALLBACK ExtendedAttributesEditorProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR ExtendedAtributesEditorDialog(HWND hParent, TFileTestData * pData);
INT_PTR FillUserDataDialog(HWND hParent, TFileTestData * pData);
INT_PTR DataEditorDialog(HWND hParent, LPVOID BaseAddress, size_t ViewSize);

//-----------------------------------------------------------------------------
// Message handlers for each page

INT_PTR CALLBACK PageProc00(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK PageProc01(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK PageProc02(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK PageProc03(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK PageProc04(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK PageProc05(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK PageProc06(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK PageProc08(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK PageProc09(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK PageProc10(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK PageProc11(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//-----------------------------------------------------------------------------
// Debugging functions

#ifdef _DEBUG
int RemoveDirectory_DEBUG(LPCTSTR szDirName);
#endif

#endif // __TESTFILE_H__
