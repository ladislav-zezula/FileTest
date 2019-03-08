/*****************************************************************************/
/* TestFile.h                             Copyright (c) Ladislav Zezula 2003 */
/*---------------------------------------------------------------------------*/
/* Definitions for file access testing application                           */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 14.07.03  1.00  Lad  The first version of FileTest.h                      */
/*****************************************************************************/

#ifndef __FILETEST_H__
#define __FILETEST_H__

#ifndef UNICODE
#define UNICODE
#define _UNICODE
#endif

#pragma warning(disable: 4091)  // warning C4091: 'typedef ': ignored on left of 'tagGPFIDL_FLAGS' when no variable is declared

#include <tchar.h>
#include <stdio.h>

#define WIN32_NO_STATUS 
#include <windows.h>
#undef WIN32_NO_STATUS 
#include <windowsx.h>
#include <ShlObj.h>
#include <winioctl.h>
#include <strsafe.h>

#include "ntstatus.h"
#include "ntdll.h"
#include "Utils.h"
#include "TAceHelper.h"
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
#define MAX_CONTEXT_MENUS           0x08            // Maximum supported number of context menus

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
#define WM_DEFER_ITEM_TEXT          (WM_USER + 0x1008)  // WPARAM = hItem, LPARAM = LPTSTR

#define STATUS_INVALID_DATA_FORMAT  0xC1110001
#define STATUS_CANNOT_EDIT_THIS     0xC1110002
#define STATUS_FILE_ID_CONVERSION   0xC1110003
#define STATUS_COPIED_TO_CLIPBOARD  0xC1110004

#define SEVERITY_PENDING            2

#define APC_TYPE_NONE               0
#define APC_TYPE_READ_WRITE         1
#define APC_TYPE_LOCK_UNLOCK        2
#define APC_TYPE_FSCTL              3
#define APC_TYPE_IOCTL              4

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

// Common structure for context menus
struct TContextMenu
{
    LPCTSTR szMenuName;                     // Name of the menu (or ID)
    HMENU hMenu;                            // Pre-loaded HMENU
};

// Common structure for data blob 
struct TDataBlob
{
    DWORD SetLength(SIZE_T NewLength);
    void Free();

    LPBYTE pbData;                          // Pointer to the data
    SIZE_T cbData;                          // Current length of the data
    SIZE_T cbDataMax;                       // Maximum length of the data
};

// Common structure for APCs. Keep its size 8-byte aligned
struct TApcEntry
{
    // Common APC entry members
    IO_STATUS_BLOCK IoStatus;               // IO_STATUS_BLOCK for the entry
    LARGE_INTEGER ByteOffset;               // Starting offset of the operation
    OVERLAPPED Overlapped;                  // Overlapped structure for the Win32 APIs
    LIST_ENTRY Entry;                       // Links to other APC entries
    HANDLE hEvent;                          // When signalled, triggers this APC
    HWND hWndPage;                          // Page that initiated the APC
    ULONG ApcType;                          // Common member for determining type of the APC
    ULONG UserParam;                        // Any user-defined 32-bit value (e.g. FSCTL code)
    ULONG BufferLength;                     // Length of data buffer (following the TApcEntry structure)
    ULONG bAsynchronousCompletion:1;        // If truem the request returned pending status and will be completed asynchronously
    ULONG bIncrementPosition:1;             // If true, the file position will be incremented when complete
    ULONG bHasIoStatus:1;                   // If true, the IO_STATUS_BLOCK is valid (otherwise it's OVERLAPED)
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
    ULONG         IsDefaultFileName1:1;     // TRUE: The file name was created as default
    
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
    UINT          FillPattern;              // Fill data pattern

    ULONG         dwCopyFileFlags;          // For file copying
    ULONG         dwMoveFileFlags;          // For MoveFileEx
    ULONG         dwOplockLevel;            // For requesting Win7 oplock
    BOOL          bTransactionActive;
    BOOL          bUseTransaction;
    BOOL          bSectionViewMapped;
    
    UINT_PTR      BlinkTimer;               // If nonzero, this is ID of the blink timer
    HWND          hWndBlink;                // It not NULL, this is the handle of blink window
    BOOL          bEnableResizing;          // TRUE if the dialog is allowed to be resized

    TDataBlob     RdWrData;                 // Buffer for ReadFile / WriteFile
    TDataBlob     NtInfoData;               // Buffer for NtQueryInformationFile/NtSetInformationFile
    TDataBlob     InData;                   // Input buffer for DeviceIoControlFile / NtDeviceIoControlFile / NtfsControlFile
    TDataBlob     OutData;                  // Output buffer for DeviceIoControlFile / NtDeviceIoControlFile / NtfsControlFile

    PREPARSE_DATA_BUFFER ReparseData;       // Buffer for reparse points
    ULONG         ReparseDataLength;        // Total length of reparse data buffer
    ULONG         ReparseDataValid;         // Available length of reparse data buffer
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
#define TYPE_VNAME_FIEBD     18             // ShortName in FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION
#define TYPE_FILEID64        19             // 8-byte file ID
#define TYPE_FILEID128       20             // 16-byte file ID
#define TYPE_DIR_HANDLE      21             // Directory handle for certain file operations
#define TYPE_FLAG32          22             // A 32-bit flag value
#define TYPE_STRUCT         100             // Sub-structure, nMemberSize must be sizeof(structure) !!!
#define TYPE_CHAINED_STRUCT 101             // Chain of structures first 32-bit number is "NextEntryOffset"
#define TYPE_ARRAY_PROCESS  102             // Array of process IDs, variable length, length is 32-bit number
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
        TFlagInfo * pFlags;                 // Flags, if this is a flag array
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

typedef BOOL (WINAPI * CREATEHARDLINK)(
    LPCTSTR lpFileName,
    LPCTSTR lpExistingFileName,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes);

//-----------------------------------------------------------------------------
// Global variables

extern TContextMenu g_ContextMenus[MAX_CONTEXT_MENUS];
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
extern CREATEHARDLINK           pfnCreateHardLink;
extern ADDMANDATORYACE          pfnAddMandatoryAce;

//-----------------------------------------------------------------------------
// Flag values, global to the entire project

extern TFlagInfo DesiredAccessValues[];
extern TFlagInfo FileAttributesValues[];

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
LPARAM TreeView_GetItemParam(HWND hTreeView, HTREEITEM hItem);
LPARAM TreeView_DeferItemText(HWND hTreeView, HTREEITEM hItem);
HTREEITEM TreeView_SetTreeItem(HWND hTreeView, HTREEITEM hItem, LPCTSTR szText, LPARAM lParam);
HTREEITEM InsertTreeItem(HWND hTreeView, HTREEITEM hParent, HTREEITEM hInsertAfter, LPCTSTR szText, PVOID pParam);
HTREEITEM InsertTreeItem(HWND hTreeView, HTREEITEM hParent, LPCTSTR szText, PVOID pParam);
HTREEITEM InsertTreeItem(HWND hTreeView, HTREEITEM hParent, LPCTSTR szText, LPARAM lParam = 0);
void TreeView_DeleteChildren(HWND hTreeView, HTREEITEM hParent);
void TreeView_CopyToClipboard(HWND hWndTree);
int OnTVKeyDown_CopyToClipboard(HWND hDlg, LPNMTVKEYDOWN pNMTVKeyDown);

BOOL GetTokenElevation(PBOOL pbElevated);
BOOL GetTokenVirtualizationEnabled(PBOOL pbEnabled);
BOOL SetTokenVirtualizationEnabled(BOOL bEnabled);

HWND AttachIconToEdit(HWND hDlg, HWND hWndChild, UINT nIDIcon);

void ResolveDynamicLoadedAPIs();
void UnloadDynamicLoadedAPIs();

BOOLEAN  IsNativeName(LPCTSTR szFileName);

NTSTATUS FileNameToUnicodeString(PUNICODE_STRING FileName, LPCTSTR szFileName);
void     FreeFileNameString(PUNICODE_STRING FileName);

NTSTATUS ConvertToNtName(HWND hDlg, UINT nIDEdit);
int      ConvertToWin32Name(HWND hDlg, UINT nIDEdit);

LPTSTR FlagsToString(TFlagInfo * pFlags, LPTSTR szBuffer, size_t cchBuffer, DWORD dwFlags, bool bNewLineSeparated);
LPTSTR NamedValueToString(TFlagInfo * pFlags, LPTSTR szBuffer, size_t cchBuffer, LPCTSTR szFormat, DWORD dwFlags);
LPTSTR GuidValueToString(LPTSTR szBuffer, size_t cchBuffer, LPCTSTR szFormat, LPGUID PtrGuid);

void FileIDToString(TFileTestData * pData, ULONGLONG FileId, LPTSTR szBuffer);
void ObjectIDToString(PBYTE pbObjId, LPCTSTR szFileName, LPTSTR szObjectID);
int  StringToFileID(LPCTSTR szFileOrObjId, LPTSTR szVolume, PVOID pvFileObjId, PDWORD pLength);

HMENU FindContextMenu(UINT nIDMenu);
int ExecuteContextMenu(HWND hWndParent, HMENU hMenu, LPARAM lParam);
int ExecuteContextMenuForDlgItem(HWND hWndParent, HMENU hMenu, UINT nIDCtrl);

NTSTATUS NtDeleteReparsePoint(HANDLE ObjectHandle);
NTSTATUS NtDeleteReparsePoint(POBJECT_ATTRIBUTES PtrObjectAttributes);

ULONG RtlComputeCrc32(ULONG InitialCrc, PVOID Buffer, ULONG Length);

BOOL WINAPI MyAddMandatoryAce(PACL pAcl, DWORD dwAceRevision, DWORD dwAceFlags, DWORD MandatoryPolicy, PSID pLabelSid);

//-----------------------------------------------------------------------------
// Common function to set result of an operation

// Supported flags
#define RSI_LAST_ERROR  0x00000001              // IDC_ERROR_CODE  -> DWORD dwErrCode (with blinking icon)
#define RSI_NTSTATUS    0x00000002              // IDC_ERROR_CODE  -> NTSTATUS Status (with blinking icon)
#define RSI_HANDLE      0x00000004              // IDC_HANDLE      -> HANDLE hHandle;
#define RSI_NOINFO      0x00000008              // IDC_INFORMATION -> Set empty
#define RSI_INFORMATION 0x00000010              // IDC_INFORMATION -> PIO_STATUS_BLOCK IoStatus
#define RSI_INFO_INT32  0x00000020              // IDC_INFORMATION -> DWORD Information
#define RSI_NTCREATE    0x00000040              // IDC_INFORMATION -> PIO_STATUS_BLOCK IoStatus
#define RSI_READ        0x00000080              // IDC_INFORMATION -> DWORD BytesRead
#define RSI_WRITTEN     0x00000100              // IDC_INFORMATION -> DWORD BytesWritten
#define RSI_FILESIZE    0x00000200              // IDC_INFORMATION -> PLARGE_INTEGER FileSize
#define RSI_FILEPOS     0x00000400              // IDC_INFORMATION -> PLARGE_INTEGER FilePos

void SetResultInfo(HWND hDlg, DWORD dwFlags, ...);

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
INT_PTR FlagsDialog_OnControl(HWND hWndParent, UINT nIDCtrl, UINT nIDTitle, TFlagInfo * pFlags);
INT_PTR FlagsDialog_PreArranged(HWND hWndParent, UINT nIDDialog, UINT nIDCtrl, TFlagInfo * pFlags);
INT_PTR EaEditorDialog(HWND hParent, PFILE_FULL_EA_INFORMATION * pEaInfo);
INT_PTR PrivilegesDialog(HWND hParent);
INT_PTR ObjectIDActionDialog(HWND hParent);
INT_PTR ObjectGuidHelpDialog(HWND hParent);
INT_PTR CopyFileDialog(HWND hParent, TFileTestData * pData);

TApcEntry * CreateApcEntry(TWindowData * pData, UINT ApcType, size_t cbExtraSize = 0);
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
INT_PTR CALLBACK PageProc12(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//-----------------------------------------------------------------------------
// Debugging functions

#endif // __FILETEST_H__
