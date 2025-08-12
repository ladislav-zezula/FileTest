/*****************************************************************************/
/* Page06NtFileInfo.cpp                   Copyright (c) Ladislav Zezula 2005 */
/*---------------------------------------------------------------------------*/
/* Description :                                                             */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 01.11.05  1.00  Lad  The first version of Page06NtFileInfo.cpp            */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local defines

#define WM_RELOADITEMS       (WM_USER + 0x1000)
#define WM_SHOW_DATE_FORMATS (WM_USER + 0x1001)

#define INITIAL_FILEINFO_BUFFER_SIZE 0x10000

static UNICODE_STRING NullString = RTL_CONSTANT_STRING(L"NULL");

//-----------------------------------------------------------------------------
// Description of data structures for file info classes

// Values for FILE_CASE_SENSITIVE_INFORMATION::Flags
static TFlagInfo CaseSensitiveFlags[] =
{
    FLAGINFO_BITV(FILE_CS_FLAG_CASE_SENSITIVE_DIR),
    FLAGINFO_END()
};


enum NewWDK22600DirectoryListingClasses
{
    FileStatBasicInformation                = 77,
    FileId64ExtdDirectoryInformation,       // 78
    FileId64ExtdBothDirectoryInformation,   // 79
    FileIdAllExtdDirectoryInformation,      // 80
    FileIdAllExtdBothDirectoryInformation   // 81
};

TStructMember FileStatBasicInformationMembers[] =
{
    {_T("FileId"),                  TYPE_FILEID64,  sizeof(LARGE_INTEGER)},
    {_T("CreationTime"),            TYPE_FILETIME,  sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),          TYPE_FILETIME,  sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),           TYPE_FILETIME,  sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),              TYPE_FILETIME,  sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),          TYPE_UINT64,    sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),               TYPE_UINT64,    sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),          TYPE_FLAG32,    sizeof(ULONG), NULL, {(TStructMember*)FileAttributesValues}},
    {_T("ReparseTag"),              TYPE_UINT32,    sizeof(ULONG)},
    {_T("NumberOfLinks"),           TYPE_UINT32,    sizeof(ULONG)},
    {_T("DeviceType"),              TYPE_UINT32,    sizeof(ULONG)},
    {_T("DeviceCharacteristics"),   TYPE_UINT32,    sizeof(ULONG)},
    {_T("Reserved"),                TYPE_UINT32,    sizeof(ULONG)},
    {_T("VolumeSerialNumber"),      TYPE_UINT64,    sizeof(LARGE_INTEGER)},
    {_T("FileId"),                  TYPE_FILEID128, sizeof(FILE_ID_128)},
    {NULL}
};

TStructMember FileId64ExtdDirectoryInformationMembers[] =
{
    {_T("NextEntryOffset"), TYPE_UINT32,   sizeof(ULONG)},
    {_T("FileIndex"),       TYPE_UINT32,   sizeof(ULONG)},
    {_T("CreationTime"),    TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),  TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember*)FileAttributesValues}},
    {_T("FileNameLength"),  TYPE_UINT32,   sizeof(ULONG)},
    {_T("EaSize"),          TYPE_UINT32,   sizeof(ULONG)},
    {_T("ReparsePointTag"), TYPE_UINT32,   sizeof(ULONG)},
    {_T("FileId"),          TYPE_FILEID64, sizeof(LARGE_INTEGER)},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength)},
    {NULL}
};

TStructMember FileId64ExtdBothDirectoryInformationMembers[] =
{
    {_T("NextEntryOffset"), TYPE_UINT32,        sizeof(ULONG)},
    {_T("FileIndex"),       TYPE_UINT32,        sizeof(ULONG)},
    {_T("CreationTime"),    TYPE_FILETIME,      sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME,      sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME,      sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME,      sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64,        sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),  TYPE_UINT64,        sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,        sizeof(ULONG), NULL, {(TStructMember*)FileAttributesValues}},
    {_T("FileNameLength"),  TYPE_UINT32,        sizeof(ULONG)},
    {_T("EaSize"),          TYPE_UINT32,        sizeof(ULONG)},
    {_T("ReparsePointTag"), TYPE_UINT32,        sizeof(ULONG)},
    {_T("FileId"),          TYPE_FILEID64,      sizeof(LARGE_INTEGER)},
    {_T("ShortNameLength"), TYPE_UINT8,         sizeof(CCHAR)},
    {_T("<padding>"),       TYPE_PADDING,       sizeof(WCHAR)},
    {_T("ShortName"),       TYPE_VNAME_FIEBD,   sizeof(WCHAR[12])},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength)},
    {NULL}
};

TStructMember FileIdAllExtdDirectoryInformationMembers[] =
{
    {_T("NextEntryOffset"), TYPE_UINT32,    sizeof(ULONG)},
    {_T("FileIndex"),       TYPE_UINT32,    sizeof(ULONG)},
    {_T("CreationTime"),    TYPE_FILETIME,  sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME,  sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME,  sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME,  sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64,    sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),  TYPE_UINT64,    sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,    sizeof(ULONG), NULL, {(TStructMember*)FileAttributesValues}},
    {_T("FileNameLength"),  TYPE_UINT32,    sizeof(ULONG)},
    {_T("EaSize"),          TYPE_UINT32,    sizeof(ULONG)},
    {_T("ReparsePointTag"), TYPE_UINT32,    sizeof(ULONG)},
    {_T("FileId"),          TYPE_FILEID64,  sizeof(LARGE_INTEGER)},
    {_T("FileId128"),       TYPE_FILEID128, sizeof(FILE_ID_128)},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength)},
    {NULL}
};

TStructMember FileIdAllExtdBothDirectoryInformationMembers[] =
{
    {_T("NextEntryOffset"), TYPE_UINT32,        sizeof(ULONG)},
    {_T("FileIndex"),       TYPE_UINT32,        sizeof(ULONG)},
    {_T("CreationTime"),    TYPE_FILETIME,      sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME,      sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME,      sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME,      sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64,        sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),  TYPE_UINT64,        sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,        sizeof(ULONG), NULL, {(TStructMember*)FileAttributesValues}},
    {_T("FileNameLength"),  TYPE_UINT32,        sizeof(ULONG)},
    {_T("EaSize"),          TYPE_UINT32,        sizeof(ULONG)},
    {_T("ReparsePointTag"), TYPE_UINT32,        sizeof(ULONG)},
    {_T("FileId"),          TYPE_FILEID64,      sizeof(LARGE_INTEGER)},
    {_T("FileId128"),       TYPE_FILEID128,     sizeof(FILE_ID_128)},
    {_T("ShortNameLength"), TYPE_UINT8,         sizeof(CCHAR)},
    {_T("<padding>"),       TYPE_PADDING,       sizeof(WCHAR)},
    {_T("ShortName"),       TYPE_VNAME_FIEBD,   sizeof(WCHAR[12])},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength)},
    {NULL}
};

// Values for FILE_FS_ATTRIBUTE_INFORMATION::FileSystemAttributes
TFlagInfo FileSystemAttributesValues[] =
{
    FLAGINFO_BITV(FILE_CASE_SENSITIVE_SEARCH),
    FLAGINFO_BITV(FILE_CASE_PRESERVED_NAMES),
    FLAGINFO_BITV(FILE_UNICODE_ON_DISK),
    FLAGINFO_BITV(FILE_PERSISTENT_ACLS),
    FLAGINFO_BITV(FILE_FILE_COMPRESSION),
    FLAGINFO_BITV(FILE_VOLUME_QUOTAS),
    FLAGINFO_BITV(FILE_SUPPORTS_SPARSE_FILES),
    FLAGINFO_BITV(FILE_SUPPORTS_REPARSE_POINTS),
    FLAGINFO_BITV(FILE_SUPPORTS_REMOTE_STORAGE),
    FLAGINFO_BITV(FILE_RETURNS_CLEANUP_RESULT_INFO),
    FLAGINFO_BITV(FILE_SUPPORTS_POSIX_UNLINK_RENAME),
    FLAGINFO_BITV(FILE_SUPPORTS_BYPASS_IO),
    FLAGINFO_BITV(FILE_SUPPORTS_STREAM_SNAPSHOTS),
    FLAGINFO_BITV(FILE_SUPPORTS_CASE_SENSITIVE_DIRS),
    FLAGINFO_BITV(FILE_VOLUME_IS_COMPRESSED),
    FLAGINFO_BITV(FILE_SUPPORTS_OBJECT_IDS),
    FLAGINFO_BITV(FILE_SUPPORTS_ENCRYPTION),
    FLAGINFO_BITV(FILE_NAMED_STREAMS),
    FLAGINFO_BITV(FILE_READ_ONLY_VOLUME),
    FLAGINFO_BITV(FILE_SEQUENTIAL_WRITE_ONCE),
    FLAGINFO_BITV(FILE_SUPPORTS_TRANSACTIONS),
    FLAGINFO_BITV(FILE_SUPPORTS_HARD_LINKS),
    FLAGINFO_BITV(FILE_SUPPORTS_EXTENDED_ATTRIBUTES),
    FLAGINFO_BITV(FILE_SUPPORTS_OPEN_BY_FILE_ID),
    FLAGINFO_BITV(FILE_SUPPORTS_USN_JOURNAL),
    FLAGINFO_BITV(FILE_SUPPORTS_INTEGRITY_STREAMS),
    FLAGINFO_BITV(FILE_SUPPORTS_BLOCK_REFCOUNTING),
    FLAGINFO_BITV(FILE_SUPPORTS_SPARSE_VDL),
    FLAGINFO_BITV(FILE_DAX_VOLUME),
    FLAGINFO_BITV(FILE_SUPPORTS_GHOSTING),
    FLAGINFO_END()
};

TStructMember FileUnknownInformationMembers[] =
{
    {_T("BinaryData"),      TYPE_ARRAY8_VARIABLE, 0},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileDirectoryInformationMembers[] =
{
    {_T("NextEntryOffset"), TYPE_UINT32,   sizeof(ULONG)},
    {_T("FileIndex"),       TYPE_UINT32,   sizeof(ULONG)},
    {_T("CreationTime"),    TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),  TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)FileAttributesValues}},
    {_T("FileNameLength"),  TYPE_UINT32,   sizeof(ULONG)},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileNameLength)},
    {NULL}
};

TStructMember FileFullDirectoryInformationMembers[] =
{
    {_T("NextEntryOffset"), TYPE_UINT32,   sizeof(ULONG)},
    {_T("FileIndex"),       TYPE_UINT32,   sizeof(ULONG)},
    {_T("CreationTime"),    TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),  TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)FileAttributesValues}},
    {_T("FileNameLength"),  TYPE_UINT32,   sizeof(ULONG)},
    {_T("EaSize"),          TYPE_UINT32,   sizeof(ULONG)},
    {_T("FileName"),        TYPE_WNAME_L32B,  FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileNameLength)},
    {NULL}
};

TStructMember FileBothDirectoryInformationMembers[] =
{                                            
    {_T("NextEntryOffset"), TYPE_UINT32,     sizeof(ULONG)},
    {_T("FileIndex"),       TYPE_UINT32,     sizeof(ULONG)},
    {_T("CreationTime"),    TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64,     sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),  TYPE_UINT64,     sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,     sizeof(ULONG), NULL, {(TStructMember *)FileAttributesValues}},
    {_T("FileNameLength"),  TYPE_UINT32,     sizeof(ULONG)},
    {_T("EaSize"),          TYPE_UINT32,     sizeof(ULONG)},
    {_T("ShortNameLength"), TYPE_UINT8,      sizeof(BYTE)},       // Although CCHAR, it has 2 bytes because of alignment
    {_T("<padding>"),       TYPE_PADDING,    sizeof(WCHAR)},
    {_T("ShortName"),       TYPE_VNAME_FBDI, sizeof(WCHAR[12])},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileNameLength)},
    {NULL}
};

TStructMember FileBasicInformationMembers[] =
{
    {_T("CreationTime"),    TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)FileAttributesValues}},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileStandardInformationMembers[] =
{
    {_T("AllocationSize"),  TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("NumberOfLinks"),   TYPE_UINT32, sizeof(ULONG)},
    {_T("DeletePending"),   TYPE_BOOLEAN, sizeof(BOOLEAN)},
    {_T("Directory"),       TYPE_BOOLEAN, sizeof(BOOLEAN)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileStandardInformationMembersEx[] =
{
    { _T("AllocationSize"),  TYPE_UINT64, sizeof(LARGE_INTEGER) },
    { _T("EndOfFile"),       TYPE_UINT64, sizeof(LARGE_INTEGER) },
    { _T("NumberOfLinks"),   TYPE_UINT32, sizeof(ULONG) },
    { _T("DeletePending"),   TYPE_BOOLEAN, sizeof(BOOLEAN) },
    { _T("Directory"),       TYPE_BOOLEAN, sizeof(BOOLEAN) },
    { _T("AlternateStream"), TYPE_BOOLEAN, sizeof(BOOLEAN) },
    { _T("MetadataAttribute"), TYPE_BOOLEAN, sizeof(BOOLEAN) },
    { NULL, TYPE_NONE, 0 }
};

TStructMember FileInternalInformationMembers[] =
{
    {_T("IndexNumber"),     TYPE_FILEID64, sizeof(LARGE_INTEGER)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileEaInformationMembers[] =
{
    {_T("EaSize"),          TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileAccessInformationMembers[] =
{
    {_T("AccessFlags"),     TYPE_FLAG32, sizeof(ACCESS_MASK), NULL, {(TStructMember *)AccessMaskValues}},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileNameInformationMembers[] =
{
    {_T("FileNameLength"),  TYPE_UINT32,     sizeof(ULONG)},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_NAME_INFORMATION, FileNameLength)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileRenameInformationMembers[] =
{
    {_T("ReplaceIfExists"), TYPE_BOOLEAN,    sizeof(BOOLEAN)},
    {_T("<padding>"),       TYPE_PADDING,    sizeof(HANDLE)},
    {_T("RootDirectory"),   TYPE_DIR_HANDLE, sizeof(HANDLE)},
    {_T("FileNameLength"),  TYPE_UINT32,     sizeof(ULONG)},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_RENAME_INFORMATION, FileNameLength)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileLinkInformationMembers[] =
{
    {_T("ReplaceIfExists"), TYPE_BOOLEAN,    sizeof(ULONG)},
    {_T("<padding>"),       TYPE_PADDING,    sizeof(HANDLE)},
    {_T("RootDirectory"),   TYPE_DIR_HANDLE, sizeof(HANDLE)},
    {_T("FileNameLength"),  TYPE_UINT32,     sizeof(ULONG)},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_LINK_INFORMATION, FileNameLength)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileLinkEntryMembers[] = 
{
    {_T("NextEntryOffset"), TYPE_UINT32,  sizeof(LARGE_INTEGER)},  // alignment
    {_T("ParentFileId"),    TYPE_FILEID64,sizeof(LARGE_INTEGER)},
    {_T("FileNameLength"),  TYPE_UINT32,  sizeof(ULONG)},
    {_T("FileName"),        TYPE_WNAME_L32W, FIELD_OFFSET(FILE_LINK_ENTRY_INFORMATION, FileNameLength)},
    {NULL, TYPE_NONE, 0}
}; 

TStructMember FileNamesInformationMembers[] =
{
    {_T("NextEntryOffset"), TYPE_UINT32,   sizeof(ULONG)},
    {_T("FileIndex"),       TYPE_UINT32,   sizeof(ULONG)},
    {_T("FileNameLength"),  TYPE_UINT32,   sizeof(ULONG)},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_NAMES_INFORMATION, FileNameLength)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileDispositionInformationMembers[] =
{
    {_T("DeleteFile"),      TYPE_BOOLEAN, sizeof(BOOLEAN)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FilePositionInformationMembers[] =
{
    {_T("CurrentByteOffset"), TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileFullEaInformationMembers[] =
{
    {_T("NextEntryOffset"), TYPE_UINT32,    sizeof(ULONG)},
    {_T("Flags"),           TYPE_UINT8,     sizeof(UCHAR)},
    {_T("EaNameLength"),    TYPE_UINT8,     sizeof(UCHAR)},
    {_T("EaValueLength"),   TYPE_UINT16,    sizeof(USHORT)},
    {_T("EaName"),          TYPE_CNAME_L8B, FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaNameLength)},
//  {_T("EaValue"),         TYPE_ARRAY,     FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaValueLength)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileModeInformationMembers[] =
{
    {_T("Mode"),            TYPE_FLAG32, sizeof(ULONG), NULL, {(TStructMember *)CreateOptionsValues}},
    {NULL, TYPE_NONE, 0}
};

static TFlagInfo FileAlignmentValues[] =
{
    FLAGINFO_NUMV(FILE_BYTE_ALIGNMENT),
    FLAGINFO_NUMV(FILE_WORD_ALIGNMENT),
    FLAGINFO_NUMV(FILE_LONG_ALIGNMENT),
    FLAGINFO_NUMV(FILE_QUAD_ALIGNMENT),
    FLAGINFO_NUMV(FILE_OCTA_ALIGNMENT),
    FLAGINFO_NUMV(FILE_32_BYTE_ALIGNMENT),
    FLAGINFO_NUMV(FILE_64_BYTE_ALIGNMENT),
    FLAGINFO_NUMV(FILE_128_BYTE_ALIGNMENT),
    FLAGINFO_NUMV(FILE_256_BYTE_ALIGNMENT),
    FLAGINFO_NUMV(FILE_512_BYTE_ALIGNMENT),
    FLAGINFO_END()
};

TStructMember FileAlignmentInformationMembers[] =
{
    {_T("AlignmentRequirement"), TYPE_FLAG32, sizeof(ULONG), NULL, {(TStructMember *)FileAlignmentValues}},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileAllInformationMembers[] =
{
    {_T("FILE_BASIC_INFORMATION"),    TYPE_STRUCT, sizeof(FILE_BASIC_INFORMATION), NULL, {FileBasicInformationMembers}},
    {_T("FILE_STANDARD_INFORMATION"), TYPE_STRUCT, sizeof(FILE_STANDARD_INFORMATION), NULL, {FileStandardInformationMembers}},
    {_T("FILE_INTERNAL_INFORMATION"), TYPE_STRUCT, sizeof(FILE_INTERNAL_INFORMATION), NULL, {FileInternalInformationMembers}},
    {_T("FILE_EA_INFORMATION"),       TYPE_STRUCT, sizeof(FILE_EA_INFORMATION), NULL, {FileEaInformationMembers}},
    {_T("FILE_ACCESS_INFORMATION"),   TYPE_STRUCT, sizeof(FILE_ACCESS_INFORMATION), NULL, {FileAccessInformationMembers}},
    {_T("FILE_POSITION_INFORMATION"), TYPE_STRUCT, sizeof(FILE_POSITION_INFORMATION), NULL, {FilePositionInformationMembers}},
    {_T("FILE_MODE_INFORMATION"),     TYPE_STRUCT, sizeof(FILE_MODE_INFORMATION), NULL, {FileModeInformationMembers}},
    {_T("FILE_ALIGNMENT_INFORMATION"),TYPE_STRUCT, sizeof(FILE_ALIGNMENT_INFORMATION), NULL, {FileAlignmentInformationMembers}},
    {_T("FILE_NAME_INFORMATION"),     TYPE_STRUCT, sizeof(FILE_NAME_INFORMATION), NULL, {FileNameInformationMembers}},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileAllocationInformationMembers[] =
{
    {_T("AllocationSize"),  TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileEndOfFileInformationMembers[] =
{
    {_T("EndOfFile"),       TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {NULL, TYPE_NONE, 0}
};

#define FileAlternateNameInformationMembers FileNameInformationMembers

TStructMember FileStreamInformationMembers[] =
{
    {_T("NextEntryOffset"),      TYPE_UINT32, sizeof(ULONG)},
    {_T("StreamNameLength"),     TYPE_UINT32, sizeof(ULONG)},
    {_T("StreamSize"),           TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("StreamAllocationSize"), TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("StreamName"),           TYPE_WNAME_L32B, FIELD_OFFSET(FILE_STREAM_INFORMATION, StreamNameLength)},
    {NULL, TYPE_NONE, 0}
};

static TFlagInfo FilePipeReadModeValues[] =
{
    FLAGINFO_NUMV(FILE_PIPE_BYTE_STREAM_MODE),
    FLAGINFO_NUMV(FILE_PIPE_MESSAGE_MODE),
    FLAGINFO_END()
};

static TFlagInfo FilePipeCompletionModeValues[] =
{
    FLAGINFO_NUMV(FILE_PIPE_QUEUE_OPERATION),
    FLAGINFO_NUMV(FILE_PIPE_COMPLETE_OPERATION),
    FLAGINFO_END()
};

TStructMember FilePipeInformationMembers[] =
{
    {_T("ReadMode"),        TYPE_FLAG32, sizeof(ULONG), NULL, {(TStructMember *)FilePipeReadModeValues}},
    {_T("CompletionMode"),  TYPE_FLAG32, sizeof(ULONG), NULL, {(TStructMember *)FilePipeCompletionModeValues}},
    {NULL, TYPE_NONE, 0}
};

static TFlagInfo FilePipeTypeValues[] =
{
    FLAGINFO_MASK(FILE_PIPE_BYTE_STREAM_TYPE | FILE_PIPE_MESSAGE_TYPE, FILE_PIPE_BYTE_STREAM_MODE),
    FLAGINFO_MASK(FILE_PIPE_BYTE_STREAM_TYPE | FILE_PIPE_MESSAGE_TYPE, FILE_PIPE_MESSAGE_TYPE),
    FLAGINFO_BITV(FILE_PIPE_REJECT_REMOTE_CLIENTS),
    FLAGINFO_END()
};

static TFlagInfo FilePipeConfigurationValues[] =
{
    FLAGINFO_NUMV(FILE_PIPE_INBOUND),
    FLAGINFO_NUMV(FILE_PIPE_OUTBOUND),
    FLAGINFO_NUMV(FILE_PIPE_FULL_DUPLEX),
    FLAGINFO_END()
};

static TFlagInfo FilePipeStateValues[] =
{
    FLAGINFO_NUMV(FILE_PIPE_DISCONNECTED_STATE),
    FLAGINFO_NUMV(FILE_PIPE_LISTENING_STATE),
    FLAGINFO_NUMV(FILE_PIPE_CONNECTED_STATE),
    FLAGINFO_NUMV(FILE_PIPE_CLOSING_STATE),
    FLAGINFO_END()
};

static TFlagInfo FilePipeEndValues[] =
{
    FLAGINFO_NUMV(FILE_PIPE_CLIENT_END),
    FLAGINFO_NUMV(FILE_PIPE_SERVER_END),
    FLAGINFO_END()
};

TStructMember FilePipeLocalInformationMembers[] =
{
    {_T("NamedPipeType"),          TYPE_FLAG32, sizeof(ULONG), NULL, {(TStructMember *)FilePipeTypeValues}},
    {_T("NamedPipeConfiguration"), TYPE_FLAG32, sizeof(ULONG), NULL, {(TStructMember *)FilePipeConfigurationValues}},
    {_T("MaximumInstances"),       TYPE_UINT32, sizeof(ULONG)},
    {_T("CurrentInstances"),       TYPE_UINT32, sizeof(ULONG)},
    {_T("InboundQuota"),           TYPE_UINT32, sizeof(ULONG)},
    {_T("ReadDataAvailable"),      TYPE_UINT32, sizeof(ULONG)},
    {_T("OutboundQuota"),          TYPE_UINT32, sizeof(ULONG)},
    {_T("WriteQuotaAvailable"),    TYPE_UINT32, sizeof(ULONG)},
    {_T("NamedPipeState"),         TYPE_FLAG32, sizeof(ULONG), NULL, {(TStructMember *)FilePipeStateValues}},
    {_T("NamedPipeEnd"),           TYPE_FLAG32, sizeof(ULONG), NULL, {(TStructMember *)FilePipeEndValues}},
    {NULL, TYPE_NONE, 0}
};

TStructMember FilePipeRemoteInformationMembers[] =
{
    {_T("CollectDataTime"),        TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("MaximumCollectionCount"), TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileMailslotQueryInformationMembers[] =
{
    {_T("MaximumMessageSize"), TYPE_UINT32, sizeof(ULONG)},
    {_T("MailslotQuota"),      TYPE_UINT32, sizeof(ULONG)},
    {_T("NextMessageSize"),    TYPE_UINT32, sizeof(ULONG)},
    {_T("MessagesAvailable"),  TYPE_UINT32, sizeof(ULONG)},
    {_T("ReadTimeout"),        TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileMailslotSetInformationMembers[] =
{
    {_T("ReadTimeout"),     TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {NULL, TYPE_NONE, 0}
};

static TFlagInfo FileCompressionFormatValues[] =
{
    FLAGINFO_NUMV(COMPRESSION_FORMAT_NONE),
    FLAGINFO_NUMV(COMPRESSION_FORMAT_DEFAULT),
    FLAGINFO_NUMV(COMPRESSION_FORMAT_LZNT1),
    FLAGINFO_END()
};

TStructMember FileCompressionInformationMembers[] =
{
    {_T("CompressedFileSize"), TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("CompressionFormat"), TYPE_FLAG16, sizeof(USHORT), NULL, {(TStructMember *)FileCompressionFormatValues}},
    {_T("CompressionUnitShift"), TYPE_UINT8, sizeof(UCHAR)},
    {_T("ChunkShift"),      TYPE_UINT8, sizeof(UCHAR)},
    {_T("ClusterShift"),    TYPE_UINT8, sizeof(UCHAR)},
    {_T("Reserved[0]"),     TYPE_UINT8, sizeof(UCHAR)},
    {_T("Reserved[1]"),     TYPE_UINT8, sizeof(UCHAR)},
    {_T("Reserved[2]"),     TYPE_UINT8, sizeof(UCHAR)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileObjectIdInformationMembers[] =
{
    {_T("FileReference"),   TYPE_FILEID64,     sizeof(LONGLONG)},
    {_T("ObjectId"),        TYPE_FILEID128,    sizeof(UCHAR[16])},
    {_T("BirthVolumeId"),   TYPE_GUID,         sizeof(UCHAR[16])},
    {_T("BirthObjectId"),   TYPE_FILEID128,    sizeof(UCHAR[16])},
    {_T("DomainId"),        TYPE_GUID,         sizeof(UCHAR[16])},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileCompletionInformationMembers[] =
{
    {_T("Port"),            TYPE_HANDLE,   sizeof(HANDLE)},
    {_T("Key"),             TYPE_POINTER,  sizeof(PVOID)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileMoveClusterInformationMembers[] =
{
    {_T("ClusterCount"),    TYPE_UINT32,     sizeof(ULONG)},
    {_T("<padding>"),       TYPE_PADDING,    sizeof(HANDLE)},
    {_T("RootDirectory"),   TYPE_DIR_HANDLE, sizeof(HANDLE)},
    {_T("FileNameLength"),  TYPE_FILETIME,   sizeof(ULONG)},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_MOVE_CLUSTER_INFORMATION, FileNameLength)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileQuotaInformationMembers[] =
{
    {_T("NextEntryOffset"), TYPE_UINT32,   sizeof(ULONG)},
    {_T("SidLength"),       TYPE_UINT32,   sizeof(ULONG)},
    {_T("ChangeTime"),      TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("QuotaUsed"),       TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("QuotaThreshold"),  TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("QuotaLimit"),      TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("Sid"),             TYPE_SID,      sizeof(SID)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileReparsePointInformationMembers[] =
{
    {_T("FileReference"),   TYPE_FILEID64, sizeof(LONGLONG)},
    {_T("Tag"),             TYPE_UINT32,   sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileNetworkOpenInformationMembers[] =
{
    {_T("CreationTime"),    TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),  TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)FileAttributesValues}},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileAttributeTagInformationMembers[] =
{
    {_T("FileAttributes"),  TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)FileAttributesValues}},
    {_T("ReparseTag"),      TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileTrackingInformationMembers[] =
{
    {_T("DestinationFile"),         TYPE_HANDLE, sizeof(HANDLE)},
    {_T("ObjectInformationLength"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ObjectInformation"),       TYPE_UINT8,  sizeof(CHAR)},   // TODO: TYPE_FTI_NAME
    {NULL, TYPE_NONE, 0}
};

TStructMember FileIdBothDirectoryInformationMembers[] =
{
    {_T("NextEntryOffset"), TYPE_UINT32,     sizeof(ULONG)},
    {_T("FileIndex"),       TYPE_UINT32,     sizeof(ULONG)},
    {_T("CreationTime"),    TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64,     sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),  TYPE_UINT64,     sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,     sizeof(ULONG), NULL, {(TStructMember *)FileAttributesValues}},
    {_T("FileNameLength"),  TYPE_UINT32,     sizeof(ULONG)},
    {_T("EaSize"),          TYPE_UINT32,     sizeof(ULONG)},
    {_T("ShortNameLength"), TYPE_UINT8,      sizeof(BYTE)},        // Although CCHAR, it has 2 bytes because of alignment
    {_T("<padding>"),       TYPE_PADDING,    sizeof(WCHAR)},
    {_T("ShortName"),       TYPE_VNAME_FIBD, sizeof(WCHAR[13])},   // One more WCHAR due to alignment
    {_T("FileId"),          TYPE_FILEID64,   sizeof(LARGE_INTEGER)},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileNameLength)},
    {NULL}
};

TStructMember FileIdFullDirectoryInformationMembers[] =
{
    {_T("NextEntryOffset"), TYPE_UINT32,     sizeof(ULONG)},
    {_T("FileIndex"),       TYPE_UINT32,     sizeof(ULONG)},
    {_T("CreationTime"),    TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME,   sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64,     sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),  TYPE_UINT64,     sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,     sizeof(ULONG), NULL, {(TStructMember *)FileAttributesValues}},
    {_T("FileNameLength"),  TYPE_UINT32,     sizeof(ULONG)},
    {_T("EaSize"),          TYPE_UINT32,     sizeof(LARGE_INTEGER)},    // Size is larger due to alignment
    {_T("FileId"),          TYPE_FILEID64,   sizeof(LARGE_INTEGER)},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileNameLength)},
    {NULL}
};

TStructMember FileValidDataLengthInformationMembers[] =
{
    {_T("ValidDataLength"), TYPE_UINT64,     sizeof(LARGE_INTEGER)},
    {NULL, TYPE_NONE, 0}
};

#define FileShortNameInformationMembers FileNameInformationMembers

TStructMember FileIoCompletionNotificationInformationMembers[] =
{
    {_T("Flags"),           TYPE_UINT32,     sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileIoStatusBlockRangeInformationMembers[] =
{
    {_T("IoStatusBlockRange"), TYPE_POINTER, sizeof(void *)},
    {_T("Length"),             TYPE_UINT32,  sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

static TFlagInfo IoPriorityHintValues[] =
{
    FLAGINFO_NUMV(IoPriorityVeryLow),
    FLAGINFO_NUMV(IoPriorityLow),
    FLAGINFO_NUMV(IoPriorityNormal),
    FLAGINFO_NUMV(IoPriorityHigh),
    FLAGINFO_NUMV(IoPriorityCritical),
    FLAGINFO_END()
};

TStructMember FileIoPriorityHintInformationMembers[] =
{
    {_T("PriorityHint"),    TYPE_FLAG32,  sizeof(IO_PRIORITY_HINT), NULL, {(TStructMember *)IoPriorityHintValues}},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileSfioReserveInformationMembers[] =
{
    {_T("RequestsPerPeriod"),  TYPE_UINT32,     sizeof(ULONG)},
    {_T("Period"),             TYPE_UINT32,     sizeof(ULONG)},
    {_T("RetryFailures"),      TYPE_BOOLEAN,    sizeof(BOOLEAN)},
    {_T("Discardable"),        TYPE_BOOLEAN,    sizeof(BOOLEAN)},
    {_T("<padding>"),          TYPE_PADDING,    sizeof(ULONG)},
    {_T("RequestSize"),        TYPE_UINT32,     sizeof(ULONG)},
    {_T("NumOutstandingRequests"), TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileSfioVolumeInformationMembers[] =
{
    {_T("MaximumRequestsPerPeriod"), TYPE_UINT32, sizeof(ULONG)},
    {_T("MinimumPeriod"),      TYPE_UINT32,  sizeof(ULONG)},
    {_T("MinimumTransferSize"),TYPE_UINT32,  sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileHardLinkInformationMembers[] =
{   
    {_T("BytesNeeded"),     TYPE_UINT32, sizeof(ULONG)},
    {_T("EntriesReturned"), TYPE_UINT32, sizeof(ULONG)},
    {_T("Entry"),           TYPE_CHAINED_STRUCT, 0, NULL, FileLinkEntryMembers},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileProcessIdsUsingFileInformationMembers[] =
{   
    {_T("NumberOfProcessIdsInList"), TYPE_UINT32, sizeof(ULONG)},
    {_T("<padding>"),                TYPE_PADDING, sizeof(HANDLE)},
    {_T("ProcessIdList"),            TYPE_ARRAY_PROCESS, FIELD_OFFSET(FILE_PROCESS_IDS_USING_FILE_INFORMATION, NumberOfProcessIdsInList)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileNetworkPhysicalNameInformationMembers[] =
{
    {_T("FileNameLength"),  TYPE_UINT32,  sizeof(ULONG)},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_NAME_INFORMATION, FileNameLength)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileNormalizedNameInformationMembers[] =
{
    {_T("FileNameLength"),  TYPE_UINT32,  sizeof(ULONG)},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_NAME_INFORMATION, FileNameLength)},
    {NULL, TYPE_NONE, 0}
};

TFlagInfo FileTxFlagsValues[] =
{
    FLAGINFO_BITV(FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_WRITELOCKED),
    FLAGINFO_BITV(FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_VISIBLE_TO_TX),
    FLAGINFO_BITV(FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_VISIBLE_OUTSIDE_TX),
    FLAGINFO_END()
};

TStructMember FileIdGlobalTxDirectoryInformationMembers[] =
{
    {_T("NextEntryOffset"), TYPE_UINT32,   sizeof(ULONG)},
    {_T("FileIndex"),       TYPE_UINT32,   sizeof(ULONG)},
    {_T("CreationTime"),    TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),  TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)FileAttributesValues}},
    {_T("FileNameLength"),  TYPE_UINT32,   sizeof(ULONG)},
    {_T("FileId"),          TYPE_FILEID64, sizeof(LARGE_INTEGER)},
    {_T("LockingTransactionId"), TYPE_GUID, sizeof(GUID)},
    {_T("TxInfoFlags"),     TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)FileTxFlagsValues}},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_ID_GLOBAL_TX_DIR_INFORMATION, FileNameLength)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileIsRemoteDeviceInformationMembers[] =
{
    {_T("IsRemote"),        TYPE_BOOLEAN,  sizeof(BOOLEAN)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileNumaNodeInformationMembers[] =
{
    {_T("NodeNumber"),      TYPE_UINT32,   sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileStandardLinkInformationMembers[] =
{
    {_T("NumberOfAccessibleLinks"), TYPE_UINT32,   sizeof(ULONG)},
    {_T("TotalNumberOfLinks"),      TYPE_UINT32,   sizeof(ULONG)},
    {_T("DeletePending"),           TYPE_BOOLEAN,  sizeof(BOOLEAN)},
    {_T("Directory"),               TYPE_BOOLEAN,  sizeof(BOOLEAN)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileRemoteProtocolInformationMembers[] =
{
    {_T("StructureVersion"), TYPE_UINT16,   sizeof(USHORT)},
    {_T("StructureSize"),    TYPE_UINT16,   sizeof(USHORT)},
    {_T("Protocol"),         TYPE_UINT32,   sizeof(ULONG)},
    {_T("ProtocolMajorVersion"), TYPE_UINT16,   sizeof(USHORT)},
    {_T("ProtocolMinorVersion"), TYPE_UINT16,   sizeof(USHORT)},
    {_T("ProtocolRevision"), TYPE_UINT16,   sizeof(USHORT)},
    {_T("Reserved"),         TYPE_UINT16,   sizeof(USHORT)},
    {_T("GenericReserved.Reserved[0x0]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("GenericReserved.Reserved[0x1]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("GenericReserved.Reserved[0x2]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("GenericReserved.Reserved[0x3]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("GenericReserved.Reserved[0x4]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("GenericReserved.Reserved[0x5]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("GenericReserved.Reserved[0x6]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("GenericReserved.Reserved[0x7]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0x0]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0x1]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0x2]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0x3]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0x4]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0x5]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0x6]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0x7]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0x8]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0x9]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0xA]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0xB]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0xC]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0xD]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0xE]"), TYPE_UINT32, sizeof(ULONG)},
    {_T("ProtocolReserved.Reserved[0xF]"), TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileVolumeNameInformationMembers[] =
{
    {_T("DeviceNameLength"),  TYPE_UINT32,     sizeof(ULONG)},
    {_T("DeviceName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_VOLUME_NAME_INFORMATION, DeviceNameLength)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileIdInformationMembers[] =
{
    {_T("VolumeSerialNumber"), TYPE_UINT64,     sizeof(LARGE_INTEGER)},
    {_T("FileId"),             TYPE_FILEID128,  sizeof(FILE_ID_128)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileIdExtdDirectoryInformationMembers[] =
{
    {_T("NextEntryOffset"), TYPE_UINT32,   sizeof(ULONG)},
    {_T("FileIndex"),       TYPE_UINT32,   sizeof(ULONG)},
    {_T("CreationTime"),    TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),  TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)FileAttributesValues}},
    {_T("FileNameLength"),  TYPE_UINT32,   sizeof(ULONG)},
    {_T("EaSize"),          TYPE_UINT32,   sizeof(ULONG)},
    {_T("ReparsePointTag"), TYPE_UINT32,   sizeof(ULONG)},
    {_T("FileId"),          TYPE_FILEID128, sizeof(FILE_ID_128)},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength)},
    {NULL}
};

TStructMember FileHardLinkFullIdInformationMembers[] =
{
    {_T("NextEntryOffset"), TYPE_UINT32,   sizeof(ULONG)},
    {_T("<alignment>"),     TYPE_UINT32,   sizeof(ULONG)},
    {_T("ParentFileId"),    TYPE_FILEID128, sizeof(FILE_ID_128)},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_LINK_ENTRY_FULL_ID_INFORMATION, FileNameLength)},
    {NULL}
};

TStructMember FileIdExtdBothDirectoryInformationMembers[] =
{
    {_T("NextEntryOffset"), TYPE_UINT32,   sizeof(ULONG)},
    {_T("FileIndex"),       TYPE_UINT32,   sizeof(ULONG)},
    {_T("CreationTime"),    TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),  TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)FileAttributesValues}},
    {_T("FileNameLength"),  TYPE_UINT32,   sizeof(ULONG)},
    {_T("EaSize"),          TYPE_UINT32,   sizeof(ULONG)},
    {_T("ReparsePointTag"), TYPE_UINT32,   sizeof(ULONG)},
    {_T("FileId"),          TYPE_FILEID128, sizeof(FILE_ID_128)},
    {_T("ShortNameLength"), TYPE_UINT8,      sizeof(BYTE)},       // Although CCHAR, it has 2 bytes because of alignment
    {_T("<padding>"),       TYPE_PADDING,    sizeof(WCHAR)},
    {_T("ShortName"),       TYPE_VNAME_FIEBD, sizeof(WCHAR[12])},
    {_T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileNameLength)},
    {NULL}
};

TFlagInfo FileDispositionInformationExValues[] = 
{
//  FLAGINFO_BITV(FILE_DISPOSITION_DO_NOT_DELETE),               // Zero; not an actual flag
    FLAGINFO_BITV(FILE_DISPOSITION_DELETE),
    FLAGINFO_BITV(FILE_DISPOSITION_POSIX_SEMANTICS),
    FLAGINFO_BITV(FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK),
    FLAGINFO_BITV(FILE_DISPOSITION_ON_CLOSE),
    FLAGINFO_BITV(FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE),
    FLAGINFO_END()
};

TStructMember FileDispositionInformationExMembers[] =
{
    { _T("DispositionFlags"),              TYPE_FLAG32, sizeof(ULONG), NULL, {(TStructMember *)FileDispositionInformationExValues}},
    { NULL, TYPE_NONE, 0 }
};

TFlagInfo FileRenameInformationExValues[] =
{
    FLAGINFO_BITV(FILE_RENAME_REPLACE_IF_EXISTS),
    FLAGINFO_BITV(FILE_RENAME_POSIX_SEMANTICS),
    FLAGINFO_BITV(FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE),
    FLAGINFO_BITV(FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERITANCE),
    FLAGINFO_BITV(FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE),
    FLAGINFO_BITV(FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE),
    FLAGINFO_BITV(FILE_RENAME_IGNORE_READONLY_ATTRIBUTE),
    FLAGINFO_BITV(FILE_RENAME_FORCE_RESIZE_TARGET_SR),
    FLAGINFO_BITV(FILE_RENAME_FORCE_RESIZE_SOURCE_SR),
    FLAGINFO_END()
};

TStructMember FileRenameInformationExMembers[] =
{
    { _T("Flags"),           TYPE_FLAG32,     sizeof(ULONG), NULL, {(TStructMember *)FileRenameInformationExValues}},
    { _T("<padding>"),       TYPE_PADDING,    sizeof(HANDLE) },
    { _T("RootDirectory"),   TYPE_DIR_HANDLE, sizeof(HANDLE) },
    { _T("FileNameLength"),  TYPE_UINT32,     sizeof(ULONG) },
    { _T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_RENAME_INFORMATION_EX, FileNameLength) },
    { NULL, TYPE_NONE, 0 }
};

TFlagInfo FileStorageClassValues[] =
{
    FLAGINFO_NUMV(FileStorageTierClassUnspecified),
    FLAGINFO_NUMV(FileStorageTierClassCapacity),
    FLAGINFO_NUMV(FileStorageTierClassPerformance),
    FLAGINFO_END()
};

TFlagInfo FileStorageFlagsValues[] =
{
    FLAGINFO_BITV(QUERY_STORAGE_CLASSES_FLAGS_MEASURE_WRITE),
    FLAGINFO_BITV(QUERY_STORAGE_CLASSES_FLAGS_MEASURE_READ),
    FLAGINFO_END()
};

TStructMember FileDesiredStorageClassInformationMembers[] =
{
    {_T("Class"),           TYPE_FLAG32,  sizeof(ULONG), NULL, {(TStructMember *)FileStorageClassValues}},
    {_T("Flags"),           TYPE_FLAG32,  sizeof(ULONG), NULL, {(TStructMember *)FileStorageFlagsValues}},
    { NULL }
};

TStructMember FileStatInformationMembers[] =
{
    {_T("FileId"),          TYPE_FILEID64, sizeof(LARGE_INTEGER)},
    {_T("CreationTime"),    TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),  TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)FileAttributesValues}},
    {_T("ReparseTag"),      TYPE_UINT32,   sizeof(ULONG)},
    {_T("NumberOfLinks"),   TYPE_UINT32,   sizeof(ULONG)},
    {_T("EffectiveAccess"), TYPE_FLAG32,   sizeof(ACCESS_MASK), NULL, {(TStructMember *)AccessMaskValues}},
    { NULL, TYPE_NONE, 0 }                                
};

TStructMember FileMemoryPartitionInformationMembers[] =
{
    {_T("OwnerPartitionHandle"), TYPE_HANDLE, sizeof(TYPE_HANDLE)},
    {_T("AllFlags"),        TYPE_UINT32,      sizeof(UINT32)},
    { NULL, TYPE_NONE, 0 }
};

TFlagInfo FileLxFlagsValues[] =
{
    FLAGINFO_BITV(LX_FILE_METADATA_HAS_UID),
    FLAGINFO_BITV(LX_FILE_METADATA_HAS_GID),
    FLAGINFO_BITV(LX_FILE_METADATA_HAS_MODE),
    FLAGINFO_BITV(LX_FILE_METADATA_HAS_DEVICE_ID),
    FLAGINFO_BITV(LX_FILE_CASE_SENSITIVE_DIR),
    FLAGINFO_END()
};

TStructMember FileStatLxInformationMembers[] =
{
    {_T("FileId"),          TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("CreationTime"),    TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastAccessTime"),  TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("LastWriteTime"),   TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("ChangeTime"),      TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("AllocationSize"),  TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("EndOfFile"),       TYPE_UINT64,   sizeof(LARGE_INTEGER)},
    {_T("FileAttributes"),  TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)FileAttributesValues}},
    {_T("ReparseTag"),      TYPE_UINT32,   sizeof(ULONG)},
    {_T("NumberOfLinks"),   TYPE_UINT32,   sizeof(ULONG)},
    {_T("AccessMask"),      TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)AccessMaskValues}},
    {_T("EffectiveAccess"), TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)AccessMaskValues}},
    {_T("LxFlags"),         TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)FileLxFlagsValues}},
    {_T("LxUid"),           TYPE_UINT32,   sizeof(ULONG)},
    {_T("LxGid"),           TYPE_UINT32,   sizeof(ULONG)},
    {_T("LxMode"),          TYPE_UINT32,   sizeof(ULONG)},
    {_T("LxDeviceIdMajor"), TYPE_UINT32,   sizeof(ULONG)},
    {_T("LxDeviceIdMinor"), TYPE_UINT32,   sizeof(ULONG)},
    { NULL, TYPE_NONE, 0 }
};

TStructMember FileCaseSensitiveInformationMembers[] =
{
    {_T("Flags"),           TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)CaseSensitiveFlags}},
    { NULL, TYPE_NONE, 0 }
};

TFlagInfo FileLinkInformationExValues[] =
{
    FLAGINFO_BITV(FILE_LINK_REPLACE_IF_EXISTS),
    FLAGINFO_BITV(FILE_LINK_POSIX_SEMANTICS),
    FLAGINFO_BITV(FILE_LINK_SUPPRESS_STORAGE_RESERVE_INHERITANCE),
    FLAGINFO_BITV(FILE_LINK_NO_INCREASE_AVAILABLE_SPACE),
    FLAGINFO_BITV(FILE_LINK_NO_DECREASE_AVAILABLE_SPACE),
    FLAGINFO_BITV(FILE_LINK_IGNORE_READONLY_ATTRIBUTE),
    FLAGINFO_BITV(FILE_LINK_FORCE_RESIZE_TARGET_SR),
    FLAGINFO_BITV(FILE_LINK_FORCE_RESIZE_SOURCE_SR),
    FLAGINFO_END()
};

TStructMember FileLinkInformationExMembers[] =
{
    {_T("Flags"),          TYPE_FLAG32,	    sizeof(ULONG), NULL, {(TStructMember *)FileLinkInformationExValues}},
	{_T("<padding>"),      TYPE_PADDING,    sizeof(HANDLE) },
    {_T("RootDirectory"),  TYPE_DIR_HANDLE, sizeof(HANDLE)},
    {_T("FileNameLength"), TYPE_UINT32,     sizeof(ULONG)},
    {_T("FileName"),       TYPE_WNAME_L32B, FIELD_OFFSET(FILE_LINK_INFORMATION, FileNameLength)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileStorageReserveIdInformationMembers[] =
{
    {_T("StorageReserveId"),    TYPE_UINT32,    sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TFlagInfo FileKnownFolderValues[] =
{
    FLAGINFO_NUMV(KnownFolderNone),
    FLAGINFO_NUMV(KnownFolderDesktop),
    FLAGINFO_NUMV(KnownFolderDocuments),
    FLAGINFO_NUMV(KnownFolderDownloads),
    FLAGINFO_NUMV(KnownFolderMusic),
    FLAGINFO_NUMV(KnownFolderPictures),
    FLAGINFO_NUMV(KnownFolderVideos),
    FLAGINFO_END()
};

TStructMember FileKnownFolderInformationMembers[] =
{
    {_T("Type"),    TYPE_FLAG32,   sizeof(ULONG), NULL, {(TStructMember *)FileKnownFolderValues}},
    {NULL, TYPE_NONE, 0}
};

#define FileAttributeCacheInformationMembers            FileUnknownInformationMembers
#define FileRenameInformationBypassAccessCheckMembers   FileRenameInformationMembers
#define FileLinkInformationBypassAccessCheckMembers     FileLinkInformationMembers
#define FileReplaceCompletionInformationMembers         FileCompletionInformationMembers
#define FileRenameInformationExBypassAccessCheckMembers FileRenameInformationExMembers
#define FileCaseSensitiveInformationBypassAccessCheckMembers FileCaseSensitiveInformationMembers
#define FileLinkInformationExBypassAccessCheckMembers   FileLinkInformationExMembers
#define FileCaseSensitiveInformationForceAccessCheckMembers  FileCaseSensitiveInformationMembers

TInfoData FileInfoData[] =                                                  
{
    FILE_INFO_READONLY(FileDirectoryInformation,                FILE_DIRECTORY_INFORMATION,                  TRUE),
    FILE_INFO_READONLY(FileFullDirectoryInformation,            FILE_FULL_DIR_INFORMATION,                   TRUE),
    FILE_INFO_READONLY(FileBothDirectoryInformation,            FILE_BOTH_DIR_INFORMATION,                   TRUE),
    FILE_INFO_EDITABLE(FileBasicInformation,                    FILE_BASIC_INFORMATION,                      FALSE),
    FILE_INFO_EDITABLE(FileStandardInformation,                 FILE_STANDARD_INFORMATION,                   FALSE),
    FILE_INFO_EDITABLE(FileInternalInformation,                 FILE_INTERNAL_INFORMATION,                   FALSE),
    FILE_INFO_EDITABLE(FileEaInformation,                       FILE_EA_INFORMATION,                         FALSE),
    FILE_INFO_EDITABLE(FileAccessInformation,                   FILE_ACCESS_INFORMATION,                     FALSE),
    FILE_INFO_READONLY(FileNameInformation,                     FILE_NAME_INFORMATION,                       FALSE),
    FILE_INFO_EDITABLE(FileRenameInformation,                   FILE_RENAME_INFORMATION,                     FALSE),
    FILE_INFO_EDITABLE(FileLinkInformation,                     FILE_LINK_INFORMATION,                       FALSE),
    FILE_INFO_READONLY(FileNamesInformation,                    FILE_NAMES_INFORMATION,                      TRUE),
    FILE_INFO_EDITABLE(FileDispositionInformation,              FILE_DISPOSITION_INFORMATION,                FALSE),
    FILE_INFO_EDITABLE(FilePositionInformation,                 FILE_POSITION_INFORMATION,                   FALSE),
    FILE_INFO_READONLY(FileFullEaInformation,                   FILE_FULL_EA_INFORMATION,                    TRUE),
    FILE_INFO_EDITABLE(FileModeInformation,                     FILE_MODE_INFORMATION,                       FALSE),
    FILE_INFO_EDITABLE(FileAlignmentInformation,                FILE_ALIGNMENT_INFORMATION,                  FALSE),
    FILE_INFO_READONLY(FileAllInformation,                      FILE_ALL_INFORMATION,                        FALSE),
    FILE_INFO_EDITABLE(FileAllocationInformation,               FILE_ALLOCATION_INFORMATION,                 FALSE),
    FILE_INFO_EDITABLE(FileEndOfFileInformation,                FILE_END_OF_FILE_INFORMATION,                FALSE),
    FILE_INFO_READONLY(FileAlternateNameInformation,            FILE_NAME_INFORMATION,                       FALSE),
    FILE_INFO_READONLY(FileStreamInformation,                   FILE_STREAM_INFORMATION,                     TRUE),
    FILE_INFO_EDITABLE(FilePipeInformation,                     FILE_PIPE_INFORMATION,                       FALSE),
    FILE_INFO_EDITABLE(FilePipeLocalInformation,                FILE_PIPE_LOCAL_INFORMATION,                 FALSE),
    FILE_INFO_EDITABLE(FilePipeRemoteInformation,               FILE_PIPE_REMOTE_INFORMATION,                FALSE),
    FILE_INFO_EDITABLE(FileMailslotQueryInformation,            FILE_MAILSLOT_QUERY_INFORMATION,             FALSE),
    FILE_INFO_EDITABLE(FileMailslotSetInformation,              FILE_MAILSLOT_SET_INFORMATION,               FALSE),
    FILE_INFO_EDITABLE(FileCompressionInformation,              FILE_COMPRESSION_INFORMATION,                FALSE),
    FILE_INFO_READONLY(FileObjectIdInformation,                 FILE_OBJECTID_INFORMATION,                   FALSE),
    FILE_INFO_EDITABLE(FileCompletionInformation,               FILE_COMPLETION_INFORMATION,                 FALSE),
    FILE_INFO_EDITABLE(FileMoveClusterInformation,              FILE_MOVE_CLUSTER_INFORMATION,               FALSE),
    FILE_INFO_READONLY(FileQuotaInformation,                    FILE_QUOTA_INFORMATION,                      TRUE),
    FILE_INFO_EDITABLE(FileReparsePointInformation,             FILE_REPARSE_POINT_INFORMATION,              FALSE),
    FILE_INFO_EDITABLE(FileNetworkOpenInformation,              FILE_NETWORK_OPEN_INFORMATION,               FALSE),
    FILE_INFO_EDITABLE(FileAttributeTagInformation,             FILE_ATTRIBUTE_TAG_INFORMATION,              FALSE),
    FILE_INFO_EDITABLE(FileTrackingInformation,                 FILE_TRACKING_INFORMATION,                   FALSE),
    FILE_INFO_READONLY(FileIdBothDirectoryInformation,          FILE_ID_BOTH_DIR_INFORMATION,                TRUE),
    FILE_INFO_READONLY(FileIdFullDirectoryInformation,          FILE_ID_FULL_DIR_INFORMATION,                TRUE),
    FILE_INFO_EDITABLE(FileValidDataLengthInformation,          FILE_VALID_DATA_LENGTH_INFORMATION,          FALSE),
    FILE_INFO_EDITABLE(FileShortNameInformation,                FILE_NAME_INFORMATION,                       FALSE),
    FILE_INFO_EDITABLE(FileIoCompletionNotificationInformation, FILE_IO_COMPLETION_NOTIFICATION_INFORMATION, FALSE),
    FILE_INFO_EDITABLE(FileIoStatusBlockRangeInformation,       FILE_IOSTATUSBLOCK_RANGE_INFORMATION,        FALSE),
    FILE_INFO_EDITABLE(FileIoPriorityHintInformation,           FILE_IO_PRIORITY_HINT_INFORMATION,           FALSE),
    FILE_INFO_EDITABLE(FileSfioReserveInformation,              FILE_SFIO_RESERVE_INFORMATION,               FALSE),
    FILE_INFO_READONLY(FileSfioVolumeInformation,               FILE_SFIO_VOLUME_INFORMATION,                FALSE),
    FILE_INFO_READONLY(FileHardLinkInformation,                 FILE_LINKS_INFORMATION,                      FALSE),
    FILE_INFO_READONLY(FileProcessIdsUsingFileInformation,      FILE_PROCESS_IDS_USING_FILE_INFORMATION,     FALSE),
    FILE_INFO_READONLY(FileNormalizedNameInformation,           FILE_NORMALIZED_NAME_INFORMATION,            FALSE),
    FILE_INFO_READONLY(FileNetworkPhysicalNameInformation,      FILE_NETWORK_PHYSICAL_NAME_INFORMATION,      FALSE),
    FILE_INFO_READONLY(FileIdGlobalTxDirectoryInformation,      FILE_ID_GLOBAL_TX_DIRECTORY_INFORMATION,     TRUE),
    FILE_INFO_READONLY(FileIsRemoteDeviceInformation,           FILE_IS_REMOTE_DEVICE_INFORMATION,           FALSE),
    FILE_INFO_READONLY(FileAttributeCacheInformation,           FILE_ATTRIBUTE_CACHE_INFORMATION,            FALSE),
    FILE_INFO_READONLY(FileNumaNodeInformation,                 FILE_NUMA_NODE_INFORMATION,                  FALSE),
    FILE_INFO_READONLY(FileStandardLinkInformation,             FILE_STANDARD_LINK_INFORMATION,              FALSE),
    FILE_INFO_READONLY(FileRemoteProtocolInformation,           FILE_REMOTE_PROTOCOL_INFORMATION,            FALSE),
    FILE_INFO_EDITABLE(FileRenameInformationBypassAccessCheck,  FILE_RENAME_INFORMATION,                     FALSE),
    FILE_INFO_EDITABLE(FileLinkInformationBypassAccessCheck,    FILE_LINK_INFORMATION,                       FALSE),
    FILE_INFO_READONLY(FileVolumeNameInformation,               FILE_VOLUME_NAME_INFORMATION,                FALSE),
    FILE_INFO_READONLY(FileIdInformation,                       FILE_ID_INFORMATION,                         FALSE),
    FILE_INFO_READONLY(FileIdExtdDirectoryInformation,          FILE_ID_EXTD_DIR_INFORMATION,                TRUE),
    FILE_INFO_EDITABLE(FileReplaceCompletionInformation,        FILE_COMPLETION_INFORMATION,                 FALSE),
    FILE_INFO_READONLY(FileHardLinkFullIdInformation,           FILE_LINK_ENTRY_FULL_ID_INFORMATION,         TRUE),
    FILE_INFO_READONLY(FileIdExtdBothDirectoryInformation,      FILE_ID_EXTD_BOTH_DIR_INFORMATION,           TRUE),
    FILE_INFO_EDITABLE(FileDispositionInformationEx,            FILE_DISPOSITION_INFORMATION_EX,             FALSE),
    FILE_INFO_EDITABLE(FileRenameInformationEx,                 FILE_RENAME_INFORMATION_EX,                  FALSE),
    FILE_INFO_EDITABLE(FileRenameInformationExBypassAccessCheck,FILE_RENAME_INFORMATION_EX,                  FALSE),
    FILE_INFO_EDITABLE(FileDesiredStorageClassInformation,      FILE_DESIRED_STORAGE_CLASS_INFORMATION,      FALSE),
    FILE_INFO_READONLY(FileStatInformation,                     FILE_STAT_INFORMATION,                       FALSE),
    FILE_INFO_EDITABLE(FileMemoryPartitionInformation,          FILE_MEMORY_PARTITION_INFORMATION,           FALSE),
    FILE_INFO_READONLY(FileStatLxInformation,                   FILE_STAT_LX_INFORMATION,                    FALSE),
    FILE_INFO_EDITABLE(FileCaseSensitiveInformation,            FILE_CASE_SENSITIVE_INFORMATION,             FALSE),
    FILE_INFO_EDITABLE(FileLinkInformationEx,                   FILE_LINK_INFORMATION_EX,                    FALSE),
    FILE_INFO_EDITABLE(FileLinkInformationExBypassAccessCheck,  FILE_LINK_INFORMATION_EX,                    FALSE),
    FILE_INFO_EDITABLE(FileStorageReserveIdInformation,         FILE_SET_STORAGE_RESERVE_ID_INFORMATION,     FALSE),
    FILE_INFO_EDITABLE(FileCaseSensitiveInformationForceAccessCheck, FILE_CASE_SENSITIVE_INFORMATION,        FALSE),
    FILE_INFO_EDITABLE(FileKnownFolderInformation,              FILE_KNOWN_FOLDER_INFORMATION,               FALSE),
    FILE_INFO_EDITABLE(FileStatBasicInformation,                FILE_KNOWN_FOLDER_INFORMATION,               FALSE),

	FILE_INFO_READONLY(FileId64ExtdDirectoryInformation,        FILE_ID_64_EXTD_DIR_INFORMATION,             TRUE),
    FILE_INFO_READONLY(FileId64ExtdBothDirectoryInformation,    FILE_ID_64_EXTD_BOTH_DIR_INFORMATION,        TRUE),
    FILE_INFO_READONLY(FileIdAllExtdDirectoryInformation,       FILE_ID_ALL_EXTD_DIR_INFORMATION,            TRUE),
    FILE_INFO_READONLY(FileIdAllExtdBothDirectoryInformation,   FILE_ID_ALL_EXTD_BOTH_DIR_INFORMATION,       TRUE),

    {FileMaximumInformation}                                                                                 
};

//-----------------------------------------------------------------------------
// Description of data structures for FS info classes

TStructMember FileFsVolumeInformationMembers[] =
{   
    {_T("VolumeCreationTime"), TYPE_FILETIME, sizeof(LARGE_INTEGER)},
    {_T("VolumeSerialNumber"), TYPE_UINT32, sizeof(ULONG)},
    {_T("VolumeLabelLength"),  TYPE_UINT32, sizeof(ULONG)},
    {_T("SupportsObjects"),    TYPE_BOOLEAN, sizeof(WCHAR)},        // Aligned to 2
    {_T("VolumeLabel"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabelLength)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileFsLabelInformationMembers[] =
{   
    {_T("VolumeLabelLength"),  TYPE_UINT32,  sizeof(ULONG)},
    {_T("VolumeLabel"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_FS_LABEL_INFORMATION, VolumeLabelLength)},
    {NULL, TYPE_NONE, 0}
};


TStructMember FileFsSizeInformationMembers[] =
{   
    {_T("TotalAllocationUnits"),        TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("AvailableAllocationUnits"),    TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("SectorsPerAllocationUnit"),    TYPE_UINT32, sizeof(ULONG)},
    {_T("BytesPerSector"),              TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TFlagInfo FileDeviceCharacteristicsValues[] =
{
    FLAGINFO_BITV(FILE_REMOVABLE_MEDIA),
    FLAGINFO_BITV(FILE_READ_ONLY_DEVICE),
    FLAGINFO_BITV(FILE_FLOPPY_DISKETTE),
    FLAGINFO_BITV(FILE_WRITE_ONCE_MEDIA),
    FLAGINFO_BITV(FILE_REMOTE_DEVICE),
    FLAGINFO_BITV(FILE_DEVICE_IS_MOUNTED),
    FLAGINFO_BITV(FILE_VIRTUAL_VOLUME),
    FLAGINFO_BITV(FILE_AUTOGENERATED_DEVICE_NAME),
    FLAGINFO_BITV(FILE_DEVICE_SECURE_OPEN),
    FLAGINFO_BITV(FILE_CHARACTERISTIC_PNP_DEVICE),
    FLAGINFO_BITV(FILE_CHARACTERISTIC_TS_DEVICE),
    FLAGINFO_BITV(FILE_CHARACTERISTIC_WEBDAV_DEVICE),
    FLAGINFO_BITV(FILE_CHARACTERISTIC_CSV),
    FLAGINFO_BITV(FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL),
    FLAGINFO_BITV(FILE_PORTABLE_DEVICE),
    FLAGINFO_BITV(FILE_REMOTE_DEVICE_VSMB),
    FLAGINFO_BITV(FILE_DEVICE_REQUIRE_SECURITY_CHECK),
    FLAGINFO_END()
};

TStructMember FileFsDeviceInformationMembers[] =
{   
    {_T("DeviceType"),           TYPE_UINT32, sizeof(ULONG)},
    {_T("Characteristics"),      TYPE_FLAG32, sizeof(ULONG), NULL, {(TStructMember *)FileDeviceCharacteristicsValues}},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileFsAttributeInformationMembers[] =
{   
    {_T("FileSystemAttributes"),       TYPE_FLAG32, sizeof(ULONG), NULL, {(TStructMember *)FileSystemAttributesValues}},
    {_T("MaximumComponentNameLength"), TYPE_UINT32, sizeof(ULONG)},
    {_T("FileSystemNameLength"),       TYPE_UINT32, sizeof(ULONG)},
    {_T("FileSystemName"),             TYPE_WNAME_L32B, FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemNameLength)},
    {NULL, TYPE_NONE, 0}
};

TFlagInfo FileSystemControlFlagValues[] =
{
    FLAGINFO_BITV(FILE_VC_QUOTA_TRACK),
    FLAGINFO_BITV(FILE_VC_QUOTA_ENFORCE),
    FLAGINFO_BITV(FILE_VC_CONTENT_INDEX_DISABLED),
    FLAGINFO_BITV(FILE_VC_LOG_QUOTA_THRESHOLD),
    FLAGINFO_BITV(FILE_VC_LOG_QUOTA_LIMIT),
    FLAGINFO_BITV(FILE_VC_LOG_VOLUME_THRESHOLD),
    FLAGINFO_BITV(FILE_VC_LOG_VOLUME_LIMIT),
    FLAGINFO_BITV(FILE_VC_QUOTAS_INCOMPLETE),
    FLAGINFO_BITV(FILE_VC_QUOTAS_REBUILDING),
    FLAGINFO_END()
};

TStructMember FileFsControlInformationMembers[] =
{   
    {_T("FreeSpaceStartFiltering"),    TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("FreeSpaceThreshold"),         TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("FreeSpaceStopFiltering"),     TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("DefaultQuotaThreshold"),      TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("DefaultQuotaLimit"),          TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("FileSystemControlFlags"),     TYPE_FLAG32, sizeof(ULONG), NULL, {(TStructMember *)FileSystemControlFlagValues}},
    {NULL, TYPE_NONE, 0}
};


TStructMember FileFsFullSizeInformationMembers[] =
{   
    {_T("TotalAllocationUnits"),           TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("CallerAvailableAllocationUnits"), TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("ActualAvailableAllocationUnits"), TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("SectorsPerAllocationUnit"),       TYPE_UINT32, sizeof(ULONG)},
    {_T("BytesPerSector"),                 TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};


TStructMember FileFsObjectIdInformationMembers[] =
{   
    {_T("ObjectId"),     TYPE_GUID,         sizeof(UCHAR[16])},
    {_T("ExtendedInfo"), TYPE_ARRAY8_FIXED, sizeof(UCHAR[48])},
    {NULL, TYPE_NONE, 0}
};


TStructMember FileFsDriverPathInformationMembers[] =
{   
    {_T("DriverInPath"),     TYPE_BOOLEAN, sizeof(ULONG)},
    {_T("DriverNameLength"), TYPE_UINT32,  sizeof(ULONG)},
    {_T("DriverName"),       TYPE_WNAME_L32B, FIELD_OFFSET(FILE_FS_DRIVER_PATH_INFORMATION, DriverNameLength)},
    {NULL, TYPE_NONE, 0}
};


TStructMember FileFsVolumeFlagsInformationMembers[] =
{   
    {_T("Flags"),            TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TFlagInfo FileSystemSectorFlagValues[] =
{
    FLAGINFO_BITV(SSINFO_FLAGS_ALIGNED_DEVICE),
    FLAGINFO_BITV(SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE),
    FLAGINFO_BITV(SSINFO_FLAGS_NO_SEEK_PENALTY),
    FLAGINFO_BITV(SSINFO_FLAGS_TRIM_ENABLED),
    FLAGINFO_BITV(SSINFO_FLAGS_BYTE_ADDRESSABLE),
    FLAGINFO_END()
};

TStructMember FileFsSectorSizeInformationMembers[] =
{   
    {_T("LogicalBytesPerSector"),               TYPE_UINT32, sizeof(ULONG)},
    {_T("PhysicalBytesPerSectorForAtomicity"),  TYPE_UINT32, sizeof(ULONG)},
    {_T("PhysicalBytesPerSectorForPerformance"), TYPE_UINT32, sizeof(ULONG)},
    {_T("FileSystemEffectivePhysicalBytesPerSectorForAtomicity"), TYPE_UINT32, sizeof(ULONG)},
    {_T("Flags"),                               TYPE_FLAG32, sizeof(ULONG), NULL, {(TStructMember *)FileSystemSectorFlagValues}},
    {_T("ByteOffsetForSectorAlignment"),        TYPE_UINT32, sizeof(ULONG)},
    {_T("ByteOffsetForPartitionAlignment"),     TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileFsDataCopyInformationMembers[] =
{
    {_T("NumberOfCopies"),               TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileFsMetadataSizeInformationMembers[] =
{
    {_T("TotalMetadataAllocationUnits"), TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("SectorsPerAllocationUnit"),     TYPE_UINT32, sizeof(ULONG)},
    {_T("BytesPerSector"),               TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileFsFullSizeInformationExMembers[] =
{
    {_T("ActualTotalAllocationUnits"),           TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("ActualAvailableAllocationUnits"),       TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("ActualPoolUnavailableAllocationUnits"), TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("CallerTotalAllocationUnits"),           TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("CallerAvailableAllocationUnits"),       TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("CallerPoolUnavailableAllocationUnits"), TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("UsedAllocationUnits"),                  TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("TotalReservedAllocationUnits"),         TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("VolumeStorageReserveAllocationUnits"),  TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("AvailableCommittedAllocationUnits"),    TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("PoolAvailableAllocationUnits"),         TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("SectorsPerAllocationUnit"),             TYPE_UINT32, sizeof(ULONG)},
    {_T("BytesPerSector"),                       TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TInfoData FsInfoData[] = 
{
    FILE_INFO_EDITABLE(FileFsVolumeInformation,        FILE_FS_VOLUME_INFORMATION,           FALSE),
    FILE_INFO_EDITABLE(FileFsLabelInformation,         FILE_FS_LABEL_INFORMATION,            FALSE),
    FILE_INFO_EDITABLE(FileFsSizeInformation,          FILE_FS_SIZE_INFORMATION,             FALSE),
    FILE_INFO_EDITABLE(FileFsDeviceInformation,        FILE_FS_DEVICE_INFORMATION,           FALSE),
    FILE_INFO_EDITABLE(FileFsAttributeInformation,     FILE_FS_ATTRIBUTE_INFORMATION,        FALSE),
    FILE_INFO_EDITABLE(FileFsControlInformation,       FILE_FS_CONTROL_INFORMATION,          FALSE),
    FILE_INFO_EDITABLE(FileFsFullSizeInformation,      FILE_FS_FULL_SIZE_INFORMATION,        FALSE),
    FILE_INFO_EDITABLE(FileFsObjectIdInformation,      FILE_FS_OBJECTID_INFORMATION,         FALSE),
    FILE_INFO_EDITABLE(FileFsDriverPathInformation,    FILE_FS_DRIVER_PATH_INFORMATION,      FALSE),
    FILE_INFO_EDITABLE(FileFsVolumeFlagsInformation,   FILE_FS_VOLUME_FLAGS_INFORMATION,     FALSE),
    FILE_INFO_EDITABLE(FileFsSectorSizeInformation,    FILE_FS_SECTOR_SIZE_INFORMATION,      FALSE),
    FILE_INFO_EDITABLE(FileFsDataCopyInformation,      FILE_FS_DATA_COPY_INFORMATION,        FALSE),
    FILE_INFO_EDITABLE(FileFsMetadataSizeInformation,  FILE_FS_METADATA_SIZE_INFORMATION,    FALSE),
    FILE_INFO_EDITABLE(FileFsFullSizeInformationEx,    FILE_FS_FULL_SIZE_INFORMATION_EX,     FALSE),
    {FileFsMaximumInformation}
};

#define InitialFileInfo FileBasicInformation
#define InitialFsInfo FileFsVolumeInformation

//-----------------------------------------------------------------------------
// Tooltip variables

static UINT_PTR nTimerTooltip = 0;
static HANDLE hDirTarget = NULL;
static HWND hToolTip = NULL;

//-----------------------------------------------------------------------------
// Forward definitions

static int FillStructMembersChained(
    HWND hTreeView,
    HTREEITEM hParentItem,
    TStructMember * pMembers,
    LPBYTE pbData,
    LPBYTE pbDataEnd
    );

//-----------------------------------------------------------------------------
// Conversion functions

#define NEXT_ENTRY_OFFSET_ATRIFICIAL    0x80000000

typedef struct _CHAINED_ENTRY
{
    ULONG NextEntryOffset;
} CHAINED_ENTRY, *PCHAINED_ENTRY;

static PCHAINED_ENTRY DirEntry_Find(LPBYTE PtrEntry, ULONG_PTR DataLength)
{
    PCHAINED_ENTRY DirEntry = (PCHAINED_ENTRY)PtrEntry;
    LPBYTE EndEntry = PtrEntry + DataLength;

    while(DirEntry->NextEntryOffset != 0 && PtrEntry < EndEntry)
    {
        PtrEntry = PtrEntry + DirEntry->NextEntryOffset;
        DirEntry = (PCHAINED_ENTRY)PtrEntry;
    }
    return DirEntry;
}

static void DirEntry_Mark(PCHAINED_ENTRY LastEntry, LPBYTE pbDataPtr)
{
    LPBYTE pbLastEntry = (LPBYTE)LastEntry;

    // At this point, the last entry's "next" offset should be zero
    assert(LastEntry->NextEntryOffset == 0);
    assert(pbDataPtr > pbLastEntry);

    // Set the last entry's offset to the next item.
    LastEntry->NextEntryOffset = NEXT_ENTRY_OFFSET_ATRIFICIAL | (ULONG)(pbDataPtr - pbLastEntry);
}

static int GetAlignedDataLength(LPBYTE pbStructPtr, LPBYTE pbData, int nTypeSize, int nAlignmentSize)
{
    int nCurrentOffset = (int)(pbData - pbStructPtr);
    int nAlignMask = nAlignmentSize - 1;
    int nAlignedSize = (nTypeSize + nAlignMask) & ~nAlignMask;

    return nAlignedSize - (nCurrentOffset & nAlignMask);
}

static LPTSTR AStringToItemText(
    LPTSTR szBuffer,
    LPTSTR szEndChar,
    LPSTR VarString,
    ULONG LengthInBytes,
    BOOL bTextForEdit)
{
    size_t nNameLength = LengthInBytes / sizeof(CHAR);

    // Include the preceding quotas, if necessary
    if(!bTextForEdit && szEndChar > szBuffer)
        *szBuffer++ = _T('\"');

    // Copy the string itself
    for(ULONG i = 0; i < nNameLength; i++)
    {
        if(szEndChar > szBuffer)
            *szBuffer++ = *VarString++;
    }

    // Close the string with quotas, if needed
    if(!bTextForEdit && szEndChar > szBuffer)
        *szBuffer++ = _T('\"');

    *szBuffer = 0;
    return szBuffer;
}

static LPTSTR WStringToItemText(
    LPTSTR szBuffer,
    LPTSTR szEndChar,
    LPWSTR VarString,
    ULONG LengthInBytes,
    BOOL bTextForEdit)
{
    size_t nNameLength;

    // The file name can't be longer than MAX_USHORT
    if(LengthInBytes > 0xFFFE)
        LengthInBytes = 0xFFFE;
    nNameLength = LengthInBytes / sizeof(WCHAR);

    // Include the preceding quotas, if necessary
    if(!bTextForEdit && szEndChar > szBuffer)
        *szBuffer++ = _T('\"');

    // Copy the string itself
    for(size_t i = 0; i < nNameLength; i++)
    {
        if(szEndChar > szBuffer)
            *szBuffer++ = *VarString++;
    }

    // Include the terminating quotation mark, if necessary
    // and terminate the string with zero
    if(!bTextForEdit && szEndChar > szBuffer)
        *szBuffer++ = _T('\"');
    *szBuffer = 0;

    return szBuffer;
}

static LPTSTR CreateFullName(LPCTSTR szDirectory, LPCWSTR szPlainName, ULONG cbPlainName)
{
    LPTSTR szFileName;
    LPTSTR szFilePtr;
    size_t cchDirectory = _tcslen(szDirectory);
    size_t cchLength;

    // Allocate buffer
    cchLength = cchDirectory + 1 + (cbPlainName / sizeof(WCHAR)) + 1; 
    szFileName = szFilePtr = new TCHAR[cchLength];
    if(szFileName != NULL)
    {
        // Do we need a backslash?
        if(cchDirectory > 0)
        {
            // Copy the directory name
            memcpy(szFilePtr, szDirectory, cchDirectory * sizeof(TCHAR));
            szFilePtr += cchDirectory;

            // Add backslash if needed
            if(szFilePtr[-1] != _T('\\'))
                *szFilePtr++ = _T('\\');
        }

        // Copy the plain name
        memcpy(szFilePtr, szPlainName, cbPlainName);
        szFilePtr[cbPlainName / sizeof(TCHAR)] = 0;
    }
    
    return szFileName;
}

static void FillComboBoxFiltered(HWND hWndCombo, TInfoData * pInfoList, LPCTSTR szFilterText)
{
    TCHAR szItemText[256];

    // Disable redrawing and remove all items
    EnableRedraw(hWndCombo, FALSE);
    
    // Delete all items
    while(ComboBox_DeleteString(hWndCombo, 0) > 0);

    // Fill the combo box
    while(pInfoList->szInfoClass != NULL)
    {
        // Convert the string to uppercase
        StringCchCopy(szItemText, _countof(szItemText), pInfoList->szInfoClass);
        CharUpper(szItemText);

        // If the item contains the substring, include it in the list
        if(_tcsstr(szItemText, szFilterText))
            ComboBox_AddString(hWndCombo, pInfoList->szInfoClass);

        // Move to the next item
        pInfoList++;
    }

    // Enable redrawing and redraw
    EnableRedraw(hWndCombo);
}
/*
static int SearchItemList(TInfoData * pInfoList, LPCTSTR szEditText, int nTextLength, int * piSelStart)
{
    TInfoData * pInfoItem;

    // Search the list, try to find the text from the beginning of the item
    for(pInfoItem = pInfoList; pInfoItem->szInfoClass != NULL; pInfoItem++)
    {
        // Does the begin of the item match?
        if(!_tcsnicmp(pInfoItem->szInfoClass, szEditText, nTextLength))
        {
            *piSelStart = nTextLength;
            return (int)(pInfoItem - pInfoList);
        }
    }

    // Search the list, try to find the text with "File" prefix
    for(pInfoItem = pInfoList; pInfoItem->szInfoClass != NULL; pInfoItem++)
    {
        LPCTSTR szItemText = pInfoItem->szInfoClass;

        // Compare all words in the item text
        while(szItemText[0] != 0)
        {
            // Skip the word
            szItemText++;
            while(szItemText[0] != 0 && IsCharUpper(szItemText[0]) == FALSE)
                szItemText++;

            // Does the begin of the word match?
            if(szItemText[0] != 0 && _tcsnicmp(szItemText, szEditText, nTextLength) == 0)
            {
                *piSelStart = (int)(szItemText - pInfoItem->szInfoClass) + nTextLength;
                return (int)(pInfoItem - pInfoList);
            }
        }
    }
        
    return -1;
}
*/

static NTSTATUS TextToDirHandle(LPCTSTR szText, PHANDLE phHandle)
{
    OBJECT_ATTRIBUTES ObjAttr;
    UNICODE_STRING FileName = {0, 0, NULL};
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;
    HANDLE FileHandle = NULL;

    // If we already have a directory handle, close it
    if(IsHandleValid(hDirTarget))
        NtClose(hDirTarget);
    hDirTarget = NULL;

    // Convert the file name to NT name
    InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = FileNameToUnicodeString(&FileName, szText);

    // Open the file/directory
    if(NT_SUCCESS(Status))
    {
        Status = NtOpenFile(&FileHandle,
                             FILE_WRITE_DATA,
                            &ObjAttr,
                            &IoStatus,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             0);
    }

    // Now put the handle to the target
    if(NT_SUCCESS(Status))
    {
        hDirTarget = FileHandle;
        *phHandle = FileHandle;
    }

    return Status;
}

static LPTSTR FileIDToFileName(
    LPCTSTR szVolumeName,
    PVOID pvFileID,
    ULONG cbFileID)
{
    PFILE_NAME_INFORMATION pFileInfo = NULL;
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING DeviceName;
    UNICODE_STRING FileName;
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE VolumeHandle = NULL;
    HANDLE FileHandle = NULL;
    LPTSTR szFileName = NULL;
    BYTE FileInfoBuff[0x400];

    // Sanity check
    assert(cbFileID == sizeof(ULONGLONG));

    // Prepare the native name of the volume
    Status = FileNameToUnicodeString(&DeviceName, szVolumeName);

    // Open the volume
    if(NT_SUCCESS(Status))
    {
        // Make the OBJECT_ATTRIBUTES structure
        InitializeObjectAttributes(&ObjAttr, &DeviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        // Now try to open the volume/directory/file
        // Use FILE_READ_ATTRIBUTES as the desired access;
        // this allows us to bypass sharing violations
        Status = NtCreateFile(&VolumeHandle,
                               FILE_READ_ATTRIBUTES,    //FILE_READ_DATA,
                              &ObjAttr,
                              &IoStatus,
                               NULL,
                               FILE_ATTRIBUTE_NORMAL,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               FILE_OPEN,
                               0,
                               NULL,
                               0);
    }

    // Prepare opening the file
    if(NT_SUCCESS(Status))
    {
        InitializeObjectAttributes(&ObjAttr, &FileName, OBJ_CASE_INSENSITIVE, VolumeHandle, NULL);
        FileName.MaximumLength =
        FileName.Length = (USHORT)cbFileID;
        FileName.Buffer = (PWSTR)pvFileID;
        Status = NtOpenFile(&FileHandle,
                             FILE_READ_ATTRIBUTES,
                            &ObjAttr,
                            &IoStatus,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_OPEN_BY_FILE_ID | FILE_OPEN_REPARSE_POINT);
    }

    // Query the file name
    if(NT_SUCCESS(Status))
    {
        pFileInfo = (PFILE_NAME_INFORMATION)FileInfoBuff;
        memset(pFileInfo, 0, sizeof(FileInfoBuff));
        Status = NtQueryInformationFile(FileHandle,
                                       &IoStatus,
                                        pFileInfo,
                                        sizeof(FileInfoBuff),
                                        FileNameInformation);
    }

    // Allocate the file name
    if(NT_SUCCESS(Status))
    {
        // Copy the volume-relative file name
        szFileName = new TCHAR[(pFileInfo->FileNameLength / 2) + 1];
        if(szFileName != NULL)
        {
            memcpy(szFileName, pFileInfo->FileName, pFileInfo->FileNameLength);
            szFileName[pFileInfo->FileNameLength / 2] = 0;
        }
    }

    // Close handles
    if(FileHandle != NULL)
        NtClose(FileHandle);
    if(VolumeHandle != NULL)
        NtClose(VolumeHandle);
    FreeFileNameString(&DeviceName);
    return szFileName;
}

static int DataToItemText(TStructMember * pMember, LPTSTR szBuffer, size_t nMaxChars, BOOL bTextForEdit)
{
    LPTSTR szEndChar = szBuffer + nMaxChars - 1;

    // If there is not even space for ending zero, do nothing
    if(nMaxChars == 0)
        return 0;

    // Insert "MemberName: " prefix
    if(bTextForEdit == FALSE)
    {
        StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("%s: "), pMember->szMemberName);
    }

    // Now insert the member value
    switch(pMember->nDataType)
    {
        case TYPE_BOOLEAN:
        {
            LPCTSTR szBoolean = (*(PBOOLEAN)(pMember->pbDataPtr)) ? _T("TRUE") : _T("FALSE");

            StringCchCopyEx(szBuffer, (szEndChar - szBuffer), szBoolean, &szBuffer, NULL, 0);
            break;
        }

        case TYPE_UINT8:
        {
            PUCHAR pucValue = (PUCHAR)pMember->pbDataPtr;

            StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("0x%02lX"), *pucValue);
            break;
        }

        case TYPE_UINT16:
        {
            PUSHORT pusValue = (PUSHORT)pMember->pbDataPtr;

            StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("0x%04lX"), *pusValue);
            break;
        }

        case TYPE_UINT32:
        {
            PULONG pulValue = (PULONG)pMember->pbDataPtr;

            StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("0x%08lX"), *pulValue);
            break;
        }

        case TYPE_UINT64:
        {
            PLARGE_INTEGER pliValue = (PLARGE_INTEGER)pMember->pbDataPtr;

            StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("%08lX-%08lX"), pliValue->HighPart, pliValue->LowPart);
            break;
        }

        case TYPE_FILEID128:
        {
            PLARGE_INTEGER pliValue = (PLARGE_INTEGER)pMember->pbDataPtr;

            StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("%016I64X-%016I64X"), pliValue[1].QuadPart, pliValue[0].QuadPart);
            break;
        }

        case TYPE_ARRAY8_FIXED:
        {
            LPBYTE pbData = (LPBYTE)pMember->pbDataPtr;

            if(szEndChar > szBuffer)
                *szBuffer++ = _T('"');

            for(UINT i = 0; i < pMember->nMemberSize; i++)
            {
                StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("%02lX "), *pbData++);
            }

            if(szEndChar > szBuffer)
                *szBuffer++ = _T('"');
            break;
        }

        case TYPE_HANDLE:
        case TYPE_POINTER:
        {
            PHANDLE phHandle = (PHANDLE)pMember->pbDataPtr;

            StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("%p"), *phHandle);
            break;
        }

        case TYPE_DIR_HANDLE:
        {
            PHANDLE phHandle = (PHANDLE)pMember->pbDataPtr;

            if(*phHandle != NULL)
            {
                StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("%p"), *phHandle);
                break;
            }

            // Display a prompt text
            szBuffer += LoadString(g_hInst, IDS_ENTER_DIRECTORY_NAME, szBuffer, (int)(szEndChar - szBuffer));
            break;
        }

        case TYPE_FLAG8:
        {
            PBYTE pbValue = (PBYTE)pMember->pbStructPtr;

            StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("0x%02hhX"), *pbValue);
            break;
        }

        case TYPE_FLAG16:
        {
            PWORD pwValue = (PWORD)pMember->pbStructPtr;

            StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("0x%04hX"), *pwValue);
            break;
        }

        case TYPE_FLAG32:
        {
            PULONG pulValue = (PULONG)pMember->pbStructPtr;

            StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("0x%08lX"), *pulValue);
            break;
        }

        case TYPE_FILETIME:
        {
            szBuffer = FileTimeToText(szBuffer,
                                      szEndChar,
                           (PFILETIME)pMember->pbDataPtr,
                                      bTextForEdit);
            break;
        }

        case TYPE_CNAME_L8B:
        {
            // Use this if it's name as CHAR array, of variable length.
            // The 'nMemberSize' must contain offset of 8-bit value, containing length
            // of the string in bytes.
            PUCHAR PtrLength = (PUCHAR)(pMember->pbStructPtr + pMember->nMemberSize);
            ULONG Length = *PtrLength;

            // Process the file name as non-null-terminated
            // array of WCHARs with variable length
            szBuffer = AStringToItemText(szBuffer,
                                         szEndChar,
                                  (LPSTR)pMember->pbDataPtr,
                                         Length,
                                         bTextForEdit);
            break;
        }

        case TYPE_WNAME_L32B:
        {
            // Use this if it's name as WCHAR array, of variable length.
            // The 'nMemberSize' must contain offset of 32-bit value, containing length
            // of the string in bytes.
            PULONG PtrLength = (PULONG)(pMember->pbStructPtr + pMember->nMemberSize);
            ULONG Length = *PtrLength;

            // Process the file name as non-null-terminated
            // array of WCHARs with variable length
            szBuffer = WStringToItemText(szBuffer,
                                         szEndChar,
                                 (LPWSTR)pMember->pbDataPtr,
                                         Length,
                                         bTextForEdit);
            break;
        }

        case TYPE_WNAME_L32W:
        {
            // Use this if it's name as WCHAR array, of variable length.
            // The 'nMemberSize' must contain offset of 32-bit value, containing length
            // of the string in WCHARs.
            PULONG PtrLength = (PULONG)(pMember->pbStructPtr + pMember->nMemberSize);
            ULONG Length = *PtrLength;

            // Process the file name as non-null-terminated
            // array of WCHARs with variable length
            szBuffer = WStringToItemText(szBuffer,
                                         szEndChar,
                                 (LPWSTR)pMember->pbDataPtr,
                                         Length * sizeof(WCHAR),
                                         bTextForEdit);
            break;
        }

        case TYPE_VNAME_FBDI:       // ShortName in FILE_BOTH_DIR_INFORMATION
        {
            PFILE_BOTH_DIR_INFORMATION FileInfo;

            // We have to take the whole structure and get the length
            // (the name doesn't have to be zero terminated)
            FileInfo = (PFILE_BOTH_DIR_INFORMATION)pMember->pbStructPtr;            

            // Process the file name as non-null-terminated
            // string with variable length
            szBuffer = WStringToItemText(szBuffer,
                                         szEndChar,
                                         FileInfo->ShortName,
                                         FileInfo->ShortNameLength,
                                         bTextForEdit);
            break;
        }

        case TYPE_VNAME_FIBD:       // ShortName in FILE_ID_BOTH_DIR_INFORMATION
        {
            PFILE_ID_BOTH_DIR_INFORMATION FileInfo;

            // We have to take the whole structure and get the length
            // (the name must not be zero terminated)
            FileInfo = (PFILE_ID_BOTH_DIR_INFORMATION)
                       (pMember->pbDataPtr - FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, ShortName));

            // Process the stream name as non-null-terminated string
            // with variable length
            szBuffer = WStringToItemText(szBuffer,
                                         szEndChar,
                                         FileInfo->ShortName,
                                         FileInfo->ShortNameLength,
                                         bTextForEdit);
            break;
        }

        case TYPE_VNAME_FIEBD:      // ShortName in FILE_ID_EXTD_BOTH_DIR_INFORMATION
        {
            PFILE_ID_EXTD_BOTH_DIR_INFORMATION FileInfo;

            // We have to take the whole structure and get the length
            // (the name must not be zero terminated)
            FileInfo = (PFILE_ID_EXTD_BOTH_DIR_INFORMATION)
                       (pMember->pbDataPtr - FIELD_OFFSET(FILE_ID_EXTD_BOTH_DIR_INFORMATION, ShortName));

            // Process the stream name as non-null-terminated string
            // with variable length
            szBuffer = WStringToItemText(szBuffer,
                                         szEndChar,
                                         FileInfo->ShortName,
                                         FileInfo->ShortNameLength,
                                         bTextForEdit);
            break;
        }

        case TYPE_FILEID64:         // File ID (unresolved)
        {
            PLARGE_INTEGER pFileId = (PLARGE_INTEGER)pMember->pbDataPtr;

            StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("%08lX-%08lX"), pFileId->HighPart, pFileId->LowPart);
            break;
        }

        case TYPE_GUID:
        {
            LPGUID pGuid = (LPGUID)pMember->pbDataPtr;
            TCHAR szGuidText[0x40];

            GuidToString(pGuid, szGuidText, _countof(szGuidText));
            StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("%s"), szGuidText);
            break;
        }

        case TYPE_SID:
        {
            PSID pSid = (PSID)pMember->pbDataPtr;
            TCHAR szSidText[SECURITY_MAX_SID_STRING_CHARACTERS];

            if(IsValidSid(pSid))
            {
                SidToString(pSid, szSidText, _countof(szSidText), TRUE);
            }

            StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("%s"), IsValidSid(pSid) ? szSidText : _T("<invalid>"));
            break;
        }

        default:
            StringCchPrintfEx(szBuffer, (szEndChar - szBuffer), &szBuffer, NULL, 0, _T("<unsupported>"));
            // No break here !!

        case TYPE_STRUCT:
            break;
    }

    // Terminate the buffer with EOS
    *szBuffer = 0;
    return ERROR_SUCCESS;
}

static NTSTATUS ItemTextToData(TStructMember * pMember, LPTSTR szItemText)
{
    // Now insert the member value
    switch(pMember->nDataType)
    {
        case TYPE_BOOLEAN:
        {
            PBOOLEAN pbValue = (PBOOLEAN)pMember->pbDataPtr;

            if(!_tcsicmp(szItemText, _T("TRUE")) || !_tcsicmp(szItemText, _T("1")))
            {
                *pbValue = TRUE;
                return STATUS_SUCCESS;
            }
            if(!_tcsicmp(szItemText, _T("FALSE")) || !_tcsicmp(szItemText, _T("0")))
            {
                *pbValue = FALSE;
                return STATUS_SUCCESS;
            }
            break;
        }

        case TYPE_UINT8:
        {
            PUCHAR pucValue = (PUCHAR)pMember->pbDataPtr;
            int nValue = 0;
            int nRoot = 10;

            // We allow either text or binary value
            if(szItemText[0] == _T('0') && toupper(szItemText[1]) == _T('X'))
            {
                szItemText += 2;
                nRoot = 16;
            }

            // Convert the text value to binary data
            nValue = StrToInt(szItemText, &szItemText, nRoot);
            if(*szItemText != 0 || nValue > 0xFF)
                return STATUS_INVALID_DATA_FORMAT;
            *pucValue = (UCHAR)nValue;
            return STATUS_SUCCESS;
        }

        case TYPE_UINT16:
        {
            PUSHORT pusValue = (PUSHORT)pMember->pbDataPtr;
            int nValue = 0;
            int nRoot = 10;

            // We allow either text or binary value
            if(szItemText[0] == _T('0') && toupper(szItemText[1]) == _T('X'))
            {
                szItemText += 2;
                nRoot = 16;
            }

            // Convert the text value to binary data
            nValue = StrToInt(szItemText, &szItemText, nRoot);
            if(*szItemText != 0 || nValue > 0xFFFF)
                return STATUS_INVALID_DATA_FORMAT;
            *pusValue = (USHORT)nValue;
            return STATUS_SUCCESS;
        }

        case TYPE_UINT32:
        {
            PULONG pulValue = (PULONG)pMember->pbDataPtr;
            int nRoot = 10;

            // We allow either text or binary value
            if(szItemText[0] == _T('0') && toupper(szItemText[1]) == _T('X'))
            {
                szItemText += 2;
                nRoot = 16;
            }

            *pulValue = (ULONG)StrToInt(szItemText, &szItemText, nRoot);
            return (*szItemText == 0) ? STATUS_SUCCESS : STATUS_INVALID_DATA_FORMAT;
        }

        case TYPE_UINT64:
        {
            PLARGE_INTEGER pliValue = (PLARGE_INTEGER)pMember->pbDataPtr;
            ULONG ulValue;

            // There must be two hexa values separated by '-'
            ulValue = (ULONG)StrToInt(szItemText, &szItemText, 16);
            if(*szItemText == _T('-'))
            {
                pliValue->HighPart = ulValue;
                pliValue->LowPart = (ULONG)StrToInt(szItemText + 1, &szItemText, 16);
            }
            else
            {
                pliValue->HighPart = 0;
                pliValue->LowPart = ulValue;
            }

            return (*szItemText == 0) ? STATUS_SUCCESS : STATUS_INVALID_DATA_FORMAT;
        }

        case TYPE_FILETIME:
        {
            return TextToFileTime(szItemText, (PFILETIME)pMember->pbDataPtr);
        }

        case TYPE_DIR_HANDLE:
        {
            return TextToDirHandle(szItemText, (PHANDLE)pMember->pbDataPtr);
        }

        case TYPE_FLAG8:
        case TYPE_FLAG16:
        case TYPE_FLAG32:
        {
            int nRoot = 10;

            // We allow either text or binary value
            if(szItemText[0] == _T('0') && toupper(szItemText[1]) == _T('X'))
            {
                szItemText += 2;
                nRoot = 16;
            }

            ULONG ulValue = (ULONG)StrToInt(szItemText, &szItemText, nRoot);

            switch (pMember->nDataType)
            {
                case TYPE_FLAG8:
                    *(PBYTE)pMember->pbStructPtr = (BYTE)ulValue;
                    break;

                case TYPE_FLAG16:
                    *(PWORD)pMember->pbStructPtr = (WORD)ulValue;
                    break;

                case TYPE_FLAG32:
                    *(PULONG)pMember->pbStructPtr = ulValue;
                    break;
            }

            return (*szItemText == 0) ? STATUS_SUCCESS : STATUS_INVALID_DATA_FORMAT;
        }

        case TYPE_WNAME_L32B:
        {
            // Use this if it's name as WCHAR array, of variable length.
            // The 'nMemberSize' must contain offset of 32-bit value, containing length
            // of the string in bytes.
            PULONG PtrLength = (PULONG)(pMember->pbStructPtr + pMember->nMemberSize);
            ULONG Length;

            // Copy the string
            Length = (ULONG)(wcslen(szItemText) * sizeof(WCHAR));
            memcpy(pMember->pbDataPtr, szItemText, Length);
            *PtrLength = Length;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_SUPPORTED;
}

static int InsertTreeItemFlags32(
    HWND hTreeView,
    HTREEITEM hParentItem,
    TStructMember * pMember,
    LPBYTE pbData,
    LPBYTE pbDataEnd)
{
    TStructMember * pMemberInfo;
    TCHAR szItemText[128] = {0};

    // Sanity check
    assert((UINT)(pbDataEnd - pbData) >= pMember->nMemberSize);
    UNREFERENCED_PARAMETER(pbDataEnd);
    assert(pMember->pFlags != NULL);

    // Allocate the data structure
    pMemberInfo = new TStructMember;
    if(pMemberInfo != NULL)
    {
        // Fill in the item data structure
        pMemberInfo->szMemberName = pMember->szMemberName;
        pMemberInfo->nDataType    = pMember->nDataType;
        pMemberInfo->nMemberSize  = pMember->nMemberSize;
        pMemberInfo->pbStructPtr  = pbData;
        pMemberInfo->pFlags       = pMember->pFlags;

        // Insert the tree item to the tree
        if(DataToItemText(pMemberInfo, szItemText, _countof(szItemText), FALSE) == ERROR_SUCCESS)
            InsertTreeItem(hTreeView, hParentItem, szItemText, pMemberInfo);
    }

    return pMember->nMemberSize;
}

static NTSTATUS OpenProcessAnyMethod(PHANDLE ProcessHandle, HANDLE ProcessId)
{
    ULONG dwProcessId = (DWORD)(DWORD_PTR)ProcessId;
    HANDLE hProcess;

    // Try normal access
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
    if(hProcess != NULL)
    {
        ProcessHandle[0] = hProcess;
        return STATUS_SUCCESS;
    }

    // Try with limited access
    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
    if(hProcess != NULL)
    {
        ProcessHandle[0] = hProcess;
        return STATUS_SUCCESS;
    }

    return STATUS_ACCESS_DENIED;
}

static NTSTATUS GetProcessImageFileNameByProcessId(HANDLE ProcessId, UNICODE_STRING & ImageName)
{
    SYSTEM_PROCESS_ID_INFORMATION processIdInfo;
    NTSTATUS Status;
    HANDLE hProcess;
    BYTE NameBuff[0x200] = {0};

    // Method 1 (Vista+): Try to retrieve the process image file name by PID.
    // This does not require an open process handle. Credit: Matthijs Lavrijsen
    processIdInfo.UniqueProcessId = ProcessId;
    processIdInfo.ImageName = ImageName;
    Status = NtQuerySystemInformation(SystemProcessIdInformation, &processIdInfo, sizeof(processIdInfo), NULL);
    if(NT_SUCCESS(Status))
    {
        ImageName.Length = processIdInfo.ImageName.Length;
        return Status;
    }

    // Method 2) Use OpenProcess and query the image name
    Status = OpenProcessAnyMethod(&hProcess, ProcessId);
    if(NT_SUCCESS(Status))
    {
        // Retrieve the process information
        Status = NtQueryInformationProcess(hProcess, ProcessImageFileName, NameBuff, sizeof(NameBuff), NULL);
        CloseHandle(hProcess);

        // If succeeded, copy the name
        if(NT_SUCCESS(Status))
        {
            PUNICODE_STRING TempName = (PUNICODE_STRING)NameBuff;
            size_t CopyLength;

            // For "System" process (PID = 0x04), the function succeeds but doesn't return anything
            if(TempName->Buffer && TempName->Length)
            {
                CopyLength = min(ImageName.MaximumLength, TempName->Length);
                memcpy(ImageName.Buffer, TempName->Buffer, CopyLength);
                ImageName.Length = (USHORT)CopyLength;
            }
        }
    }

    return Status;
}

static size_t InsertTreeItemProcess(HWND hTreeView, HTREEITEM hSubItem, HANDLE ProcessId, int nIndex)
{
    UNICODE_STRING ImageName;
    LPCWSTR szPlainName = NULL;
    LPCWSTR szFormat;
    NTSTATUS Status;
    WCHAR szBuffer[0x200] = {0};
    ULONG dwProcessId = (DWORD)(DWORD_PTR)ProcessId;

    // Initialize the UNICODE_STRING holding the file name
    ImageName.MaximumLength = (USHORT)(sizeof(szBuffer) - sizeof(WCHAR));
    ImageName.Length = 0;
    ImageName.Buffer = szBuffer;

    // Try to retrieve the process image file name
    Status = GetProcessImageFileNameByProcessId(ProcessId, ImageName);
    if(NT_SUCCESS(Status) && ImageName.Length)
    {
        ImageName.Buffer[ImageName.Length / sizeof(WCHAR)] = L'\0';
        szPlainName = GetPlainName(ImageName.Buffer);
    }
    else if(dwProcessId == 0)
    {
        szPlainName = L"System Idle Process";
    }
    else if(dwProcessId == 4)
    {
        szPlainName = L"System";
    }

    // Construct the image name
    szFormat = (szPlainName != NULL) ? _T("[0x%02X]: %u (%s)") : _T("[0x%02X]: %u (unknown)");
    StringCchPrintf(szBuffer, _countof(szBuffer), szFormat, nIndex, dwProcessId, szPlainName);
    InsertTreeItem(hTreeView, hSubItem, szBuffer);
    return sizeof(UINT_PTR);
}

static int InsertTreeItemByDataType(
    HWND hTreeView,
    HTREEITEM hParentItem,
    TStructMember * pMember,
    PBYTE pbStructPtr,
    PBYTE pbDataPtr,
    PBYTE pbDataEnd)
{
    TStructMember * pMemberInfo;
    TCHAR szItemText[1024] = _T("");
    int nBytesUsed = pMember->nMemberSize;

    if(pMember->nDataType == TYPE_ARRAY8_VARIABLE)
    {
        UINT nTotalDataLength = (UINT)(pbDataEnd - pbDataPtr);
        UINT nChunkDataLength;

        // Limit the total length to 1024 bytes
        nBytesUsed = nTotalDataLength;
        if(nTotalDataLength > 1024)
            nTotalDataLength = 1024;

        // Enter multiple lines, 1 paragraph per line
        while(nTotalDataLength != 0)
        {
            // Find out the maximum data length
            nChunkDataLength = min(nTotalDataLength, 0x10);

            // Allocate the data structure
            pMemberInfo = new TStructMember;
            if(pMemberInfo != NULL)
            {
                // Fill in the item data structure
                pMemberInfo->szMemberName = pMember->szMemberName;
                pMemberInfo->nDataType    = TYPE_ARRAY8_FIXED;
                pMemberInfo->nMemberSize  = nChunkDataLength;
                pMemberInfo->pbStructPtr  = pbStructPtr;
                pMemberInfo->pbDataPtr    = pbDataPtr;

                // Get the item text
                if(DataToItemText(pMemberInfo, szItemText, _countof(szItemText), FALSE) == ERROR_SUCCESS)
                    InsertTreeItem(hTreeView, hParentItem, szItemText, pMemberInfo);
            }

            // Move the pointer
            nTotalDataLength -= nChunkDataLength;
            pbDataPtr += nChunkDataLength;
        }
    }
    else
    {
        // Allocate the data structure
        pMemberInfo = new TStructMember;
        if(pMemberInfo != NULL)
        {
            // Fill in the item data structure
            pMemberInfo->szMemberName = pMember->szMemberName;
            pMemberInfo->nDataType    = pMember->nDataType;
            pMemberInfo->nMemberSize  = pMember->nMemberSize;
            pMemberInfo->pbStructPtr  = pbStructPtr;
            pMemberInfo->pbDataPtr    = pbDataPtr;

            // Get the item text
            if(DataToItemText(pMemberInfo, szItemText, _countof(szItemText), FALSE) == ERROR_SUCCESS)
                InsertTreeItem(hTreeView, hParentItem, szItemText, pMemberInfo);
        }
    }

    return nBytesUsed;
}

static int GetStructLength(TStructMember * pMember)
{
    int nStructLength = 0;

    // We don't need recursion here; structure members in structures
    // have also their size present, so we just add it
    for(; pMember->szMemberName != NULL; pMember++)
        nStructLength += pMember->nMemberSize;

    // If the structure size is greater than 4 bytes,
    // we have to align it to 8-byte boundary
    if(nStructLength > 0x04)
        nStructLength = ALIGN_INT64(nStructLength);

    return nStructLength;
}

static void EnableOrDisableButtons(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    BOOL bEnable = FALSE;

    // Controls on the dialog will be enabled only if the
    // handle is valid and it is a NT handle

    if(IsHandleValid(pData->hFile))
        bEnable = TRUE;
    if(GetDlgItem(hDlg, IDC_QUERY_INFO) != NULL)
        EnableDlgItems(hDlg, bEnable, IDC_QUERY_INFO, IDC_QUERY_DIR, IDC_SET_INFO, 0);
    if(GetDlgItem(hDlg, IDC_QUERY_VOL_INFO) != NULL)
        EnableDlgItems(hDlg, bEnable, IDC_QUERY_VOL_INFO, IDC_SET_VOL_INFO, 0);
}

static PUNICODE_STRING GetQueryDirectoryMask(HWND hDlg, UINT nID)
{
    PUNICODE_STRING FileMask;
    SIZE_T cbToAllocate;
    SIZE_T cbFileMask;
    HWND hWndChild = GetDlgItem(hDlg, nID);
    int nTextLength;

    // Retrieve the length of the mask
    nTextLength = GetWindowTextLength(hWndChild);
    cbFileMask  = (nTextLength * sizeof(WCHAR));
    cbToAllocate = sizeof(UNICODE_STRING) + cbFileMask + sizeof(WCHAR);
    FileMask = (PUNICODE_STRING)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, cbToAllocate);
    if(FileMask != NULL)
    {
        // Initialize the self-relative UNICODE_STRING
        FileMask->MaximumLength = (USHORT)(cbFileMask + sizeof(WCHAR));
        FileMask->Length = (USHORT)(cbFileMask);
        FileMask->Buffer = (LPWSTR)(FileMask + 1);

        // Copy the string
        GetWindowText(hWndChild, FileMask->Buffer, nTextLength + 1);

        // Special case: If the text is "NULL", then a NULL UNICODE_STRING is returned
        if(!RtlCompareUnicodeString(FileMask, &NullString, TRUE))
        {
            HeapFree(g_hHeap, 0, FileMask);
            FileMask = NULL;
        }
    }

    return FileMask;
}

static int ReloadTreeViewItems(HWND hDlg, HWND hTreeView, HTREEITEM hParentItem)
{
    TStructMember * pMemberInfo;
    HTREEITEM hItem = TreeView_GetNextItem(hTreeView, hParentItem, TVGN_CHILD);
    TVITEM tvi;
    TCHAR szItemText[1024];

    // Process all items at the same level
    while(hItem != NULL)
    {
        // Retrieve data struct associated with treeview item
        pMemberInfo = (TStructMember *)TreeView_GetItemParam(hTreeView, hItem);

        // If any structure associated, get its text
        if(pMemberInfo != NULL)
        {
            // Get the item text
            if(DataToItemText(pMemberInfo, szItemText, _countof(szItemText), FALSE) == ERROR_SUCCESS)
            {
                ZeroMemory(&tvi, sizeof(TVITEM));
                tvi.mask    = TVIF_TEXT;
                tvi.hItem   = hItem;
                tvi.pszText = szItemText;
                TreeView_SetItem(hTreeView, &tvi);
            }
        }

        // If the tree view item has a subitem, we have to recursively
        // reload subtree too
        if(TreeView_GetNextItem(hTreeView, hItem, TVGN_CHILD) != NULL)
            ReloadTreeViewItems(hDlg, hTreeView, hItem);

        // And finally, move to the next item at the same level
        hItem = TreeView_GetNextItem(hTreeView, hItem, TVGN_NEXT);
    }

    return TRUE;
}


static size_t FillStructureMembers(
    HWND hTreeView,
    HTREEITEM hParentItem,
    TStructMember * pMembers,
    LPBYTE pbData,
    LPBYTE pbDataEnd)
{
    HTREEITEM hSubItem;
    LPBYTE pbStructPtr = pbData;        // Pointer to the begin of the structure
    size_t nTotalLength = 0;            // Length, in bytes, of the structure member

    // Hack: In Windows 10, the FILE_STANDARD_INFORMATION becomes FILE_STANDARD_INFORMATION_EX
    if(pMembers == FileStandardInformationMembers && g_dwWinVer >= 0x0A00)
        pMembers = FileStandardInformationMembersEx;

    // Parse the members and fill them
    for(; pMembers->szMemberName != NULL; pMembers++)
    {
        size_t nDataLength = 0;

        switch(pMembers->nDataType)
        {
            case TYPE_STRUCT:
                assert(pMembers->pSubItems != NULL);

                hSubItem = InsertTreeItem(hTreeView, hParentItem, pMembers->szMemberName);
                nDataLength = FillStructureMembers(hTreeView,
                                                   hSubItem,
                                                   pMembers->pSubItems,
                                                   pbData,
                                                   pbDataEnd);
                break;

            case TYPE_CHAINED_STRUCT:

                hSubItem = InsertTreeItem(hTreeView, hParentItem, pMembers->szMemberName);
                nDataLength = FillStructMembersChained(hTreeView,
                                                       hSubItem,
                                                       pMembers->pSubItems,
                                                       pbData,
                                                       pbDataEnd);
                break;

            case TYPE_ARRAY_PROCESS:
            {
                // Use this if it's array of handles or INT_PTRs
                // The 'nMemberSize' must contain offset of 32-bit value, containing length
                // of the string in bytes.
                PHANDLE HandleArray = (PHANDLE)pbData;
                PULONG PtrHandleCount = (PULONG)(pbStructPtr + pMembers->nMemberSize);

                // Insert the subitem
                hSubItem = InsertTreeItem(hTreeView, hParentItem, pMembers->szMemberName);

                // Parse the array of process ID
                if(PtrHandleCount && PtrHandleCount[0])
                {
                    for(ULONG i = 0; i < PtrHandleCount[0]; i++)
                    {
                        nDataLength += InsertTreeItemProcess(hTreeView, hSubItem, HandleArray[i], i);
                    }
                }
                break;
            }

            case TYPE_FLAG8:
            case TYPE_FLAG16:
            case TYPE_FLAG32:   // Insert the flag array
                nDataLength = InsertTreeItemFlags32(hTreeView, hParentItem, pMembers, pbData, pbDataEnd);

				// If there is an alignment following the data member, do a proper alignment
				if(pMembers[1].nDataType == TYPE_PADDING)
				{
					nDataLength = GetAlignedDataLength(pbStructPtr, pbData, pMembers[0].nMemberSize, pMembers[1].nMemberSize);
					pMembers++;
				}
                break;

            default:

                // Insert the data member
                nDataLength = InsertTreeItemByDataType(hTreeView, hParentItem, pMembers, pbStructPtr, pbData, pbDataEnd);

                // If there is an alignment following the data member, do a proper alignment
                if(pMembers[1].nDataType == TYPE_PADDING)
                {
                    nDataLength = GetAlignedDataLength(pbStructPtr, pbData, pMembers[0].nMemberSize, pMembers[1].nMemberSize);
                    pMembers++;
                }
                break;
        }

        // Move the data pointer and total length by the item size
        nTotalLength += nDataLength;
        pbData += nDataLength;
    }

    // If the structure size is greater than 4 bytes,
    // we have to align it to 8-byte boundary
    if(nTotalLength > 0x04)
        nTotalLength = ALIGN_INT64(nTotalLength);

    // At the end, we have to round the structure size up to 8-byte boundary
    TreeView_Expand(hTreeView, hParentItem, TVE_EXPAND);
    return nTotalLength;
}

// This function fills a variable length structure
// The data structure must contain "ULONG NextEntryOffset"
// as its very first member
static int FillStructMembersChained(
    HWND hTreeView,
    HTREEITEM hParentItem,
    TStructMember * pMembers,
    LPBYTE pbData,
    LPBYTE pbDataEnd)
{
    HTREEITEM hItem;
    LPBYTE pbDataBegin = pbData;
    TCHAR szItemName[128];
    int nIndex = 0;

    // Insert infos about the streams
    while(pbData < pbDataEnd)
    {
        PCHAINED_ENTRY ChainedEntry = (PCHAINED_ENTRY)(pbData);
        ULONG NextEntryOffset = ChainedEntry->NextEntryOffset;

        // Fixup entries with artificial NextEntryOffset
        if(ChainedEntry->NextEntryOffset & NEXT_ENTRY_OFFSET_ATRIFICIAL)
        {
            NextEntryOffset &= ~NEXT_ENTRY_OFFSET_ATRIFICIAL;
            ChainedEntry->NextEntryOffset = 0;
        }

        StringCchPrintf(szItemName, _countof(szItemName), _T("[%u]"), nIndex++);
        hItem = InsertTreeItem(hTreeView, hParentItem, szItemName, pbData);
        FillStructureMembers(hTreeView, hItem, pMembers, pbData, pbDataEnd);

        // If the "NextEntryOffset" is zero, we stop searching
        if(NextEntryOffset == 0)
            break;
        pbData += NextEntryOffset;
    }

    // At the end, we have to round the structure size up to 8-byte boundary
    // Return the total length of the stream info
    TreeView_Expand(hTreeView, hParentItem, TVE_EXPAND);
    return (ULONG)(pbData - pbDataBegin);
}

static size_t FillDialogWithFileInfo(HWND hDlg, TInfoData * pInfoData, int nInfoClass)
{
    TFileTestData * pData = GetDialogData(hDlg);
    HTREEITEM hRootItem = NULL;
    LPBYTE pbNtInfoBuffEnd = pData->NtInfoData.pbData + pData->NtInfoData.cbData;
    HWND hTreeView = GetDlgItem(hDlg, IDC_FILE_INFO);
    HWND hComment = GetDlgItem(hDlg, IDC_COMMENT);
    size_t nInputLength = 0;
    BOOL bEnable = FALSE;
    BOOL bShowTreeView = FALSE;

    // Delete all items in the tree view
    TreeView_DeleteAllItems(hTreeView);

    // File infos and FS infos start from 1
    assert(nInfoClass >= 1);
    pInfoData = pInfoData + nInfoClass - 1;

    // Fill the tree view.
    // For some structures (like FILE_STREAM_INFORMATION),
    // we have to do it manually, because our data struct description
    // don't allow us to process the variable structs following each other
    if(pInfoData->szStructName != NULL)
    {
        hRootItem = InsertTreeItem(hTreeView, TVI_ROOT, pInfoData->szStructName);
        if(hRootItem != NULL && pInfoData->pStructMembers != NULL)
        {
            // Chained structures, like FILE_DIRECTORY_INFORMATION,
            // require different approach.
            if(pInfoData->bIsChain == FALSE)
            {
                nInputLength = FillStructureMembers(hTreeView,
                                                    hRootItem,
                                                    pInfoData->pStructMembers,
                                                    pData->NtInfoData.pbData,
                                                    pbNtInfoBuffEnd);
            }
            else
            {
                nInputLength = FillStructMembersChained(hTreeView,
                                                        hRootItem,
                                                        pInfoData->pStructMembers,
                                                        pData->NtInfoData.pbData,
                                                        pbNtInfoBuffEnd);
            }

            // Expand all subitems
            bShowTreeView = TRUE;
            bEnable = TRUE;
        }
    }

    // Enable/disable input length and setinfo button
    EnableDlgItems(hDlg, bEnable, IDC_INPUT_LENGTH_TITLE,
                                  IDC_INPUT_LENGTH,
                                  IDC_DEFAULT_LENGTH,
                                  IDC_MAXIMUM_LENGTH,
                                  0);

    // Enable/disable the buttons
    EnableOrDisableButtons(hDlg);

    // Show/hide the tree view
    if(bShowTreeView != IsWindowVisible(hTreeView))
    {
        ShowWindow(hTreeView, bShowTreeView ? SW_SHOW : SW_HIDE);
        ShowWindow(hComment, bShowTreeView ? SW_HIDE : SW_SHOW);
    }

    return nInputLength;
}

static void FillDialogWithMasks(HWND hWndCombo)
{
    ComboBox_InsertString(hWndCombo, -1, _T("NULL"));
    ComboBox_InsertString(hWndCombo, -1, _T("*"));
    ComboBox_InsertString(hWndCombo, -1, _T("*.*"));
    ComboBox_InsertString(hWndCombo, -1, _T("*.exe"));

    ComboBox_SetCurSel(hWndCombo, 0);
}

VOID CALLBACK TimerTooltipProc(HWND hDlg, UINT /* uMsg */, UINT_PTR /* idEvent */, DWORD /* dwTime */)
{
    // Destroy the tooltip window
    if(hToolTip != NULL)
        DestroyWindow(hToolTip);
    hToolTip = NULL;

    // Kill the timer 
    if(nTimerTooltip != NULL)
        KillTimer(hDlg, nTimerTooltip);
    nTimerTooltip = 0;
}

static int CopyItemToClipboard(HWND hDlg, TStructMember * pMemberInfo)
{
    HGLOBAL hMem = NULL;
    LPTSTR szClipboard = NULL;
    size_t cbMemberData = 0;
    DWORD dwErrCode = ERROR_CAN_NOT_COMPLETE;

    // Get the binary length of the data
    if(pMemberInfo->nDataType == TYPE_WNAME_L32B)
        cbMemberData = *(PULONG)(pMemberInfo->pbStructPtr + pMemberInfo->nMemberSize);

    // Only for known data
    assert(cbMemberData != 0);

    // Allocate space for clipboard
    hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, cbMemberData + 2);
    if(hMem != NULL)
    {
        // Lock the memory
        szClipboard = (LPTSTR)GlobalLock(hMem);
        if(szClipboard != NULL)
        {
            // Copy the data to the clipboard
            CopyMemory(szClipboard, pMemberInfo->pbDataPtr, cbMemberData);
            GlobalUnlock(hMem);

            // Open the clipboard
            if(OpenClipboard(hDlg))
            {
                EmptyClipboard();
                if(SetClipboardData(CF_UNICODETEXT, hMem))
                    dwErrCode = ERROR_SUCCESS;
                CloseClipboard();
            }
        }

        GlobalFree(hMem);
    }

    return dwErrCode;
}

static bool FileIdHasFileName(HWND hTreeView, HTREEITEM hItem)
{
    TVITEM tvi;
    bool bResult = false;

    // Allocate buffer for a maximum possible file name length
    tvi.mask = TVIF_TEXT;
    tvi.hItem = hItem;
    tvi.pszText = new TCHAR[MAX_NT_PATH + 1];
    tvi.cchTextMax = MAX_NT_PATH;
    if(tvi.pszText != NULL)
    {
        // Load the tree view text
        TreeView_GetItem(hTreeView, &tvi);
        if(tvi.cchTextMax != 0)
        {
            // If there is a file name tail (" (\"), then we have file name there
            if(_tcschr(tvi.pszText, _T('(')))
                bResult = true;
        }

        delete [] tvi.pszText;
    }

    return bResult;
}

static TInfoData * GetSelectedInfoClass(HWND hDlg, UINT nIDCombo, TInfoData * pInfoData)
{
    TCHAR szSelection[MAX_PATH];
    HWND hWndCombo = GetDlgItem(hDlg, nIDCombo);
    int nSelection = ComboBox_GetCurSel(hWndCombo);

    // If there's an active selection,
    // we need to find the proper item by the string
    if(nSelection != CB_ERR)
    {
        // Retrieve the actually selected item
        if(ComboBox_GetLBText(hWndCombo, nSelection, szSelection) > 0)
        {
            // Find the proper info class
            for(int i = 0; pInfoData[i].szInfoClass != NULL; i++)
            {
                if(!_tcsicmp(pInfoData[i].szInfoClass, szSelection))
                {
                    return pInfoData + i;
                }
            }
        }
    }

    return NULL;
}

//-----------------------------------------------------------------------------
// Message handlers

static TAnchors * pAnchors1 = NULL; // For NtFileInfo
static TAnchors * pAnchors2 = NULL; // For NtVolInfo

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    TFileTestData * pData;
    PROPSHEETPAGE * pPage = (PROPSHEETPAGE *)lParam;
    TAnchors * pAnchors = NULL;
    HWND hWndChild;

    // Allocate the buffer for file information class.
    // Hopefully the struct size will never exceed 32 KB
    pData = (TFileTestData *)pPage->lParam;

    // Initialize the dialog
    SetDialogData(hDlg, pPage->lParam);
    hDirTarget = NULL;

    // Configure dialog resizing
    if(pData->bEnableResizing)
    {
        if(GetDlgItem(hDlg, IDC_QUERY_INFO) != NULL)
        {
            pAnchors1 = new TAnchors(hDlg);
            pAnchors = pAnchors1;
        }

        if(GetDlgItem(hDlg, IDC_QUERY_VOL_INFO) != NULL)
        {
            pAnchors2 = new TAnchors(hDlg);
            pAnchors = pAnchors2;
        }

        pAnchors->AddAnchor(hDlg, IDC_FILE_INFO_CLASS_TITLE, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_INFO_CLASS, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_VOL_INFO_CLASS_TITLE, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_VOL_INFO_CLASS, akLeft | akTop | akRight);
//      pAnchors->AddAnchor(hDlg, IDC_SEARCH_MASK_TITLE, akLeft | akTop);
//      pAnchors->AddAnchor(hDlg, IDC_SEARCH_MASK, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_INPUT_LENGTH_TITLE, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_INPUT_LENGTH, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_DEFAULT_LENGTH, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_MAXIMUM_LENGTH, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_COMMENT, akAll);
        pAnchors->AddAnchor(hDlg, IDC_FILE_INFO, akAll);
        pAnchors->AddAnchor(hDlg, IDC_QUERY_INFO, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_QUERY_DIR, akLeftCenter | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_SET_INFO, akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_QUERY_VOL_INFO, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_SET_VOL_INFO, akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_FRAME, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_INFORMATION_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_INFORMATION, akLeft | akRight | akBottom);
    }

    // Allocate default size for the FileInfo.
    pData->NtInfoData.SetLength(INITIAL_FILEINFO_BUFFER_SIZE);

    // Fill the combo box with names of file information classes
    hWndChild = GetDlgItem(hDlg, IDC_FILE_INFO_CLASS);
    if(hWndChild != NULL)
    {
        // Fill all info classes for NtSetInformationFile
        FillComboBoxFiltered(hWndChild, FileInfoData, _T(""));
        ComboBox_SetCurSel(hWndChild, (int)InitialFileInfo - 1);
        SetFocus(hWndChild);

        // Initialize tree view with structure for current
        // file information class
        FillDialogWithFileInfo(hDlg, FileInfoData, (int)InitialFileInfo);
    }

    // Fill the combo box with names of volume information classes
    hWndChild = GetDlgItem(hDlg, IDC_VOL_INFO_CLASS);
    if(hWndChild != NULL)
    {
        // Fill all info classes for NtSetVolumeInformationFile
        FillComboBoxFiltered(hWndChild, FsInfoData, _T(""));
        ComboBox_SetCurSel(hWndChild, (int)InitialFsInfo - 1);
        SetFocus(hWndChild);

        // Initialize tree view with structure for current
        // file information class
        FillDialogWithFileInfo(hDlg, FsInfoData, (int)InitialFsInfo);
    }

    // Configure the search mask edit box
    hWndChild = GetDlgItem(hDlg, IDC_SEARCH_MASK);
    if(hWndChild != NULL)
        FillDialogWithMasks(hWndChild);

    // Initialize the in/out data length
    Hex2DlgText32(hDlg, IDC_INPUT_LENGTH, (DWORD)(pData->NtInfoData.cbData));

    // Configure the buttons
    EnableOrDisableButtons(hDlg);
    return TRUE;
}

// Posted when the item label has been edited.
// We will fix the tree item to contain "Name: Value" text
static int OnReloadItems(HWND hDlg, HWND hTreeView, HTREEITEM hTreeItem)
{
    // If the treeview edit process has not been completed yet,
    // post the processing again
    if(TreeView_GetEditControl(hTreeView) != NULL)
    {
        PostMessage(hDlg, WM_RELOADITEMS, (WPARAM)hTreeView, (LPARAM)hTreeItem);
        return TRUE;
    }

    ReloadTreeViewItems(hDlg, hTreeView, hTreeItem);
    return TRUE;
}

static int OnShowDateFormats(HWND hDlg, HWND hTreeItem, HTREEITEM hItem)
{
    TOOLINFO ti;
    LPTSTR szText;
    TCHAR szDateFormatPrefix[120];
    TCHAR szTimeFormatPrefix[120];
    TCHAR szTitle[120];
    POINT pt;
    RECT rect;
    int nMaxChars = 0x1000;

    // Get the position of the treeview item
    TreeView_GetItemRect(hTreeItem, hItem, &rect, TRUE);
    pt.x = rect.left + (rect.right - rect.left) / 2;
    pt.y = rect.top + (rect.bottom - rect.top) / 2;
    ClientToScreen(hTreeItem, &pt);

    // Allocate text for error
    szText = new TCHAR[nMaxChars + 1];
    if(szText == NULL)
        return TRUE;
  
    // Prepare the text for the tooltip
    LoadString(g_hInst, IDS_BAD_DATETIME_FORMAT, szTitle, _countof(szTitle));
    LoadString(g_hInst, IDS_DATE_FORMAT_PREFIX, szDateFormatPrefix, _countof(szDateFormatPrefix));
    LoadString(g_hInst, IDS_TIME_FORMAT_PREFIX, szTimeFormatPrefix, _countof(szTimeFormatPrefix));
    GetSupportedDateTimeFormats(szDateFormatPrefix, szTimeFormatPrefix, szText, nMaxChars);

    // Create the additional tooltip window
    if(hToolTip == NULL)
    {
        hToolTip = CreateWindowEx(WS_EX_TOPMOST,
                                  TOOLTIPS_CLASS,
                                  NULL,
                                  WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP | TTS_BALLOON | TTS_CLOSE,
                                  CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                                  hDlg,
                                  NULL,
                                  g_hInst,
                                  NULL);
    }

    if(hToolTip != NULL)
    {
        // Set the one (and only one) tooltip window for the list view
        ZeroMemory(&ti, sizeof(TOOLINFO));
        ti.cbSize   = sizeof(TOOLINFO);
        ti.uFlags   = TTF_TRACK | TTF_TRANSPARENT | TTF_IDISHWND;
        ti.hinst    = g_hInst;
        ti.lpszText = szText;
        ti.uId      = (UINT_PTR)hTreeItem;
        SendMessage(hToolTip, TTM_ADDTOOL, 0, (LPARAM)&ti);

        // Set the icon and title
        SendMessage(hToolTip, TTM_SETTITLE, TTI_INFO, (LPARAM)szTitle);

        // Force the tooltip to be multi-line by specifying max width
        GetClientRect(hDlg, &rect);
        SendMessage(hToolTip, TTM_SETMAXTIPWIDTH, 0, (LPARAM)(rect.right - rect.left));

        // Set the tooltip position
        SendMessage(hToolTip, TTM_TRACKPOSITION, 0, MAKELONG(pt.x, pt.y));

        // Show the tooltip
        SendMessage(hToolTip, TTM_TRACKACTIVATE, TRUE, (LPARAM)&ti);

        // Set the tooltip timer
        nTimerTooltip = SetTimer(hDlg, WM_TIMER_TOOLTIP, 10000, TimerTooltipProc); 
    }

    // Free buffers and exit
    if(szText != NULL)
        delete [] szText;
    return TRUE;
}

static int OnSetActive(HWND hDlg)
{
    EnableOrDisableButtons(hDlg);
    return TRUE;
}

static int OnBeginLabelEdit(HWND hDlg, NMTVDISPINFO * pTVDispInfo)
{
    TStructMember * pMemberInfo = (TStructMember *)pTVDispInfo->item.lParam;
    TInfoData * pInfoData;
    NTSTATUS CantEditStatus = STATUS_CANNOT_EDIT_THIS;
    TCHAR szItemText[1024] = _T("");
    HWND hTreeView = pTVDispInfo->hdr.hwndFrom;
    HWND hEdit;
    BOOL bStartEditing = FALSE;
    bool bCopyToClipboard = false;
    bool bEditable = true;

    // If there is a tooltip active, destroy it
    TimerTooltipProc(hDlg, 0, 0, 0);

    // Verify if the selected file info class is editable
    pInfoData = GetSelectedInfoClass(hDlg, IDC_FILE_INFO_CLASS, FileInfoData);
    if(pInfoData != NULL)
    {
        if(pInfoData->bIsChain == TRUE || pInfoData->bIsEditable == FALSE)
            bEditable = false;
        if(pMemberInfo != NULL && pMemberInfo->nDataType == TYPE_WNAME_L32B)
            bCopyToClipboard = true;
    }

    // Verify if the selected FS info class is editable
    pInfoData = GetSelectedInfoClass(hDlg, IDC_VOL_INFO_CLASS, FsInfoData);
    if(pInfoData != NULL)
    {
        if(pInfoData->bIsChain == TRUE || pInfoData->bIsEditable == FALSE)
            bEditable = false;
    }

    // If not editable, show message
    if(bEditable == false)
    {
        if(bCopyToClipboard)
        {
            CopyItemToClipboard(hDlg, pMemberInfo);
            CantEditStatus = STATUS_COPIED_TO_CLIPBOARD;
        }

        SetResultInfo(hDlg, RSI_NTSTATUS | RSI_NOINFO, CantEditStatus);
        SetWindowLongPtr(hDlg, DWLP_MSGRESULT, TRUE);
        return TRUE;
    }

    // If the item has an associated struct member, allow editing
    if(pMemberInfo != NULL)
    {
        // Get the edit control which will be shown
        hEdit = TreeView_GetEditControl(hTreeView);
        if(hEdit != NULL)
        {
            // Get the item text
            if(DataToItemText(pMemberInfo, szItemText, _countof(szItemText), TRUE) == ERROR_SUCCESS)
            {
                SetWindowText(hEdit, szItemText);
                bStartEditing = TRUE;
            }
        }
    }

    // If we start editing something, make sure that Esc key will not
    // cancel the entire FileTest
    DisableCloseDialog(hDlg, bStartEditing);

    // Store the result info the dialog's private variables
    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, bStartEditing ? FALSE : TRUE);
    return TRUE;
}

static int OnEndLabelEdit(HWND hDlg, NMTVDISPINFO * pTVDispInfo)
{
    TStructMember * pMemberInfo = (TStructMember *)pTVDispInfo->item.lParam;
    NTSTATUS Status;
    HWND hTreeView = pTVDispInfo->hdr.hwndFrom;
    BOOL bAcceptChanges = FALSE;

    // If the item has an associated member, analyze the result text
    if(pMemberInfo != NULL && pTVDispInfo->item.pszText != NULL)
    {
        // Try to convert the text to appropriate data item
        Status = ItemTextToData(pMemberInfo, pTVDispInfo->item.pszText);
        if(NT_SUCCESS(Status))
        {
            HTREEITEM hParentItem;

            // We have to reload all items at the same level, because 
            // the ItemTextToData might have changed more than one item data
            // (Example: variable length strings editation change also the length)
            hParentItem = TreeView_GetNextItem(hTreeView, pTVDispInfo->item.hItem, TVGN_PARENT);
            PostMessage(hDlg, WM_RELOADITEMS, (WPARAM)hTreeView, (LPARAM)hParentItem);
            bAcceptChanges = TRUE;
        }
        else
        {
            // If the user failed to enter proper date/time, show him the possible options
            if(pMemberInfo->nDataType == TYPE_FILETIME)
                PostMessage(hDlg, WM_SHOW_DATE_FORMATS, (WPARAM)hTreeView, (LPARAM)pTVDispInfo->item.hItem);

            // We should warn the user about that the item
            // has invalid format for its data type
            SetResultInfo(hDlg, RSI_NTSTATUS | RSI_NOINFO, Status);
        }
    }

    // Enable the exit button
    DisableCloseDialog(hDlg, FALSE);
    SetWindowLongPtr(hDlg, DWLP_MSGRESULT, bAcceptChanges);
    return TRUE;
}

static int OnDoubleClick(HWND hDlg, LPNMHDR pNMHDR)
{
    TStructMember * pMemberInfo;
    TFileTestData * pData = GetDialogData(hDlg);
    PLARGE_INTEGER pliValue;
    TInfoData * pInfoData;
    HTREEITEM hParentItem;
    HTREEITEM hItem;
    LPCTSTR szFormat = _T("%s: %08X-%08X (%s)");
    LPTSTR szFileName = NULL;
    LPTSTR szItemText = NULL;
    TVITEM tvi;
    size_t nLength;
    HWND hTreeView;

    // Only accept doubleclicks on IDC_FILE_INFO
    if(pNMHDR->idFrom != IDC_FILE_INFO)
        return TRUE;
    hTreeView = GetDlgItem(hDlg, (int)pNMHDR->idFrom);

    // Retrieve the selected item
    hItem = TreeView_GetSelection(hTreeView);
    if(hItem == NULL)
        return TRUE;

    // Retrieve the item's data
    pMemberInfo = (TStructMember *)TreeView_GetItemParam(hTreeView, hItem);
    if(pMemberInfo == NULL)
        return TRUE;

    // Doubleclick on a file ID appends a file name after it
    if(pMemberInfo->nDataType == TYPE_FILEID64)
    {
        // If the file name is not there yet, query the file name
        if(FileIdHasFileName(hTreeView, hItem) == false)
        {
            szFileName = FileIDToFileName(pData->szFileName1, pMemberInfo->pbDataPtr, pMemberInfo->nMemberSize);
            if(szFileName != NULL)
            {
                nLength = _tcslen(pMemberInfo->szMemberName) + _tcslen(szFormat) + 16 + _tcslen(szFileName);
                szItemText = new TCHAR[nLength];
                if(szItemText != NULL)
                {
                    // Format the item text
                    pliValue = (PLARGE_INTEGER)pMemberInfo->pbDataPtr;
                    StringCchPrintf(szItemText, nLength,
                                                szFormat,
                                                pMemberInfo->szMemberName,
                                                pliValue->HighPart,
                                                pliValue->LowPart,
                                                szFileName);
                    
                    // Apply the item text to the tree view                    
                    ZeroMemory(&tvi, sizeof(TVITEM));
                    tvi.mask = TVIF_TEXT;
                    tvi.hItem = hItem;
                    tvi.pszText = szItemText;
                    TreeView_SetItem(hTreeView, &tvi);
                    delete [] szItemText;
                }

                delete [] szFileName;
            }
        }
        else
        {
            ULONGLONG FileId = *(PULONGLONG)pMemberInfo->pbDataPtr;
            TCHAR szFileId[MAX_FILEID_PATH];

            FileIDToString(pData, FileId, szFileId);
            NtUseFileId(hDlg, szFileId);
        }
    }

    // Doubleclick on a subdirectory or stream name
    // creates a full path and switches to "NtCreate"
    if(pMemberInfo->nDataType == TYPE_WNAME_L32B)
    {
        HWND hWndParent = GetParent(hDlg);
        HWND hTabCtrl = GetDlgItem(hWndParent, IDC_TAB);
        ULONG FileNameLength = *(PULONG)(pMemberInfo->pbStructPtr + pMemberInfo->nMemberSize);

        szFileName = CreateFullName(pData->szFileName1, (LPWSTR)pMemberInfo->pbDataPtr, FileNameLength);
        if(szFileName != NULL)
        {
            StringCchCopy(pData->szFileName1, MAX_NT_PATH, szFileName);
            TabCtrl_SelectPageByID(hTabCtrl, MAKEINTRESOURCE(IDD_PAGE02_NTCREATE));
            delete [] szFileName;
        }
    }

    // Doubleclick on TYPE_FLAG* opens a dialog with flags
    if(pMemberInfo->nDataType == TYPE_FLAG8 || pMemberInfo->nDataType == TYPE_FLAG16 || pMemberInfo->nDataType == TYPE_FLAG32)
    {
        DWORD Flags;

        switch (pMemberInfo->nDataType)
        {
            case TYPE_FLAG8:
                Flags = *(PBYTE)pMemberInfo->pbStructPtr;
                break;

            case TYPE_FLAG16:
                Flags = *(PWORD)pMemberInfo->pbStructPtr;
                break;

            case TYPE_FLAG32:
                Flags = *(PDWORD)pMemberInfo->pbStructPtr;
                break;
        }

        if(FlagsDialog(hDlg, IDS_ENTER_FLAGS, pMemberInfo->pFlags, Flags))
        {
            // Only change the item if editable
            pInfoData = GetSelectedInfoClass(hDlg, IDC_FILE_INFO_CLASS, FileInfoData);
            if(pInfoData != NULL && pInfoData->bIsEditable)
            {
                switch (pMemberInfo->nDataType)
                {
                    case TYPE_FLAG8:
                        *(PBYTE)pMemberInfo->pbStructPtr = (BYTE)Flags;
                        break;

                    case TYPE_FLAG16:
                        *(PWORD)pMemberInfo->pbStructPtr = (WORD)Flags;
                        break;

                    case TYPE_FLAG32:
                        *(PDWORD)pMemberInfo->pbStructPtr = Flags;
                        break;
                }
                
                hParentItem = TreeView_GetNextItem(hTreeView, hItem, TVGN_PARENT);
                PostMessage(hDlg, WM_RELOADITEMS, (WPARAM)hTreeView, (LPARAM)hParentItem);
            }
        }
    }

    return TRUE;
}

//
// Provides some extension to the default combo box search
// 
// When the user types something, the combo box's drop list
// is filtered. Only those items that are in the list are included
//
// If the user types "Stand", then only these items are displayed:
//
//  "FileStandardInformation"
//  "FileStandardLinkInformation"
//
static int OnComboBoxEditUpdate(HWND hDlg, UINT nID, TInfoData * pInfoData)
{
    TCHAR szEditText[MAX_PATH+1];
    HWND hWndCombo = GetDlgItem(hDlg, nID);

    if(!ComboBox_GetDroppedState(hWndCombo))
        ComboBox_ShowDropdown(hWndCombo, TRUE);

    // Get the text from the combo box
    GetWindowText(hWndCombo, szEditText, MAX_PATH);

    // Reset the combo box to only contain items with that substring
    CharUpper(szEditText);
    FillComboBoxFiltered(hWndCombo, pInfoData, szEditText);

    // The text might have been changed by the text filling
    return TRUE;
}

static int OnComboBoxItemSelected(HWND hDlg, UINT nID, TInfoData * pInfoData)
{
    TFileTestData * pData = GetDialogData(hDlg);

    // If there's an active selection, fill the dialog
    pInfoData = GetSelectedInfoClass(hDlg, nID, pInfoData);
    if(pInfoData != NULL)
    {
        ZeroMemory(pData->NtInfoData.pbData, pData->NtInfoData.cbData);
        FillDialogWithFileInfo(hDlg, pInfoData, 1);
        Hex2DlgText32(hDlg, IDC_INPUT_LENGTH, (DWORD)(pData->NtInfoData.cbData));
    }

    return TRUE;
}

static int OnDefaultLengthClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    TInfoData * pInfoData;
    UINT nDataLength = 0;

    // Default length for file info class
    pInfoData = GetSelectedInfoClass(hDlg, IDC_FILE_INFO_CLASS, FileInfoData);
    if(pInfoData != NULL)
        nDataLength = GetStructLength(pInfoData->pStructMembers);

    // Default length for FS info class
    pInfoData = GetSelectedInfoClass(hDlg, IDC_VOL_INFO_CLASS, FsInfoData);
    if(pInfoData != NULL)
        nDataLength = GetStructLength(pInfoData->pStructMembers);

    pData->NtInfoData.SetLength(nDataLength);
    Hex2DlgText32(hDlg, IDC_INPUT_LENGTH, nDataLength);
    return TRUE;
}

static int OnMaximumLengthClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    pData->NtInfoData.SetLength(pData->NtInfoData.cbDataMax);
    Hex2DlgText32(hDlg, IDC_INPUT_LENGTH, (DWORD)(pData->NtInfoData.cbDataMax));
    return TRUE;
}

static int OnQueryInfoClick(HWND hDlg)
{
    FILE_INFORMATION_CLASS FileInfoClass;
    TFileTestData * pData = GetDialogData(hDlg);
    IO_STATUS_BLOCK IoStatus = {0};
    TInfoData * pInfoData;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Length = 0;

    // Test if the handle is an NT file handle and get the file info class
    if(IsHandleValid(pData->hFile) == FALSE)
        return FALSE;

    // Get the selected info data
    pInfoData = GetSelectedInfoClass(hDlg, IDC_FILE_INFO_CLASS, FileInfoData);
    if(pInfoData == NULL)
        return FALSE;

    // Get the file information class
    FileInfoClass = (FILE_INFORMATION_CLASS)(pInfoData->InfoClass);

    // Get the input length
    DlgText2Hex32(hDlg, IDC_INPUT_LENGTH, &Length);
    
    // If the required length is bigger than the current one, reallocate the buffer
    pData->NtInfoData.SetLength(Length);

    // Perform the call
    if(NT_SUCCESS(Status))
    {
        Status = NtQueryInformationFile(pData->hFile,
                                        &IoStatus,
                                        pData->NtInfoData.pbData,
                                        Length,
                                        FileInfoClass);
    }                                        

    // If succeeded, we have to fill the dialog with file info
    if(NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
        FillDialogWithFileInfo(hDlg, FileInfoData, (int)FileInfoClass);

    // Set the result status and return
    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_INFORMATION, Status, &IoStatus);
    return TRUE;
}


static int OnQueryDirClick(HWND hDlg)
{
    FILE_INFORMATION_CLASS FileInfoClass;
    TFileTestData * pData = GetDialogData(hDlg);
    IO_STATUS_BLOCK IoStatus = {0};
    PUNICODE_STRING FileMask = NULL;
    TInfoData * pInfoData;
    ULONG_PTR TotalLength = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN RestartScan = TRUE;
    HANDLE hEvent = NULL;
    ULONG Length = 0;

    // Test if the handle is an NT file handle and get the file info class
    if(IsHandleValid(pData->hFile) == FALSE)
        return FALSE;

    // Get the selected info data
    pInfoData = GetSelectedInfoClass(hDlg, IDC_FILE_INFO_CLASS, FileInfoData);
    if(pInfoData == NULL)
        return FALSE;

    // Get the file information class
    FileInfoClass = (FILE_INFORMATION_CLASS)(pInfoData->InfoClass);

    // Get the input mask
    FileMask = GetQueryDirectoryMask(hDlg, IDC_SEARCH_MASK);

    // Get the input length
    DlgText2Hex32(hDlg, IDC_INPUT_LENGTH, &Length);

    // If the required length is bigger than the current one, reallocate the buffer
    pData->NtInfoData.SetLength(Length);

    // Create event for asynchronous calls
    if(NT_SUCCESS(Status))
    {
        hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        if(hEvent == NULL)
            Status = STATUS_UNSUCCESSFUL;
    }

    // Perform the directory query. Note that we need to keep enumerating
    // until we get out of memory or until STATUS_NO_MORE_FILES is returned.
    // https://github.com/ladislav-zezula/FileTest/issues/32
    if(NT_SUCCESS(Status))
    {
        PCHAINED_ENTRY LastEntry = NULL;
        LPBYTE pbDataEnd = pData->NtInfoData.pbData + pData->NtInfoData.cbData;
        LPBYTE pbDataPtr = pData->NtInfoData.pbData;

        // Do not allow buffer overflow
        while(pbDataPtr < pbDataEnd)
        {
            // Perform the single directory query
            Status = NtQueryDirectoryFile(pData->hFile,
                                          hEvent,
                                          NULL,
                                          NULL,
                                         &IoStatus,
                                          pbDataPtr,
                                  (ULONG)(pbDataEnd - pbDataPtr),
                                          FileInfoClass,
                                          FALSE,
                                          FileMask,
                                          RestartScan);

            // If the operation is pending, we have to wait until it's complete
            if(Status == STATUS_PENDING)
            {
                WaitForSingleObject(hEvent, INFINITE);
                Status = IoStatus.Status;
            }

            // Calculate the total length returned
            TotalLength = (pbDataPtr + IoStatus.Information) - pData->NtInfoData.pbData;

            // Anything else than STATUS_SUCCESS will break the loop.
            // At the end of the search, we expect STATUS_NO_MORE_FILES
            if(Status != STATUS_SUCCESS)
                break;

            // If we have data from the previous search, mark the last entry
            // so we can later process the whole buffer as if it was result of a single search
            if(LastEntry != NULL)
                DirEntry_Mark(LastEntry, pbDataPtr);
            LastEntry = DirEntry_Find(pbDataPtr, IoStatus.Information);

            // Prepare the 8-byte-aligned pointer to the next directory query
            pbDataPtr += ALIGN_TO_SIZE(IoStatus.Information, 0x08);
            RestartScan = FALSE;
        }
    }

    // If succeeded, we have to fill the dialog with file info
    if(NT_SUCCESS(Status) || Status == STATUS_NO_MORE_FILES || Status == STATUS_BUFFER_OVERFLOW)
    {
        pData->NtInfoData.SetLength(TotalLength);
        FillDialogWithFileInfo(hDlg, FileInfoData, (int)FileInfoClass);
    }

    // Set the result status and return
    if(hEvent != NULL)
        CloseHandle(hEvent);
    if(FileMask != NULL)
        HeapFree(g_hHeap, 0, FileMask);
    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_INFORMATION, Status, &IoStatus);
    return TRUE;
}

static int OnSetInfoClick(HWND hDlg)
{
    FILE_INFORMATION_CLASS FileInfoClass;
    TFileTestData * pData = GetDialogData(hDlg);
    IO_STATUS_BLOCK IoStatus = {0};
    TInfoData * pInfoData;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Length = 0;

    // Test if the handle is an NT file handle and get the file info class
    if(IsHandleValid(pData->hFile) == FALSE)
        return FALSE;

    // Get the selected info data
    pInfoData = GetSelectedInfoClass(hDlg, IDC_FILE_INFO_CLASS, FileInfoData);
    if(pInfoData == NULL)
        return FALSE;

    // Get the file information class
    FileInfoClass = (FILE_INFORMATION_CLASS)(pInfoData->InfoClass);

    // Get the length of the input data
    DlgText2Hex32(hDlg, IDC_INPUT_LENGTH, &Length);

    // If the required length is bigger than the current one, reallocate the buffer
    pData->NtInfoData.SetLength(Length);

    // Call NtSetInformationFile
    if(NT_SUCCESS(Status))
    {
        Status = NtSetInformationFile(pData->hFile,
                                     &IoStatus,
                                      pData->NtInfoData.pbData,
                                      Length,
                                      FileInfoClass);
    }                                        

    // Set the result status and return
    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_INFORMATION, Status, &IoStatus);
    return TRUE;
}

static int OnQueryFsInfoClick(HWND hDlg)
{
    FS_INFORMATION_CLASS FsInfoClass;
    TFileTestData * pData = GetDialogData(hDlg);
    TInfoData * pInfoData;
    IO_STATUS_BLOCK IoStatus = {0};
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Length = 0;

    // Test if the handle is an NT file handle and get the file info class
    if(IsHandleValid(pData->hFile) == FALSE)
        return FALSE;
    
    // Get the selected info data
    pInfoData = GetSelectedInfoClass(hDlg, IDC_VOL_INFO_CLASS, FsInfoData);
    if(pInfoData == NULL)
        return FALSE;

    // Get the file system info class
    FsInfoClass = (FS_INFORMATION_CLASS)(pInfoData->InfoClass);

    // Get the input length
    DlgText2Hex32(hDlg, IDC_INPUT_LENGTH, &Length);

    // If the required length is bigger than the current one, reallocate the buffer
    pData->NtInfoData.SetLength(Length);

    // Perform the call
    if(NT_SUCCESS(Status))
    {
        Status = NtQueryVolumeInformationFile(pData->hFile,
                                             &IoStatus,
                                              pData->NtInfoData.pbData,
                                              Length,
                                              FsInfoClass);
    }                                        

    // If succeeded, we have to fill the dialog with file info
    if(NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
        FillDialogWithFileInfo(hDlg, FsInfoData, (int)FsInfoClass);

    // Set the result status and return
    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_INFORMATION, Status, &IoStatus);
    return TRUE;
}

static int OnSetFsInfoClick(HWND hDlg)
{
    FS_INFORMATION_CLASS FsInfoClass;
    TFileTestData * pData = GetDialogData(hDlg);
    IO_STATUS_BLOCK IoStatus = {0};
    TInfoData * pInfoData;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Length = 0;

    // Test if the handle is an NT file handle and get the file info class
    if(IsHandleValid(pData->hFile) == FALSE)
        return FALSE;

    // Get the selected info data
    pInfoData = GetSelectedInfoClass(hDlg, IDC_VOL_INFO_CLASS, FsInfoData);
    if(pInfoData == NULL)
        return FALSE;

    // Get the file system info class
    FsInfoClass = (FS_INFORMATION_CLASS)(pInfoData->InfoClass);

    // Get the length of the input data
    DlgText2Hex32(hDlg, IDC_INPUT_LENGTH, &Length);

    // If the required length is bigger than the current one, reallocate the buffer
    pData->NtInfoData.SetLength(Length);

    // Call NtSetInformationFile
    if(NT_SUCCESS(Status))
    {
        Status = NtSetVolumeInformationFile(pData->hFile,
                                           &IoStatus,
                                            pData->NtInfoData.pbData,
                                            Length,
                                            FsInfoClass);
    }                                        

    // Set the result status and return
    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_INFORMATION, Status, &IoStatus);
    return TRUE;
}

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    if(nNotify == BN_CLICKED || nNotify == 1)
    {
        switch(nIDCtrl)
        {
            case ID_EDIT_LABEL:
                return TreeView_EditLabel_ID(hDlg, IDC_FILE_INFO);

            case IDC_DEFAULT_LENGTH:
                return OnDefaultLengthClick(hDlg);

            case IDC_MAXIMUM_LENGTH:
                return OnMaximumLengthClick(hDlg);

            case IDC_QUERY_INFO:
                return OnQueryInfoClick(hDlg);

            case IDC_QUERY_DIR:
                return OnQueryDirClick(hDlg);

            case IDC_SET_INFO:
                return OnSetInfoClick(hDlg);

            case IDC_QUERY_VOL_INFO:
                return OnQueryFsInfoClick(hDlg);

            case IDC_SET_VOL_INFO:
                return OnSetFsInfoClick(hDlg);
        }
    }

    // Extra handling for comboboxes with info class
    if(nIDCtrl == IDC_FILE_INFO_CLASS || nIDCtrl == IDC_VOL_INFO_CLASS)
    {
        switch(nNotify)
        {
            // Provide more convenient item search than the default one    
            case CBN_EDITUPDATE:
                OnComboBoxEditUpdate(hDlg, nIDCtrl, (nIDCtrl == IDC_FILE_INFO_CLASS) ? FileInfoData : FsInfoData);
                return TRUE;

            // If the selection has been changed, reflect it in the dialog
            case CBN_SELENDOK:
                OnComboBoxItemSelected(hDlg, nIDCtrl, (nIDCtrl == IDC_FILE_INFO_CLASS) ? FileInfoData : FsInfoData);
                return TRUE;
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

        case PSN_KILLACTIVE:
            TimerTooltipProc(hDlg, WM_TIMER, 0, 0);
            break;

        case TVN_SELCHANGED:
            TimerTooltipProc(hDlg, WM_TIMER, 0, 0);
            break;

        case TVN_BEGINLABELEDIT:
            return OnBeginLabelEdit(hDlg, (NMTVDISPINFO *)pNMHDR);

        case TVN_ENDLABELEDIT:
            return OnEndLabelEdit(hDlg, (NMTVDISPINFO *)pNMHDR);

        case TVN_KEYDOWN:
            return OnTVKeyDown_CopyToClipboard(hDlg, (LPNMTVKEYDOWN)pNMHDR);

        case NM_DBLCLK:
            return OnDoubleClick(hDlg, pNMHDR);
    }
    return FALSE;
}

static int OnDestroy(HWND hDlg)
{
    TimerTooltipProc(hDlg, WM_TIMER, 0, 0);

    // Free the first anchors, if exist
    if(pAnchors1 != NULL && pAnchors1->GetParentWindow() == hDlg)
    {
        delete pAnchors1;
        pAnchors1 = NULL;
    }

    // Free the second anchors, if exist
    if(pAnchors2 != NULL && pAnchors2->GetParentWindow() == hDlg)
    {
        delete pAnchors2;
        pAnchors2 = NULL;
    }

    // Close the target directory handle
    if(IsHandleValid(hDirTarget))
        NtClose(hDirTarget);
    hDirTarget = NULL;
    return FALSE;
}

//-----------------------------------------------------------------------------
// Public functions

INT_PTR CALLBACK PageProc06(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
        case WM_INITDIALOG:
            return OnInitDialog(hDlg, lParam);

        case WM_SIZE:
            if(pAnchors1 != NULL && pAnchors1->GetParentWindow() == hDlg)
                pAnchors1->OnMessage(uMsg, wParam, lParam);
            if(pAnchors2 != NULL && pAnchors2->GetParentWindow() == hDlg)
                pAnchors2->OnMessage(uMsg, wParam, lParam);
            return FALSE;

        case WM_ACTIVATE:
            if(wParam == WA_INACTIVE)
                TimerTooltipProc(hDlg, WM_TIMER, 0, 0);
            break;

        case WM_RELOADITEMS:
            return OnReloadItems(hDlg, (HWND)wParam, (HTREEITEM)lParam);

        case WM_SHOW_DATE_FORMATS:
            return OnShowDateFormats(hDlg, (HWND)wParam, (HTREEITEM)lParam);

        case WM_COMMAND:
            return OnCommand(hDlg, HIWORD(wParam), LOWORD(wParam));

        case WM_NOTIFY:
            return OnNotify(hDlg, (NMHDR *)lParam);

        case WM_DESTROY:
            return OnDestroy(hDlg);
    }
    return FALSE;
}
