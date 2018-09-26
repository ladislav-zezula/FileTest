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
// Local structures

#define WM_RELOADITEMS       (WM_USER + 0x1000)
#define WM_SHOW_DATE_FORMATS (WM_USER + 0x1001)

static UNICODE_STRING NullString = RTL_CONSTANT_STRING(L"NULL");

//-----------------------------------------------------------------------------
// Description of data structures for file info classes

// Values for FILE_FS_ATTRIBUTE_INFORMATION::FileSystemAttributes
TFlagInfo FileSystemAttributesValues[] =
{
    FLAG_INFO_ENTRY(FILE_CASE_SENSITIVE_SEARCH),
    FLAG_INFO_ENTRY(FILE_CASE_PRESERVED_NAMES),
    FLAG_INFO_ENTRY(FILE_UNICODE_ON_DISK),
    FLAG_INFO_ENTRY(FILE_PERSISTENT_ACLS),
    FLAG_INFO_ENTRY(FILE_FILE_COMPRESSION),
    FLAG_INFO_ENTRY(FILE_VOLUME_QUOTAS),
    FLAG_INFO_ENTRY(FILE_SUPPORTS_SPARSE_FILES),
    FLAG_INFO_ENTRY(FILE_SUPPORTS_REPARSE_POINTS),
    FLAG_INFO_ENTRY(FILE_SUPPORTS_REMOTE_STORAGE),
    FLAG_INFO_ENTRY(FILE_RETURNS_CLEANUP_RESULT_INFO),
    FLAG_INFO_ENTRY(FILE_SUPPORTS_POSIX_UNLINK_RENAME),
    FLAG_INFO_ENTRY(FILE_VOLUME_IS_COMPRESSED),
    FLAG_INFO_ENTRY(FILE_SUPPORTS_OBJECT_IDS),
    FLAG_INFO_ENTRY(FILE_SUPPORTS_ENCRYPTION),
    FLAG_INFO_ENTRY(FILE_NAMED_STREAMS),
    FLAG_INFO_ENTRY(FILE_READ_ONLY_VOLUME),
    FLAG_INFO_ENTRY(FILE_SEQUENTIAL_WRITE_ONCE),
    FLAG_INFO_ENTRY(FILE_SUPPORTS_TRANSACTIONS),
    FLAG_INFO_ENTRY(FILE_SUPPORTS_HARD_LINKS),
    FLAG_INFO_ENTRY(FILE_SUPPORTS_EXTENDED_ATTRIBUTES),
    FLAG_INFO_ENTRY(FILE_SUPPORTS_OPEN_BY_FILE_ID),
    FLAG_INFO_ENTRY(FILE_SUPPORTS_USN_JOURNAL),
    FLAG_INFO_END
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
    {_T("AccessFlags"),     TYPE_UINT32, sizeof(ACCESS_MASK)},
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
    {_T("Mode"),            TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileAlignmentInformationMembers[] =
{
    {_T("AlignmentRequirement"), TYPE_UINT32, sizeof(ULONG)},
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

TStructMember FilePipeInformationMembers[] =
{
    {_T("ReadMode"),        TYPE_UINT32, sizeof(ULONG)},
    {_T("CompletionMode"),  TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FilePipeLocalInformationMembers[] =
{
    {_T("NamedPipeType"),          TYPE_UINT32, sizeof(ULONG)},
    {_T("NamedPipeConfiguration"), TYPE_UINT32, sizeof(ULONG)},
    {_T("MaximumInstances"),       TYPE_UINT32, sizeof(ULONG)},
    {_T("CurrentInstances"),       TYPE_UINT32, sizeof(ULONG)},
    {_T("InboundQuota"),           TYPE_UINT32, sizeof(ULONG)},
    {_T("ReadDataAvailable"),      TYPE_UINT32, sizeof(ULONG)},
    {_T("OutboundQuota"),          TYPE_UINT32, sizeof(ULONG)},
    {_T("WriteQuotaAvailable"),    TYPE_UINT32, sizeof(ULONG)},
    {_T("NamedPipeState"),         TYPE_UINT32, sizeof(ULONG)},
    {_T("NamedPipeEnd"),           TYPE_UINT32, sizeof(ULONG)},
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

TStructMember FileCompressionInformationMembers[] =
{
    {_T("CompressedFileSize"), TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("CompressionFormat"), TYPE_UINT16, sizeof(USHORT)},
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
    {_T("FileReference"),   TYPE_UINT64,       sizeof(LONGLONG)},
    {_T("ObjectId"),        TYPE_ARRAY8_FIXED, sizeof(UCHAR[16])},
    {_T("BirthVolumeId"),   TYPE_ARRAY8_FIXED, sizeof(UCHAR[16])},
    {_T("BirthObjectId"),   TYPE_ARRAY8_FIXED, sizeof(UCHAR[16])},
    {_T("DomainId"),        TYPE_ARRAY8_FIXED, sizeof(UCHAR[16])},
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
    {_T("Sid"),             TYPE_NONE,     sizeof(SID)},
    {NULL, TYPE_NONE, 0}
};

TStructMember FileReparsePointInformationMembers[] =
{
    {_T("FileReference"),   TYPE_UINT64,   sizeof(LONGLONG)},
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

TStructMember FileIoPriorityHintInformationMembers[] =
{
    {_T("PriorityHint"),    TYPE_UINT32,  sizeof(IO_PRIORITY_HINT)},
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
    {_T("LockingTransactionId"), TYPE_ARRAY8_FIXED, sizeof(GUID)},
    {_T("TxInfoFlags"),     TYPE_UINT32,   sizeof(ULONG)},
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
    {_T("VolumeSerialNumber"), TYPE_UINT64,     sizeof(ULONG)},
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
//  FLAG_INFO_ENTRY(FILE_DISPOSITION_DO_NOT_DELETE),               // Zero; not an actual flag
    FLAG_INFO_ENTRY(FILE_DISPOSITION_DELETE),
    FLAG_INFO_ENTRY(FILE_DISPOSITION_POSIX_SEMANTICS),
    FLAG_INFO_ENTRY(FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK),
    FLAG_INFO_ENTRY(FILE_DISPOSITION_ON_CLOSE),
    FLAG_INFO_END
};

TStructMember FileDispositionInformationExMembers[] =
{
    { _T("DispositionFlags"),              TYPE_FLAG32, sizeof(ULONG), NULL, {(TStructMember *)FileDispositionInformationExValues}},
    { NULL, TYPE_NONE, 0 }
};

TFlagInfo FileRenameInformationExValues[] =
{
	FLAG_INFO_ENTRY(FILE_RENAME_REPLACE_IF_EXISTS),
	FLAG_INFO_ENTRY(FILE_RENAME_POSIX_SEMANTICS),
	FLAG_INFO_END
};

TStructMember FileRenameInformationExMembers[] =
{
	{ _T("Flags"), 			 TYPE_FLAG32,	  sizeof(ULONG), NULL, {(TStructMember *)FileRenameInformationExValues}},
	{ _T("<padding>"),       TYPE_PADDING,    sizeof(HANDLE) },
	{ _T("RootDirectory"),   TYPE_DIR_HANDLE, sizeof(HANDLE) },
	{ _T("FileNameLength"),  TYPE_UINT32,     sizeof(ULONG) },
	{ _T("FileName"),        TYPE_WNAME_L32B, FIELD_OFFSET(FILE_RENAME_INFORMATION_EX, FileNameLength) },
	{ NULL, TYPE_NONE, 0 }
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
    {_T("EffectiveAccess"), TYPE_UINT32,   sizeof(ULONG)},
    { NULL, TYPE_NONE, 0 }
};

#define FileAttributeCacheInformationMembers            FileUnknownInformationMembers
#define FileStandardLinkInformationMembers              FileUnknownInformationMembers
#define FileRenameInformationBypassAccessCheckMembers   FileRenameInformationMembers
#define FileLinkInformationBypassAccessCheckMembers     FileLinkInformationMembers
#define FileReplaceCompletionInformationMembers         FileUnknownInformationMembers
#define FileHardLinkFullIdInformationMembers            FileUnknownInformationMembers
#define FileRenameInformationExMembers                  FileRenameInformationExMembers
#define FileRenameInformationExBypassAccessCheckMembers FileUnknownInformationMembers
#define FileDesiredStorageClassInformationMembers       FileUnknownInformationMembers

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
    FILE_INFO_READONLY(FileCompletionInformation,               FILE_COMPLETION_INFORMATION,                 FALSE),
    FILE_INFO_READONLY(FileMoveClusterInformation,              FILE_MOVE_CLUSTER_INFORMATION,               FALSE),
    FILE_INFO_READONLY(FileQuotaInformation,                    FILE_QUOTA_INFORMATION,                      TRUE),
    FILE_INFO_READONLY(FileReparsePointInformation,             FILE_REPARSE_POINT_INFORMATION,              FALSE),
    FILE_INFO_EDITABLE(FileNetworkOpenInformation,              FILE_NETWORK_OPEN_INFORMATION,               FALSE),
    FILE_INFO_EDITABLE(FileAttributeTagInformation,             FILE_ATTRIBUTE_TAG_INFORMATION,              FALSE),
    FILE_INFO_READONLY(FileTrackingInformation,                 FILE_TRACKING_INFORMATION,                   FALSE),
    FILE_INFO_READONLY(FileIdBothDirectoryInformation,          FILE_ID_BOTH_DIR_INFORMATION,                TRUE),
    FILE_INFO_READONLY(FileIdFullDirectoryInformation,          FILE_ID_FULL_DIR_INFORMATION,                TRUE),
    FILE_INFO_EDITABLE(FileValidDataLengthInformation,          FILE_VALID_DATA_LENGTH_INFORMATION,          FALSE),
    FILE_INFO_READONLY(FileShortNameInformation,                FILE_NAME_INFORMATION,                       FALSE),
    FILE_INFO_READONLY(FileIoCompletionNotificationInformation, FILE_IO_COMPLETION_NOTIFICATION_INFORMATION, FALSE),
    FILE_INFO_READONLY(FileIoStatusBlockRangeInformation,       FILE_IOSTATUSBLOCK_RANGE_INFORMATION,        FALSE),
    FILE_INFO_READONLY(FileIoPriorityHintInformation,           FILE_IO_PRIORITY_HINT_INFORMATION,           FALSE),
    FILE_INFO_READONLY(FileSfioReserveInformation,              FILE_SFIO_RESERVE_INFORMATION,               FALSE),
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
    FILE_INFO_READONLY(FileRenameInformationBypassAccessCheck,  FILE_RENAME_INFORMATION,                     TRUE),
    FILE_INFO_READONLY(FileLinkInformationBypassAccessCheck,    FILE_LINK_INFORMATION,                       FALSE),
    FILE_INFO_READONLY(FileVolumeNameInformation,               FILE_VOLUME_NAME_INFORMATION,                FALSE),
    FILE_INFO_READONLY(FileIdInformation,                       FILE_ID_INFORMATION,                         FALSE),
    FILE_INFO_READONLY(FileIdExtdDirectoryInformation,          FILE_ID_EXTD_DIR_INFORMATION,                TRUE),
    FILE_INFO_READONLY(FileReplaceCompletionInformation,        FILE_UNKNOWN_INFORMATION,                    FALSE),
    FILE_INFO_READONLY(FileHardLinkFullIdInformation,           FILE_UNKNOWN_INFORMATION,                    FALSE),
    FILE_INFO_READONLY(FileIdExtdBothDirectoryInformation,      FILE_ID_EXTD_BOTH_DIR_INFORMATION,           TRUE),
    FILE_INFO_EDITABLE(FileDispositionInformationEx,            FILE_DISPOSITION_INFORMATION_EX,             FALSE),
    FILE_INFO_EDITABLE(FileRenameInformationEx,                 FILE_RENAME_INFORMATION_EX,                  FALSE),
    FILE_INFO_READONLY(FileRenameInformationExBypassAccessCheck,FILE_UNKNOWN_INFORMATION,                    FALSE),
    FILE_INFO_READONLY(FileDesiredStorageClassInformation,      FILE_UNKNOWN_INFORMATION,                    FALSE),
    FILE_INFO_READONLY(FileStatInformation,                     FILE_STAT_INFORMATION,                       FALSE),

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
    {_T("TotalAllocationUnits"), TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("AvailableAllocationUnits"), TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("SectorsPerAllocationUnit"),  TYPE_UINT32, sizeof(ULONG)},
    {_T("BytesPerSector"),      TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};


TStructMember FileFsDeviceInformationMembers[] =
{   
    {_T("DeviceType"),           TYPE_UINT32, sizeof(ULONG)},
    {_T("Characteristics"),      TYPE_UINT32, sizeof(ULONG)},
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


TStructMember FileFsControlInformationMembers[] =
{   
    {_T("FreeSpaceStartFiltering"),    TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("FreeSpaceThreshold"),         TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("FreeSpaceStopFiltering"),     TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("DefaultQuotaThreshold"),      TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("DefaultQuotaLimit"),          TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("FileSystemControlFlags"),     TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};


TStructMember FileFsFullSizeInformationMembers[] =
{   
    {_T("TotalAllocationUnits"),    TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("CallerAvailableAllocationUnits"), TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("ActualAvailableAllocationUnits"),     TYPE_UINT64, sizeof(LARGE_INTEGER)},
    {_T("SectorsPerAllocationUnit"),     TYPE_UINT32, sizeof(ULONG)},
    {_T("BytesPerSector"),              TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};


TStructMember FileFsObjectIdInformationMembers[] =
{   
    {_T("ObjectId"),     TYPE_ARRAY8_FIXED, sizeof(UCHAR[16])},
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

TStructMember FileFsSectorSizeInformationMembers[] =
{   
    {_T("LogicalBytesPerSector"),               TYPE_UINT32, sizeof(ULONG)},
    {_T("PhysicalBytesPerSectorForAtomicity"),  TYPE_UINT32, sizeof(ULONG)},
    {_T("PhysicalBytesPerSectorForPerformance"), TYPE_UINT32, sizeof(ULONG)},
    {_T("FileSystemEffectivePhysicalBytesPerSectorForAtomicity"), TYPE_UINT32, sizeof(ULONG)},
    {_T("Flags"),                               TYPE_UINT32, sizeof(ULONG)},
    {_T("ByteOffsetForSectorAlignment"),        TYPE_UINT32, sizeof(ULONG)},
    {_T("ByteOffsetForPartitionAlignment"),     TYPE_UINT32, sizeof(ULONG)},
    {NULL, TYPE_NONE, 0}
};

#define FileFsDataCopyInformationMembers FileUnknownInformationMembers

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
    FILE_INFO_EDITABLE(FileFsDataCopyInformation,      FILE_UNKNOWN_INFORMATION,             FALSE),
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

static int FillChainedStructMembers(
    HWND hTreeView,
    HTREEITEM hParentItem,
    TStructMember * pMembers,
    LPBYTE pbData,
    LPBYTE pbDataEnd
    );

//-----------------------------------------------------------------------------
// Conversion functions

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
    SendMessage(hWndCombo, WM_SETREDRAW, FALSE, 0);
    
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
    SendMessage(hWndCombo, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hWndCombo, NULL, TRUE);
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
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
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
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
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
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             FILE_OPEN_BY_FILE_ID);

        // Perhaps it's a reparse point?
        if(Status == STATUS_INVALID_PARAMETER)
        {
            Status = NtOpenFile(&FileHandle,
                                 FILE_READ_ATTRIBUTES,
                                &ObjAttr,
                                &IoStatus,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 FILE_OPEN_BY_FILE_ID | FILE_OPEN_REPARSE_POINT);
        }
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

        case TYPE_ARRAY8_FIXED:
        case TYPE_FILEID128:
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

        case TYPE_FLAG32:
        {
            PULONG pulValue = (PULONG)pMember->pbStructPtr;
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
    TCHAR szItemText[128] = _T("");

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
        if(DataToItemText(pMemberInfo, szItemText, _maxchars(szItemText), FALSE) == ERROR_SUCCESS)
            InsertTreeItem(hTreeView, hParentItem, szItemText, pMemberInfo);
    }

    return pMember->nMemberSize;
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
                if(DataToItemText(pMemberInfo, szItemText, _maxchars(szItemText), FALSE) == ERROR_SUCCESS)
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
            if(DataToItemText(pMemberInfo, szItemText, _maxchars(szItemText), FALSE) == ERROR_SUCCESS)
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
            if(DataToItemText(pMemberInfo, szItemText, _maxchars(szItemText), FALSE) == ERROR_SUCCESS)
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


static int FillStructureMembers(
    HWND hTreeView,
    HTREEITEM hParentItem,
    TStructMember * pMembers,
    LPBYTE pbData,
    LPBYTE pbDataEnd)
{
    HTREEITEM hSubItem;
    LPBYTE pbStructPtr = pbData;        // Pointer to the begin of the structure
    TCHAR szBuffer[256];
    int nTotalLength = 0;               // Length, in bytes, of the structure member

    // Hack: In Windows 10, the FILE_STANDARD_INFORMATION becomes FILE_STANDARD_INFORMATION_EX
    if (pMembers == FileStandardInformationMembers && g_dwWinVer >= 0x0A00)
        pMembers = FileStandardInformationMembersEx;

    // Parse the members and fill them
    for(; pMembers->szMemberName != NULL; pMembers++)
    {
        int nDataLength = 0;

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
                nDataLength = FillChainedStructMembers(hTreeView, 
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
                        HANDLE ProcessId = HandleArray[i];

                        StringCchPrintf(szBuffer, _countof(szBuffer), _T("[0x%02X]: %p"), i, ProcessId);
                        InsertTreeItem(hTreeView, hSubItem, szBuffer);
                        nDataLength += sizeof(UINT_PTR);
                    }
                }
                break;
            }

            case TYPE_FLAG32:   // Insert the flag array
                nDataLength = InsertTreeItemFlags32(hTreeView, hParentItem, pMembers, pbData, pbDataEnd);

				// If there is an alignment following the data member, do a proper alignment
				if (pMembers[1].nDataType == TYPE_PADDING)
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
static int FillChainedStructMembers(
    HWND hTreeView,
    HTREEITEM hParentItem,
    TStructMember * pMembers,
    LPBYTE pbData,
    LPBYTE pbDataEnd)
{
    HTREEITEM hItem;
    TCHAR szItemName[128];
    ULONG NextEntryOffset;
    int nDataLength = 0;
    int nIndex = 0;

    // Insert infos about the streams
    while(pbData < pbDataEnd)
    {
        StringCchPrintf(szItemName, _countof(szItemName), _T("[%u]"), nIndex++);
        hItem = InsertTreeItem(hTreeView, hParentItem, szItemName, pbData);
        FillStructureMembers(hTreeView, hItem, pMembers, pbData, pbDataEnd);

        // If the "NextEntryOffset" is zero, we stop searching
        NextEntryOffset = *(PULONG)pbData;
        if(NextEntryOffset == 0)
            break;

        // Move to the next structure by simply adding the NextEntryOffset
        // to the current pointer. Also add NextEntryOffset to data size 
        nDataLength += NextEntryOffset;
        pbData += NextEntryOffset;
    }

    // At the end, we have to round the structure size up to 8-byte boundary
    // Return the total length of the stream info
    TreeView_Expand(hTreeView, hParentItem, TVE_EXPAND);
    return nDataLength;
}

static int FillDialogWithFileInfo(HWND hDlg, TInfoData * pInfoData, int nInfoClass)
{
    TFileTestData * pData = GetDialogData(hDlg);
    HTREEITEM hRootItem = NULL;
    LPBYTE pbNtInfoBuffEnd = pData->pbNtInfoBuff + pData->cbNtInfoBuff;
    HWND hTreeView = GetDlgItem(hDlg, IDC_FILE_INFO);
    HWND hComment = GetDlgItem(hDlg, IDC_COMMENT);
    UINT nInputLength = 0;
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
                                                    pData->pbNtInfoBuff,
                                                    pbNtInfoBuffEnd);
            }
            else
            {
                nInputLength = FillChainedStructMembers(hTreeView, 
                                                        hRootItem,
                                                        pInfoData->pStructMembers,
                                                        pData->pbNtInfoBuff,
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
    int nError = ERROR_CAN_NOT_COMPLETE;

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
                    nError = ERROR_SUCCESS;
                CloseClipboard();
            }
        }

        GlobalFree(hMem);
    }

    return nError;
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
            pAnchors1 = new TAnchors();
            pAnchors = pAnchors1;
        }

        if(GetDlgItem(hDlg, IDC_QUERY_VOL_INFO) != NULL)
        {
            pAnchors2 = new TAnchors();
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
        pAnchors->AddAnchor(hDlg, IDC_RESULT_STATUS_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_STATUS, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_IOSTATUS_INFO_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_IOSTATUS_INFO, akLeft | akRight | akBottom);
    }

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
    Hex2DlgText32(hDlg, IDC_INPUT_LENGTH, pData->cbNtInfoBuff);

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
    LoadString(g_hInst, IDS_BAD_DATETIME_FORMAT, szTitle, _maxchars(szTitle));
    LoadString(g_hInst, IDS_DATE_FORMAT_PREFIX, szDateFormatPrefix, _maxchars(szDateFormatPrefix));
    LoadString(g_hInst, IDS_TIME_FORMAT_PREFIX, szTimeFormatPrefix, _maxchars(szTimeFormatPrefix));
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

        SetResultInfo(hDlg, CantEditStatus);
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
            if(DataToItemText(pMemberInfo, szItemText, _maxchars(szItemText), TRUE) == ERROR_SUCCESS)
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
            SetResultInfo(hDlg, Status);
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
            StringCchCopy(pData->szFileName1, _countof(pData->szFileName1), szFileName);
            TabCtrl_SelectPageByID(hTabCtrl, MAKEINTRESOURCE(IDD_PAGE02_NTCREATE));
            delete [] szFileName;
        }
    }

    // Doubleclick on TYPE_FLAG32 opens a dialog with flags
    if(pMemberInfo->nDataType == TYPE_FLAG32)
    {
        PDWORD PtrFlags = (PDWORD)pMemberInfo->pbStructPtr;

        if(FlagsDialog(hDlg, PtrFlags, IDS_ENTER_FLAGS, pMemberInfo->pFlags))
        {
            // Only change the item if editable
            pInfoData = GetSelectedInfoClass(hDlg, IDC_FILE_INFO_CLASS, FileInfoData);
            if(pInfoData != NULL && pInfoData->bIsEditable)
            {
                hParentItem = TreeView_GetNextItem(hTreeView, hItem, TVGN_PARENT);
                PostMessage(hDlg, WM_RELOADITEMS, (WPARAM)hTreeView, (LPARAM)hParentItem);
            }
        }
    }

    return TRUE;
}

static int OnEditLabel(HWND hDlg)
{
    HTREEITEM hItem;
    HWND hTreeView = GetDlgItem(hDlg, IDC_FILE_INFO);

    // Only start editing if the tree view has focus
    if(GetFocus() == hTreeView)
    {
        hItem = TreeView_GetSelection(hTreeView);
        if(hItem != NULL)
            TreeView_EditLabel(hTreeView, hItem);
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
        ZeroMemory(pData->pbNtInfoBuff, pData->cbNtInfoBuff);
        FillDialogWithFileInfo(hDlg, pInfoData, 1);
        Hex2DlgText32(hDlg, IDC_INPUT_LENGTH, pData->cbNtInfoBuff);
    }

    return TRUE;
}

static int OnDefaultLengthClick(HWND hDlg)
{
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

    Hex2DlgText32(hDlg, IDC_INPUT_LENGTH, nDataLength);
    return TRUE;
}

static int OnMaximumLengthClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    Hex2DlgText32(hDlg, IDC_INPUT_LENGTH, pData->cbNtInfoBuff);
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
    if(Length > pData->cbNtInfoBuff) 
    {
        if(pData->pbNtInfoBuff != NULL)
            HeapFree(g_hHeap, 0, pData->pbNtInfoBuff);
        pData->pbNtInfoBuff = (LPBYTE)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, Length);
        pData->cbNtInfoBuff = Length;
    }

    // Perform the call
    if(NT_SUCCESS(Status))
    {
        Status = NtQueryInformationFile(pData->hFile,
                                        &IoStatus,
                                        pData->pbNtInfoBuff,
                                        Length,
                                        FileInfoClass);
    }                                        

    // If succeeded, we have to fill the dialog with file info
    if(NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
        FillDialogWithFileInfo(hDlg, FileInfoData, (int)FileInfoClass);

    // Set the result status and return
    SetResultInfo(hDlg, Status, NULL, IoStatus.Information);
    return TRUE;
}


static int OnQueryDirClick(HWND hDlg)
{
    FILE_INFORMATION_CLASS FileInfoClass;
    TFileTestData * pData = GetDialogData(hDlg);
    IO_STATUS_BLOCK IoStatus = {0};
    PUNICODE_STRING FileMask = NULL;
    TInfoData * pInfoData;
    NTSTATUS Status = STATUS_SUCCESS;
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
    if(Length > pData->cbNtInfoBuff) 
    {
        if(pData->pbNtInfoBuff != NULL)
            HeapFree(g_hHeap, 0, pData->pbNtInfoBuff);
        pData->pbNtInfoBuff = (LPBYTE)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, Length);
        pData->cbNtInfoBuff = Length;
    }

    // Perform the call
    if(NT_SUCCESS(Status))
    {
        hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        if(hEvent == NULL)
            Status = STATUS_UNSUCCESSFUL;
    }

    if(NT_SUCCESS(Status))
    {
        Status = NtQueryDirectoryFile(pData->hFile,
                                      hEvent,
                                      NULL,
                                      NULL,
                                     &IoStatus,
                                      pData->pbNtInfoBuff,
                                      Length, 
                                      FileInfoClass,
                                      FALSE,
                                      FileMask,
                                      TRUE);

        // If the operation is pending, we have to wait until it's complete
        if(Status == STATUS_PENDING)
        {
            WaitForSingleObject(hEvent, INFINITE);
            Status = IoStatus.Status;
        }
    }                                        

    // If succeeded, we have to fill the dialog with file info
    if(NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
        FillDialogWithFileInfo(hDlg, FileInfoData, (int)FileInfoClass);
    SetResultInfo(hDlg, Status, NULL, IoStatus.Information);

    // Set the result status and return
    if(hEvent != NULL)
        CloseHandle(hEvent);
    if(FileMask != NULL)
        HeapFree(g_hHeap, 0, FileMask);
    return TRUE;
}

static int OnSetInfoClick(HWND hDlg)
{
    FILE_INFORMATION_CLASS FileInfoClass;
    TFileTestData * pData = GetDialogData(hDlg);
    IO_STATUS_BLOCK IoStatus = {0};
    TInfoData * pInfoData;
    NTSTATUS Status = STATUS_SUCCESS;
    LPBYTE pbNtInfoBuff = pData->pbNtInfoBuff;
    ULONG cbNtInfoBuff = pData->cbNtInfoBuff;
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
    if(Length > pData->cbNtInfoBuff) 
    {
        // Allocate new buffer
        pData->pbNtInfoBuff = (LPBYTE)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, Length);
        pData->cbNtInfoBuff = Length;

        // Copy old buffer to the new one
        if(pData->pbNtInfoBuff != NULL && pbNtInfoBuff != NULL)
            memcpy(pData->pbNtInfoBuff, pbNtInfoBuff, cbNtInfoBuff);
        if(pbNtInfoBuff != NULL)
            HeapFree(g_hHeap, 0, pbNtInfoBuff);
    }

    // Call NtSetInformationFile
    if(NT_SUCCESS(Status))
    {
        Status = NtSetInformationFile(pData->hFile,
                                     &IoStatus,
                                      pData->pbNtInfoBuff,
                                      Length,
                                      FileInfoClass);
    }                                        

    // Set the result status and return
    SetResultInfo(hDlg, Status, NULL, IoStatus.Information);
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
    if(Length > pData->cbNtInfoBuff) 
    {
        if(pData->pbNtInfoBuff != NULL)
            HeapFree(g_hHeap, 0, pData->pbNtInfoBuff);
        pData->pbNtInfoBuff = (LPBYTE)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, Length);
        pData->cbNtInfoBuff = Length;
    }

    // Perform the call
    if(NT_SUCCESS(Status))
    {
        Status = NtQueryVolumeInformationFile(pData->hFile,
                                             &IoStatus,
                                              pData->pbNtInfoBuff,
                                              Length,
                                              FsInfoClass);
    }                                        

    // If succeeded, we have to fill the dialog with file info
    if(NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
        FillDialogWithFileInfo(hDlg, FsInfoData, (int)FsInfoClass);

    // Set the result status and return
    SetResultInfo(hDlg, Status, NULL, IoStatus.Information);
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
    if(Length > pData->cbNtInfoBuff) 
    {
        if(pData->pbNtInfoBuff != NULL)
            HeapFree(g_hHeap, 0, pData->pbNtInfoBuff);
        pData->pbNtInfoBuff = (LPBYTE)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, Length);
        pData->cbNtInfoBuff = Length;
    }

    // Call NtSetInformationFile
    if(NT_SUCCESS(Status))
    {
        Status = NtSetVolumeInformationFile(pData->hFile,
                                           &IoStatus,
                                            pData->pbNtInfoBuff,
                                            Length,
                                            FsInfoClass);
    }                                        

    // Set the result status and return
    SetResultInfo(hDlg, Status, NULL, IoStatus.Information);
    return TRUE;
}

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    if(nNotify == BN_CLICKED || nNotify == 1)
    {
        switch(nIDCtrl)
        {
            case ID_EDIT_LABEL:
                return OnEditLabel(hDlg);

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
                pAnchors1->OnSize();
            if(pAnchors2 != NULL && pAnchors2->GetParentWindow() == hDlg)
                pAnchors2->OnSize();
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
            TimerTooltipProc(hDlg, WM_TIMER, 0, 0);

            if(IsHandleValid(hDirTarget))
                NtClose(hDirTarget);
            if(pAnchors2 != NULL)
                delete pAnchors2;
            if(pAnchors1 != NULL)
                delete pAnchors1;
            pAnchors2 = pAnchors1 = NULL;
            hDirTarget = NULL;
            return FALSE;
    }
    return FALSE;
}
