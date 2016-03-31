/*****************************************************************************/
/* WinSDK.h                               Copyright (c) Ladislav Zezula 2016 */
/*---------------------------------------------------------------------------*/
/* Definitions for constants missing in SDK vor Visual Studio 2005           */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 08.01.16  1.00  Lad  The first version of WinSDK.h                        */
/*****************************************************************************/

#ifndef __WINSDK_H__
#define __WINSDK_H__

//-----------------------------------------------------------------------------
// Window messages (not included in VS 2005 SDK)

#ifndef WM_MOUSEWHEEL
#define WM_MOUSEWHEEL                   0x020A
#endif

//-----------------------------------------------------------------------------
// Progress bar (not included in VS 2005 SDK)

#ifndef PBS_MARQUEE
#define PBS_MARQUEE             0x08
#define PBM_SETMARQUEE          (WM_USER+10)
#endif

//-----------------------------------------------------------------------------
// Command button (not included in VS 2005 SDK)

#ifndef BS_COMMANDLINK
#define BS_COMMANDLINK          0x0000000EL
#define BS_DEFCOMMANDLINK       0x0000000FL
#endif

//-----------------------------------------------------------------------------
// Kernel32 definitions (not included in VS 2005 SDK)

#ifndef FILE_FLAG_SESSION_AWARE
#define FILE_FLAG_SESSION_AWARE             0x00800000
#endif

#ifndef FILE_SESSION_AWARE
#define FILE_SESSION_AWARE                  0x00040000
#endif

#ifndef FILE_ATTRIBUTE_INTEGRITY_STREAM
#define FILE_ATTRIBUTE_INTEGRITY_STREAM     0x00008000
#define FILE_ATTRIBUTE_NO_SCRUB_DATA        0x00020000
#define FILE_ATTRIBUTE_EA                   0x00040000
#endif

#ifndef FILE_ATTRIBUTE_VIRTUAL
#define FILE_ATTRIBUTE_VIRTUAL              0x00010000  
#endif

#ifndef MEM_ROTATE
#define MEM_ROTATE         0x800000     
#endif

#ifndef SEC_PROTECTED_IMAGE
#define SEC_PROTECTED_IMAGE  0x2000000     
#define SEC_WRITECOMBINE 0x40000000     
#endif

#ifndef SECURITY_VALUE_MASK
#define SECURITY_VALUE_MASK                (SECURITY_ANONYMOUS | SECURITY_IDENTIFICATION | SECURITY_IMPERSONATION | SECURITY_DELEGATION)
#endif

#ifndef COPY_FILE_FAIL_IF_EXISTS
#define COPY_FILE_FAIL_IF_EXISTS              0x00000001
#define COPY_FILE_RESTARTABLE                 0x00000002
#define COPY_FILE_OPEN_SOURCE_FOR_WRITE       0x00000004
#define COPY_FILE_ALLOW_DECRYPTED_DESTINATION 0x00000008
#endif

#ifndef MOVEFILE_CREATE_HARDLINK
#define MOVEFILE_CREATE_HARDLINK        0x00000010
#define MOVEFILE_FAIL_IF_NOT_TRACKABLE  0x00000020
#endif

#ifndef TokenElevationType
#define TokenElevationType         (TOKEN_INFORMATION_CLASS)0x12
#define TokenElevation             (TOKEN_INFORMATION_CLASS)0x14
#define TokenVirtualizationEnabled (TOKEN_INFORMATION_CLASS)0x18
#define TokenIntegrityLevel        (TOKEN_INFORMATION_CLASS)0x19
#endif	// TokenElevationType

#ifndef ADS_RIGHT_DELETE
#define ADS_RIGHT_DS_CREATE_CHILD           0x1
#define ADS_RIGHT_DS_DELETE_CHILD           0x2
#define ADS_RIGHT_ACTRL_DS_LIST     	    0x4
#define ADS_RIGHT_DS_SELF           	    0x8
#define ADS_RIGHT_DS_READ_PROP      	    0x10
#define ADS_RIGHT_DS_WRITE_PROP     	    0x20
#define ADS_RIGHT_DS_DELETE_TREE            0x40
#define ADS_RIGHT_DS_LIST_OBJECT            0x80
#define ADS_RIGHT_DS_CONTROL_ACCESS         0x100
#define ADS_RIGHT_DELETE            	    0x10000
#define ADS_RIGHT_READ_CONTROL       	    0x20000
#define ADS_RIGHT_WRITE_DAC         	    0x40000
#define ADS_RIGHT_WRITE_OWNER               0x80000
#define ADS_RIGHT_SYNCHRONIZE               0x100000
#define ADS_RIGHT_ACCESS_SYSTEM_SECURITY    0x1000000
#define ADS_RIGHT_GENERIC_READ              0x80000000
#define ADS_RIGHT_GENERIC_WRITE             0x40000000
#define ADS_RIGHT_GENERIC_EXECUTE           0x20000000
#define ADS_RIGHT_GENERIC_ALL               0x10000000
#endif

//-----------------------------------------------------------------------------
// Mandatory label definitions (not included in VS 2005 SDK)

#ifndef LABEL_SECURITY_INFORMATION
#define LABEL_SECURITY_INFORMATION       (0x00000010L)
#endif

#ifndef SE_GROUP_INTEGRITY
#define SE_GROUP_INTEGRITY                 (0x00000020L)
#define SE_GROUP_INTEGRITY_ENABLED         (0x00000040L)
#endif // SE_GROUP_INTEGRITY

#ifndef ACCESS_ALLOWED_COMPOUND_ACE_TYPE
#define ACCESS_ALLOWED_COMPOUND_ACE_TYPE        (0x4)
#define ACCESS_MAX_MS_V3_ACE_TYPE               (0x4)
#endif

#ifndef ACCESS_MIN_MS_OBJECT_ACE_TYPE
#define ACCESS_MIN_MS_OBJECT_ACE_TYPE           (0x5)
#define ACCESS_ALLOWED_OBJECT_ACE_TYPE          (0x5)
#define ACCESS_DENIED_OBJECT_ACE_TYPE           (0x6)
#define SYSTEM_AUDIT_OBJECT_ACE_TYPE            (0x7)
#define SYSTEM_ALARM_OBJECT_ACE_TYPE            (0x8)
#define ACCESS_MAX_MS_OBJECT_ACE_TYPE           (0x8)
#define ACCESS_MAX_MS_V4_ACE_TYPE               (0x8)
#endif

#ifndef ACCESS_ALLOWED_CALLBACK_ACE_TYPE
#define ACCESS_ALLOWED_CALLBACK_ACE_TYPE        (0x9)
#define ACCESS_DENIED_CALLBACK_ACE_TYPE         (0xA)
#define ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE (0xB)
#define ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  (0xC)
#define SYSTEM_AUDIT_CALLBACK_ACE_TYPE          (0xD)
#define SYSTEM_ALARM_CALLBACK_ACE_TYPE          (0xE)
#define SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   (0xF)
#define SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   (0x10)
#define SYSTEM_MANDATORY_LABEL_ACE_TYPE         (0x11)
#define ACCESS_MAX_MS_V5_ACE_TYPE               (0x11)
#endif

// Access mask for the mandatory label ACE
#ifndef SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
#define SYSTEM_MANDATORY_LABEL_NO_WRITE_UP         0x1
#define SYSTEM_MANDATORY_LABEL_NO_READ_UP          0x2
#define SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP       0x4

#define SYSTEM_MANDATORY_LABEL_VALID_MASK (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP   | \
                                           SYSTEM_MANDATORY_LABEL_NO_READ_UP    | \
                                           SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP)
#endif  // SYSTEM_MANDATORY_LABEL_NO_WRITE_UP

#ifndef SECURITY_MANDATORY_LABEL_AUTHORITY
#define SECURITY_MANDATORY_LABEL_AUTHORITY          {0,0,0,0,0,16}
#define SECURITY_MANDATORY_UNTRUSTED_RID            (0x00000000L)
#define SECURITY_MANDATORY_LOW_RID                  (0x00001000L)
#define SECURITY_MANDATORY_MEDIUM_RID               (0x00002000L)
#define SECURITY_MANDATORY_HIGH_RID                 (0x00003000L)
#define SECURITY_MANDATORY_SYSTEM_RID               (0x00004000L)
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID    (0x00005000L)
#endif  // SECURITY_MANDATORY_LABEL_AUTHORITY

//-----------------------------------------------------------------------------
// Definitions for token mandatory label

#ifndef ACCESS_MAX_MS_V5_ACE_TYPE

typedef struct _TOKEN_MANDATORY_LABEL
{
    SID_AND_ATTRIBUTES Label;

} TOKEN_MANDATORY_LABEL, *PTOKEN_MANDATORY_LABEL;

typedef enum _TOKEN_ELEVATION_TYPE {
    TokenElevationTypeDefault = 1,
    TokenElevationTypeFull,
    TokenElevationTypeLimited,
} TOKEN_ELEVATION_TYPE, *PTOKEN_ELEVATION_TYPE;

typedef struct _TOKEN_ELEVATION {
    DWORD TokenIsElevated;
} TOKEN_ELEVATION, *PTOKEN_ELEVATION;

#endif  // ACCESS_MAX_MS_V5_ACE_TYPE

//-----------------------------------------------------------------------------
// Additional ACE types version 4 (not included in VS 2005 SDK)

#ifndef ACCESS_MAX_MS_V4_ACE_TYPE

typedef struct _ACCESS_ALLOWED_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
} ACCESS_ALLOWED_OBJECT_ACE, *PACCESS_ALLOWED_OBJECT_ACE;

typedef struct _ACCESS_DENIED_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
} ACCESS_DENIED_OBJECT_ACE, *PACCESS_DENIED_OBJECT_ACE;

typedef struct _SYSTEM_AUDIT_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
} SYSTEM_AUDIT_OBJECT_ACE, *PSYSTEM_AUDIT_OBJECT_ACE;

typedef struct _SYSTEM_ALARM_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
} SYSTEM_ALARM_OBJECT_ACE, *PSYSTEM_ALARM_OBJECT_ACE;
#endif

//-----------------------------------------------------------------------------
// Additional ACE types version 5 (not included in VS 2005 SDK)

#ifndef ACCESS_MAX_MS_V5_ACE_TYPE

typedef struct _ACCESS_ALLOWED_CALLBACK_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
    // Opaque resouce manager specific data
} ACCESS_ALLOWED_CALLBACK_ACE, *PACCESS_ALLOWED_CALLBACK_ACE;

typedef struct _ACCESS_DENIED_CALLBACK_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
    // Opaque resouce manager specific data
} ACCESS_DENIED_CALLBACK_ACE, *PACCESS_DENIED_CALLBACK_ACE;

typedef struct _ACCESS_ALLOWED_CALLBACK_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
    // Opaque resouce manager specific data
} ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, *PACCESS_ALLOWED_CALLBACK_OBJECT_ACE;

typedef struct _ACCESS_DENIED_CALLBACK_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
    // Opaque resouce manager specific data
} ACCESS_DENIED_CALLBACK_OBJECT_ACE, *PACCESS_DENIED_CALLBACK_OBJECT_ACE;

typedef struct _SYSTEM_AUDIT_CALLBACK_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
    // Opaque resouce manager specific data
} SYSTEM_AUDIT_CALLBACK_ACE, *PSYSTEM_AUDIT_CALLBACK_ACE;

typedef struct _SYSTEM_ALARM_CALLBACK_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
    // Opaque resouce manager specific data
} SYSTEM_ALARM_CALLBACK_ACE, *PSYSTEM_ALARM_CALLBACK_ACE;

typedef struct _SYSTEM_AUDIT_CALLBACK_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
    // Opaque resouce manager specific data
} SYSTEM_AUDIT_CALLBACK_OBJECT_ACE, *PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE;

typedef struct _SYSTEM_ALARM_CALLBACK_OBJECT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    DWORD SidStart;
    // Opaque resouce manager specific data
} SYSTEM_ALARM_CALLBACK_OBJECT_ACE, *PSYSTEM_ALARM_CALLBACK_OBJECT_ACE;

typedef struct _SYSTEM_MANDATORY_LABEL_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} SYSTEM_MANDATORY_LABEL_ACE, *PSYSTEM_MANDATORY_LABEL_ACE;

#endif  // ACCESS_MAX_MS_V5_ACE_TYPE

//-----------------------------------------------------------------------------
// Object ID definitions (not included in VS 2005 SDK)

typedef BOOL (WINAPI * ADDMANDATORYACE)(PACL pAcl,
                                        DWORD dwAceRevision,
                                        DWORD AceFlags,
                                        DWORD MandatoryPolicy,
                                        PSID pLabelSid);

//-----------------------------------------------------------------------------
// Object ID definitions (not included in VS 2005 SDK)

#ifndef FSCTL_GET_OBJECT_ID

#define FSCTL_SET_OBJECT_ID             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 38, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // FILE_OBJECTID_BUFFER
#define FSCTL_GET_OBJECT_ID             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 39, METHOD_BUFFERED, FILE_ANY_ACCESS) // FILE_OBJECTID_BUFFER
#define FSCTL_CREATE_OR_GET_OBJECT_ID   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 48, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SET_SPARSE                CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 49, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _FILE_OBJECTID_BUFFER {

    //
    //  This is the portion of the object id that is indexed.
    //

    BYTE  ObjectId[16];

    //
    //  This portion of the object id is not indexed, it's just
    //  some metadata for the user's benefit.
    //

    union {
        struct {
            BYTE  BirthVolumeId[16];
            BYTE  BirthObjectId[16];
            BYTE  DomainId[16];
        } ;
        BYTE  ExtendedInfo[48];
    };

} FILE_OBJECTID_BUFFER, *PFILE_OBJECTID_BUFFER;

#endif	// FSCTL_GET_OBJECT_ID

//-----------------------------------------------------------------------------
// OPLOCK definitions (not included in VS 2005 SDK)

#ifndef FSCTL_REQUEST_OPLOCK
#define FSCTL_REQUEST_OPLOCK                CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 144, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#ifndef FILE_OPLOCK_BROKEN_TO_LEVEL_2
#define FILE_OPLOCK_BROKEN_TO_LEVEL_2   0x00000007
#define FILE_OPLOCK_BROKEN_TO_NONE      0x00000008
#define FILE_OPBATCH_BREAK_UNDERWAY     0x00000009
#endif

#ifndef OPLOCK_LEVEL_CACHE_READ
#define OPLOCK_LEVEL_CACHE_READ         (0x00000001)
#define OPLOCK_LEVEL_CACHE_HANDLE       (0x00000002)
#define OPLOCK_LEVEL_CACHE_WRITE        (0x00000004)

#define REQUEST_OPLOCK_INPUT_FLAG_REQUEST               (0x00000001)
#define REQUEST_OPLOCK_INPUT_FLAG_ACK                   (0x00000002)
#define REQUEST_OPLOCK_INPUT_FLAG_COMPLETE_ACK_ON_CLOSE (0x00000004)

#define REQUEST_OPLOCK_CURRENT_VERSION          1

typedef struct _REQUEST_OPLOCK_INPUT_BUFFER {

    //
    //  This should be set to REQUEST_OPLOCK_CURRENT_VERSION.
    //

    WORD   StructureVersion;

    WORD   StructureLength;

    //
    //  One or more OPLOCK_LEVEL_CACHE_* values to indicate the desired level of the oplock.
    //

    DWORD RequestedOplockLevel;

    //
    //  REQUEST_OPLOCK_INPUT_FLAG_* flags.
    //

    DWORD Flags;

} REQUEST_OPLOCK_INPUT_BUFFER, *PREQUEST_OPLOCK_INPUT_BUFFER;

#define REQUEST_OPLOCK_OUTPUT_FLAG_ACK_REQUIRED     (0x00000001)
#define REQUEST_OPLOCK_OUTPUT_FLAG_MODES_PROVIDED   (0x00000002)

typedef struct _REQUEST_OPLOCK_OUTPUT_BUFFER {

    //
    //  This should be set to REQUEST_OPLOCK_CURRENT_VERSION.
    //

    WORD   StructureVersion;

    WORD   StructureLength;

    //
    //  One or more OPLOCK_LEVEL_CACHE_* values indicating the level of the oplock that
    //  was just broken.
    //

    DWORD OriginalOplockLevel;

    //
    //  One or more OPLOCK_LEVEL_CACHE_* values indicating the level to which an oplock
    //  is being broken, or an oplock level that may be available for granting, depending
    //  on the operation returning this buffer.
    //

    DWORD NewOplockLevel;

    //
    //  REQUEST_OPLOCK_OUTPUT_FLAG_* flags.
    //

    DWORD Flags;

    //
    //  When REQUEST_OPLOCK_OUTPUT_FLAG_MODES_PROVIDED is set, and when the
    //  OPLOCK_LEVEL_CACHE_HANDLE level is being lost in an oplock break, these fields
    //  contain the access mode and share mode of the request that is causing the break.
    //

    ACCESS_MASK AccessMode;

    WORD   ShareMode;

} REQUEST_OPLOCK_OUTPUT_BUFFER, *PREQUEST_OPLOCK_OUTPUT_BUFFER;
#endif	// OPLOCK_LEVEL_CACHE_READ

#ifndef PROGRESS_CONTINUE
#define PROGRESS_CONTINUE   0
#define PROGRESS_CANCEL     1
#define PROGRESS_STOP       2
#define PROGRESS_QUIET      3

typedef
DWORD
(WINAPI *LPPROGRESS_ROUTINE)(
    IN LARGE_INTEGER TotalFileSize,
    IN LARGE_INTEGER TotalBytesTransferred,
    IN LARGE_INTEGER StreamSize,
    IN LARGE_INTEGER StreamBytesTransferred,
    IN DWORD dwStreamNumber,
    IN DWORD dwCallbackReason,
    IN HANDLE hSourceFile,
    IN HANDLE hDestinationFile,
    IN LPVOID lpData OPTIONAL
    );
#endif	// PROGRESS_CONTINUE

//-----------------------------------------------------------------------------
// Defines for the reparse point

#ifndef IO_REPARSE_TAG_SYMLINK
#define IO_REPARSE_TAG_SYMLINK          (0xA000000CL)       
#endif

#ifndef IO_REPARSE_TAG_WIM
#define IO_REPARSE_TAG_WIM				(0x80000008L)
#endif

#ifndef FSCTL_SET_REPARSE_POINT
#define FSCTL_SET_REPARSE_POINT         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // REPARSE_DATA_BUFFER,
#define FSCTL_GET_REPARSE_POINT         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED, FILE_ANY_ACCESS) // REPARSE_DATA_BUFFER
#define FSCTL_DELETE_REPARSE_POINT      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // REPARSE_DATA_BUFFER,
#endif  // FSCTL_SET_REPARSE_POINT

typedef struct _REPARSE_DATA_BUFFER
{
    ULONG  ReparseTag;                          // Reparse tag type
    USHORT ReparseDataLength;                   // Length of the reparse data
    USHORT Reserved;                            // Used internally by NTFS to store remaining length

    union
    {
        // Structure for IO_REPARSE_TAG_SYMLINK
        // Handled by nt!IoCompleteRequest
        struct
        {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        
        // Structure for IO_REPARSE_TAG_MOUNT_POINT
        // Handled by nt!IoCompleteRequest
        struct
        {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;

        // Structure for IO_REPARSE_TAG_WIM
        // Handled by wimmount!FPOpenReparseTarget->wimserv.dll (wimsrv!ImageExtract)
        struct
        {
            GUID ImageGuid;                     // GUID of the mounted VIM image
            BYTE ImagePathHash[0x14];           // Hash of the path to the file within the image
        } WimImageReparseBuffer;

        // Dummy structure
        struct
        {
            UCHAR  DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

#define REPARSE_DATA_BUFFER_HEADER_SIZE   FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer)

#endif // __WINSDK_H__
