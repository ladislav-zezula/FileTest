/*****************************************************************************/
/* ReparseDataHsm.h                       Copyright (c) Ladislav Zezula 2018 */
/*---------------------------------------------------------------------------*/
/* Interface of the HSM reparse data structures                              */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 06.09.18  1.00  Lad  The first version of ReparseDataHsm.h                */
/*****************************************************************************/

#ifndef __REPARSE_DATA_HSM_H__
#define __REPARSE_DATA_HSM_H__

//-----------------------------------------------------------------------------
// Defines

#define HSM_BITMAP_MAGIC                0x70527442  // 'BtRp'
#define HSM_BITMAP_ELEMENTS             0x05        // Fixed number of elements for HSM bitmap
#define HSM_FILE_MAGIC                  0x70526546  // 'FeRp'
#define HSM_FILE_ELEMENTS               0x09        // Fixed number of elements for HSM reparse data

#define HSM_DATA_HAVE_CRC               0x02        // If set, then the data has CRC

#define HSM_XXX_DATA_SIZE               0x10
#define HSM_MIN_DATA_SIZE(elements)    (HSM_XXX_DATA_SIZE + (elements * sizeof(HSM_ELEMENT_INFO)))

#define HSM_ELEMENT_TYPE_NONE           0x00
#define HSM_ELEMENT_TYPE_UINT64         0x06
#define HSM_ELEMENT_TYPE_BYTE           0x07
#define HSM_ELEMENT_TYPE_UINT32         0x0A
#define HSM_ELEMENT_TYPE_BITMAP         0x11
#define HSM_ELEMENT_TYPE_MAX            0x12

//-----------------------------------------------------------------------------
// Data structures for HSM reparse data

typedef struct _HSM_ELEMENT_INFO
{
    USHORT Type;                        // Type of the element (?). One of HSM_ELEMENT_TYPE_XXX
    USHORT Length;                      // Length of the element data in bytes
    ULONG  Offset;                      // Offset of the element data, relative to begin of HSM_DATA. Aligned to 4 bytes
} HSM_ELEMENT_INFO, *PHSM_ELEMENT_INFO;

typedef struct _HSM_DATA
{
    ULONG  Magic;                       // 0x70527442 ('pRtB') for bitmap data, 0x70526546 ('FeRp') for file data
    ULONG  Crc32;                       // CRC32 of the following data (calculated by RtlComputeCrc32)
    ULONG  Length;                      // Length of the entire HSM_DATA in bytes
    USHORT Flags;                       // HSM_DATA_XXXX
    USHORT NumberOfElements;            // Number of elements
    HSM_ELEMENT_INFO ElementInfos[1];   // Array of element infos. There is fixed maximal items for bitmap and reparse data
} HSM_DATA, *PHSM_DATA;

typedef struct _HSM_REPARSE_DATA
{
    USHORT Flags;                       // Lower 8 bits is revision (must be 1 as of Windows 10 16299)
                                        // Flags: 0x8000 = Data needs to be decompressed by RtlCompressBuffer
    USHORT Length;                      // Length of the HSM_REPARSE_DATA structure (including "Flags" and "Length")
    
    HSM_DATA FileData;                  // HSM data
} HSM_REPARSE_DATA, *PHSM_REPARSE_DATA;

//-----------------------------------------------------------------------------
// Helper functions

LPBYTE   HsmGetElementData(PHSM_DATA HsmData, ULONG ElementIndex);
NTSTATUS HsmUncompressData(PREPARSE_DATA_BUFFER RawReparseData, ULONG RawDataLength, PREPARSE_DATA_BUFFER * OutReparseData);
NTSTATUS HsmValidateReparseData(PREPARSE_DATA_BUFFER ReparseData);

#endif  // __REPARSE_DATA_HSM_H__
