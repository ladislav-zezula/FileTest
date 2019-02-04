/*****************************************************************************/
/* ReparseDataHsm.cpp                     Copyright (c) Ladislav Zezula 2018 */
/*---------------------------------------------------------------------------*/
/* Description: Implementation of HSM reparse data functions                 */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 18.03.14  1.00  Lad  The first version of ReparseDataHsm.cpp              */
/*****************************************************************************/

#include "FileTest.h"
#include "ReparseDataHsm.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local functions

static bool HsmpCheckElement(PHSM_DATA HsmData, ULONG ElementIndex)
{
    PHSM_ELEMENT_INFO pElementInfo = &HsmData->ElementInfos[ElementIndex];
    ULONG ElementCount = HsmData->NumberOfElements;

    if (pElementInfo->Type >= HSM_ELEMENT_TYPE_MAX)
        return false;
    if (pElementInfo->Offset != 0 && pElementInfo->Offset < HSM_MIN_DATA_SIZE(ElementCount))
        return false;
    if (pElementInfo->Offset > HsmData->Length)
        return false;
    if (pElementInfo->Length > HsmData->Length)
        return false;
    if ((pElementInfo->Offset + pElementInfo->Length) > HsmData->Length)
        return false;

    return true;
}

static NTSTATUS HsmValidateCommonData(PHSM_DATA HsmData, ULONG Magic, ULONG ElementCount, ULONG RemainingLength)
{
    ULONG FirstElementOffset;
    ULONG NumberOfElements;
    ULONG CheckPhase = 0;

    // The remaining data must be at least HSM_FILE_DATA_MINSIZE bytes
    if (RemainingLength < HSM_MIN_DATA_SIZE(1))
        return STATUS_CLOUD_FILE_METADATA_CORRUPT;
    CheckPhase = 1;

    if (HsmData->Magic != Magic)
        return STATUS_CLOUD_FILE_METADATA_CORRUPT;
    CheckPhase = 2;

    // Check CRC, if present
    if ((HsmData->Flags & HSM_DATA_HAVE_CRC) && RtlComputeCrc32(0, &HsmData->Length, RemainingLength - 8) != HsmData->Crc32)
        return STATUS_CLOUD_FILE_METADATA_CORRUPT;
    CheckPhase = 3;

    // Check the remaining size
    if (HsmData->Length != RemainingLength)
        return STATUS_CLOUD_FILE_METADATA_CORRUPT;
    CheckPhase = 4;

    // Check the zero field
    if ((NumberOfElements = HsmData->NumberOfElements) == 0)
        return STATUS_CLOUD_FILE_METADATA_CORRUPT;
    CheckPhase = 5;

    // Check the offset of the first element
    if ((FirstElementOffset = HSM_MIN_DATA_SIZE(NumberOfElements)) > RemainingLength)
        return STATUS_CLOUD_FILE_METADATA_CORRUPT;
    CheckPhase = 0x10000;

    // Check the elements
    for (ULONG i = 0; i < min(NumberOfElements, ElementCount); i++)
    {
        if (!HsmpCheckElement(HsmData, i))
            return STATUS_CLOUD_FILE_METADATA_CORRUPT;
        CheckPhase++;
    }

    CheckPhase = 0x20000;

    // Check element[0] (version?)
    if (NumberOfElements == 0 || RemainingLength < HSM_MIN_DATA_SIZE(1))
        return STATUS_CLOUD_FILE_METADATA_CORRUPT;
    if (!HsmpCheckElement(HsmData, 0))
        return STATUS_CLOUD_FILE_METADATA_CORRUPT;
    if (HsmData->ElementInfos[0].Type != HSM_ELEMENT_TYPE_BYTE || HsmData->ElementInfos[0].Length != sizeof(BYTE))
        return STATUS_CLOUD_FILE_METADATA_CORRUPT;
    if (*HsmGetElementData(HsmData, 0) != 1)
        return STATUS_CLOUD_FILE_METADATA_CORRUPT;

    CheckPhase = 0x20001;
    return STATUS_SUCCESS;
}

//-----------------------------------------------------------------------------
// Uncompresses the HSM reparse data buffer. Note that the buffer may be already
// uncompressed (if the flag 0x8000 is not set).

LPBYTE HsmGetElementData(PHSM_DATA HsmData, ULONG ElementIndex)
{
    return ((LPBYTE)HsmData) + HsmData->ElementInfos[ElementIndex].Offset;
}

NTSTATUS HsmUncompressData(PREPARSE_DATA_BUFFER RawReparseData, ULONG RawReparseDataLength, PREPARSE_DATA_BUFFER * OutReparseData)
{
    PREPARSE_DATA_BUFFER HsmReparseData = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG HsmReparseDataLength;
    ULONG UncompressedSize = 0;

    // Is the cloud buffer compressed?
    if (RawReparseData->HsmReparseBufferRaw.Flags & 0x8000)
    {
        HsmReparseDataLength = sizeof(ULONG) + sizeof(USHORT) + sizeof(USHORT) + RawReparseData->HsmReparseBufferRaw.Length;
        HsmReparseData = (PREPARSE_DATA_BUFFER)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, HsmReparseDataLength);
        if (HsmReparseData != NULL)
        {
            // Copy the data that don't belong in the compressed area
            memcpy(HsmReparseData, RawReparseData, FIELD_OFFSET(REPARSE_DATA_BUFFER, HsmReparseBufferRaw.RawData));
            Status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1,
                                         HsmReparseData->HsmReparseBufferRaw.RawData,
                                         HsmReparseDataLength - FIELD_OFFSET(REPARSE_DATA_BUFFER, HsmReparseBufferRaw.RawData),
                                         RawReparseData->HsmReparseBufferRaw.RawData,
                                         RawReparseDataLength - FIELD_OFFSET(REPARSE_DATA_BUFFER, HsmReparseBufferRaw.RawData),
                                        &UncompressedSize);
            if (NT_SUCCESS(Status))
            {
                HsmReparseData->ReparseDataLength = RawReparseData->HsmReparseBufferRaw.Length;
                OutReparseData[0] = HsmReparseData;
                return STATUS_SUCCESS;
            }

            // Free the allocated buffer
            HeapFree(g_hHeap, 0, HsmReparseData);
            HsmReparseData = NULL;
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        OutReparseData[0] = RawReparseData;
        return STATUS_SUCCESS;
    }
}

//-----------------------------------------------------------------------------
// Validates the HSM reparse point. Basically the same implementation like
// cldflt.sys!HsmpRpValidateBuffer:
// NTSTATUS HsmpRpValidateBuffer(PHSM_REPARSE_DATA pHsmReparseData, ULONG ReparseDataSize)

NTSTATUS HsmpBitmapIsReparseBufferSupported(PHSM_DATA HsmData, ULONG RemainingLength)
{
    NTSTATUS Status;
    ULONG NumberOfElements;
    BYTE Element1;
    BYTE Element2;

    // Perform common data validation
    Status = HsmValidateCommonData(HsmData, HSM_BITMAP_MAGIC, HSM_BITMAP_ELEMENTS, RemainingLength);
    if (!NT_SUCCESS(Status))
        return Status;
    NumberOfElements = HsmData->NumberOfElements;

    // Check element[2]
    if (NumberOfElements < 2 || RemainingLength < HSM_MIN_DATA_SIZE(2))
        return STATUS_NOT_FOUND;
    if (!HsmpCheckElement(HsmData, 2))
        return STATUS_NOT_FOUND;
    if (HsmData->ElementInfos[2].Type != HSM_ELEMENT_TYPE_BYTE || HsmData->ElementInfos[2].Length != sizeof(BYTE))
        return STATUS_NOT_FOUND;
    Element2 = *HsmGetElementData(HsmData, 2);

    if (Element2 != 0)
    {
        if (NumberOfElements < 4 || HsmData->ElementInfos[4].Offset == 0)
            return STATUS_CLOUD_FILE_METADATA_CORRUPT;
        if (HsmData->ElementInfos[4].Length > 0x1000)
            return STATUS_CLOUD_FILE_METADATA_CORRUPT;
    }

    if (Element2 > 1)
        STATUS_CLOUD_FILE_METADATA_CORRUPT;
    if (NumberOfElements < 1 || RemainingLength < HSM_MIN_DATA_SIZE(1))
        return STATUS_CLOUD_FILE_METADATA_CORRUPT;
    if (!HsmpCheckElement(HsmData, 1))
        return STATUS_CLOUD_FILE_METADATA_CORRUPT;
    if (HsmData->ElementInfos[1].Type != HSM_ELEMENT_TYPE_BYTE || HsmData->ElementInfos[1].Length != sizeof(BYTE))
        return STATUS_NOT_FOUND;
    Element1 = *HsmGetElementData(HsmData, 1);

    if (Element1 <= 0 || Element1 > 0x14)
        STATUS_CLOUD_FILE_METADATA_CORRUPT;

    return STATUS_SUCCESS;
}

NTSTATUS HsmpCheckBitmapElement(PHSM_DATA HsmData, ULONG ElementIndex)
{
    PHSM_DATA pBitmap = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG RemainingLength = HsmData->Length;
    ULONG BitmapLength = 0;

    __try
    {
        if (HsmData->NumberOfElements < ElementIndex || RemainingLength < HSM_MIN_DATA_SIZE(ElementIndex))
        {
            Status = STATUS_NOT_FOUND;
            __leave;
        }

        if (!HsmpCheckElement(HsmData, ElementIndex))
        {
            Status = STATUS_NOT_FOUND;
            __leave;
        }

        if (HsmData->ElementInfos[ElementIndex].Type != HSM_ELEMENT_TYPE_BITMAP)
        {
            Status = STATUS_NOT_FOUND;
            __leave;
        }

        if (HsmData->ElementInfos[ElementIndex].Offset && HsmData->ElementInfos[ElementIndex].Length)
        {
            pBitmap = (PHSM_DATA)HsmGetElementData(HsmData, ElementIndex);
            BitmapLength = HsmData->ElementInfos[ElementIndex].Length;
        }

        Status = HsmpBitmapIsReparseBufferSupported(pBitmap, BitmapLength);
    }
    __finally
    {
        Status = (Status == STATUS_NOT_FOUND) ? STATUS_SUCCESS : Status;
    }

    return Status;
}

NTSTATUS HsmValidateReparseData(PREPARSE_DATA_BUFFER ReparseData)
{
    PHSM_REPARSE_DATA HsmReparseData = (PHSM_REPARSE_DATA)(&ReparseData->HsmReparseBufferRaw);
    PHSM_DATA HsmData;
    NTSTATUS Status;
    ULONG NumberOfElements;
    ULONG RemainingLength;
    ULONG ElementFlags;

    // Check the length
    if (HsmReparseData->Length != ReparseData->ReparseDataLength)
        return STATUS_INVALID_BLOCK_LENGTH;

    // Check the revision
    if ((HsmReparseData->Flags & 0x0F) > 1)
        return STATUS_UNKNOWN_REVISION;
    if ((HsmReparseData->Flags & 0x0F) < 1)
        return STATUS_REVISION_MISMATCH;
    
    // Get the HSM data and the remaining length
    HsmData = (PHSM_DATA)&HsmReparseData->FileData;
    RemainingLength = HsmReparseData->Length - FIELD_OFFSET(HSM_REPARSE_DATA, FileData);

    // Check the common part of the data
    Status = HsmValidateCommonData(HsmData, HSM_FILE_MAGIC, HSM_FILE_ELEMENTS, RemainingLength);
    if (!NT_SUCCESS(Status))
        return Status;
    NumberOfElements = HsmData->NumberOfElements;

    // Check element[1] (flags?)
    if (NumberOfElements < 1 || RemainingLength < HSM_MIN_DATA_SIZE(2))
        return STATUS_NOT_FOUND;
    if (!HsmpCheckElement(HsmData, 1))
        return STATUS_NOT_FOUND;
    if (HsmData->ElementInfos[1].Type != HSM_ELEMENT_TYPE_UINT32 || HsmData->ElementInfos[1].Length != sizeof(DWORD))
        return STATUS_NOT_FOUND;
    ElementFlags = *(PULONG)HsmGetElementData(HsmData, 1);
    if (ElementFlags & 0x10)
        return STATUS_SUCCESS;

    // Check element[2] (stream size)
    if (NumberOfElements < 2 || RemainingLength < HSM_MIN_DATA_SIZE(3))
        return STATUS_NOT_FOUND;
    if (!HsmpCheckElement(HsmData, 2))
        return STATUS_NOT_FOUND;
    if (HsmData->ElementInfos[2].Type != HSM_ELEMENT_TYPE_UINT64 || HsmData->ElementInfos[2].Length != sizeof(ULONGLONG))
        return STATUS_NOT_FOUND;

    // Check element[4] (HSM_BITMAP)
    Status = HsmpCheckBitmapElement(HsmData, 4);
    if (!NT_SUCCESS(Status))
        return Status;

    // Check element[5] (HSM_BITMAP)
    Status = HsmpCheckBitmapElement(HsmData, 5);
    if (!NT_SUCCESS(Status))
        return Status;

    // Check element[6] (HSM_BITMAP)
    Status = HsmpCheckBitmapElement(HsmData, 6);
    return Status;
}
