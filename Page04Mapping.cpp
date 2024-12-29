/*****************************************************************************/
/* Page04Mapping.cpp                      Copyright (c) Ladislav Zezula 2014 */
/*---------------------------------------------------------------------------*/
/* Description:                                                              */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 17.04.14  1.00  Lad  The first version of Page04Mapping.cpp               */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Flags

static TFlagInfo SectionAccessValues[] =
{
    FLAGINFO_BITV(SECTION_QUERY),
    FLAGINFO_BITV(SECTION_MAP_WRITE),
    FLAGINFO_BITV(SECTION_MAP_READ),
    FLAGINFO_BITV(SECTION_MAP_EXECUTE),
    FLAGINFO_BITV(SECTION_EXTEND_SIZE),
    FLAGINFO_BITV(SECTION_MAP_EXECUTE_EXPLICIT),

    FLAGINFO_BITV(DELETE),
    FLAGINFO_BITV(READ_CONTROL),
    FLAGINFO_BITV(WRITE_DAC),
    FLAGINFO_BITV(WRITE_OWNER),
    FLAGINFO_BITV(SYNCHRONIZE),
    FLAGINFO_BITV(ACCESS_SYSTEM_SECURITY),
    FLAGINFO_BITV(GENERIC_READ),
    FLAGINFO_BITV(GENERIC_WRITE),
    FLAGINFO_BITV(GENERIC_EXECUTE),
    FLAGINFO_BITV(GENERIC_ALL),
    FLAGINFO_END()
};

TFlagInfo AllocationAttributesValues[] =
{
    FLAGINFO_BITV(SEC_HUGE_PAGES),
    FLAGINFO_BITV(SEC_PARTITION_OWNER_HANDLE),
    FLAGINFO_BITV(SEC_64K_PAGES),
    FLAGINFO_BITV(SEC_FILE),
    FLAGINFO_BITV(SEC_IMAGE),
    FLAGINFO_BITV(SEC_PROTECTED_IMAGE),
    FLAGINFO_BITV(SEC_RESERVE),
    FLAGINFO_BITV(SEC_COMMIT),
    FLAGINFO_BITV(SEC_NOCACHE),
    FLAGINFO_BITV(SEC_WRITECOMBINE),
    FLAGINFO_BITV(SEC_LARGE_PAGES),
    FLAGINFO_END()
};


static TFlagInfo AllocationTypeValues[] =
{
    FLAGINFO_BITV(MEM_COMMIT),
    FLAGINFO_BITV(MEM_RESERVE),
    FLAGINFO_BITV(MEM_DECOMMIT),
    FLAGINFO_BITV(MEM_RELEASE),
    FLAGINFO_BITV(MEM_FREE),
    FLAGINFO_BITV(MEM_PRIVATE),
    FLAGINFO_BITV(MEM_MAPPED),
    FLAGINFO_BITV(MEM_RESET),
    FLAGINFO_BITV(MEM_TOP_DOWN),
    FLAGINFO_BITV(MEM_WRITE_WATCH),
    FLAGINFO_BITV(MEM_PHYSICAL),
    FLAGINFO_BITV(MEM_ROTATE),
    FLAGINFO_BITV(MEM_RESET_UNDO),
    FLAGINFO_BITV(MEM_LARGE_PAGES),
    FLAGINFO_BITV(MEM_4MB_PAGES),
    FLAGINFO_END()
};

static TFlagInfo PageProtectionValues[] =
{
    FLAGINFO_BITV(PAGE_NOACCESS),   
    FLAGINFO_BITV(PAGE_READONLY),   
    FLAGINFO_BITV(PAGE_READWRITE),   
    FLAGINFO_BITV(PAGE_WRITECOPY),   
    FLAGINFO_BITV(PAGE_EXECUTE),   
    FLAGINFO_BITV(PAGE_EXECUTE_READ),   
    FLAGINFO_BITV(PAGE_EXECUTE_READWRITE),   
    FLAGINFO_BITV(PAGE_EXECUTE_WRITECOPY),   
    FLAGINFO_BITV(PAGE_GUARD),
    FLAGINFO_BITV(PAGE_NOCACHE),
    FLAGINFO_BITV(PAGE_WRITECOMBINE),
    FLAGINFO_END()
};

static TAnchors * pAnchors = NULL;

//-----------------------------------------------------------------------------
// Local functions

static void InitPageProtections(HWND hDlg, UINT nIDCombo, TFlagInfo * pFlags)
{
    TCHAR szItemText[0x40];
    HWND hWndCombo = GetDlgItem(hDlg, nIDCombo);

    if(hWndCombo != NULL)
    {
        for(DWORD i = 0; !pFlags->IsTerminator(); i++, pFlags++)
        {
            // Format and insert the string to the combo box
            StringCchPrintf(szItemText, _countof(szItemText), _T("[%04X] %hs"), pFlags->dwValue, pFlags->szFlagText);
            ComboBox_AddString(hWndCombo, szItemText);
        }
    }
}

static void Hex2PageProtection(HWND hDlg, UINT nIDCombo, DWORD dwProtection)
{
    TFlagInfo * pFlags = PageProtectionValues;
    HWND hWndCombo = GetDlgItem(hDlg, nIDCombo);
    int nItemIndex = 0;

    if(hWndCombo != NULL)
    {
        // Find the proper page protection
        for(int i = 0; pFlags->szFlagText != NULL; i++, pFlags++)
        {
            if(pFlags->IsValuePresent(dwProtection))
            {
                nItemIndex = i;
                break;
            }
        }

        // Select the given item
        ComboBox_SetCurSel(hWndCombo, nItemIndex);
    }
}

static DWORD PageProtection2Hex(HWND hDlg, UINT nIDCombo)
{
    HWND hWndCombo = GetDlgItem(hDlg, nIDCombo);
    int nMaxItemIndex = _countof(PageProtectionValues) - 1;
    int nItemIndex;

    if(hWndCombo != NULL)
    {
        // Get the selected item
        nItemIndex = ComboBox_GetCurSel(hWndCombo);
        if(nItemIndex == CB_ERR || nItemIndex > nMaxItemIndex)
            nItemIndex = 0;

        // Get the page protection
        return PageProtectionValues[nItemIndex].dwValue;
    }

    return 0;
}

static void UpdateDialog(HWND hDlg, TFileTestData * pData)
{
    BOOL bEnable;

    // The mapping buttons are only allowed if we have valid map handle
    bEnable = IsHandleValid(pData->hSection) ? TRUE : FALSE;
    EnableDlgItems(hDlg, bEnable, IDC_NTCLOSE, IDC_MAP_VIEW, 0);

    // The map accessing is only allowed if we have valid mapping
    EnableDlgItems(hDlg, pData->bSectionViewMapped, IDC_DATA_EDITOR, IDC_UNMAP_VIEW, 0);
}

static int SaveDialog1(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    DWORD dwErrCode;

    GetDlgItemText(hDlg, IDC_SECTION_NAME, pData->szSectionName, MAX_NT_PATH);

    if((dwErrCode = DlgText2Hex64(hDlg, IDC_SECTION_SIZE, &pData->MaximumSize.QuadPart)) != ERROR_SUCCESS)
        return dwErrCode;
    if((dwErrCode = DlgText2Hex32(hDlg, IDC_DESIRED_ACCESS, &pData->dwSectDesiredAccess)) != ERROR_SUCCESS)
        return dwErrCode;
    if((dwErrCode = DlgText2Hex32(hDlg, IDC_ALLOCATION_ATTRIBUTES, &pData->dwSectAllocAttributes)) != ERROR_SUCCESS)
        return dwErrCode;

    pData->dwSectPageProtection = PageProtection2Hex(hDlg, IDC_PAGE_PROTECTION);
    return ERROR_SUCCESS;
}

static int SaveDialog2(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    int dwErrCode;

    if((dwErrCode = DlgText2HexPtr(hDlg, IDC_BASE_ADDRESS, (PDWORD_PTR)(&pData->pvSectionMappedView))) != ERROR_SUCCESS)
        return dwErrCode;
    if((dwErrCode = DlgText2HexPtr(hDlg, IDC_COMMIT_SIZE, (PDWORD_PTR)(&pData->cbSectCommitSize))) != ERROR_SUCCESS)
        return dwErrCode;
    if((dwErrCode = DlgText2Hex64(hDlg, IDC_SECTION_OFFSET, &pData->SectionOffset.QuadPart)) != ERROR_SUCCESS)
        return dwErrCode;
    if((dwErrCode = DlgText2HexPtr(hDlg, IDC_VIEW_SIZE, (PDWORD_PTR)(&pData->cbSectViewSize))) != ERROR_SUCCESS)
        return dwErrCode;
    if((dwErrCode = DlgText2Hex32(hDlg, IDC_ALLOCATION_TYPE, &pData->dwSectAllocType)) != ERROR_SUCCESS)
        return dwErrCode;
    pData->dwSectWin32Protect = PageProtection2Hex(hDlg, IDC_WIN32_PROTECTION);
    return ERROR_SUCCESS;
}

//-----------------------------------------------------------------------------
// Message handlers

static int OnNtCloseClick(HWND hDlg);
static int OnUnmapViewClick(HWND hDlg);

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    TFileTestData * pData;
    PROPSHEETPAGE * pPage = (PROPSHEETPAGE *)lParam;

    SetDialogData(hDlg, pPage->lParam);
    pData = (TFileTestData *)pPage->lParam;

    // Configure dialog resizing
    if(pData->bEnableResizing)
    {
        pAnchors = new TAnchors(hDlg);
        pAnchors->AddAnchor(hDlg, IDC_SECTION_FRAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SECTION_NAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SECTION_SIZE, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SECTION_SIZE_UPDOWN, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_DESIRED_ACCESS, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_DESIRED_ACCESS_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_PAGE_PROTECTION, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_ALLOCATION_ATTRIBUTES, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_ALLOCATION_ATTRIBUTES_BROWSE, akTop | akRight);

        pAnchors->AddAnchor(hDlg, IDC_NTCREATE_SECTION, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_NTOPEN_SECTION, akLeftCenter | akTop);
        pAnchors->AddAnchor(hDlg, IDC_NTCLOSE, akRight | akTop);

        pAnchors->AddAnchor(hDlg, IDC_SECTION_VIEW_FRAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_BASE_ADDRESS, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_BASE_ADDRESS_UPDOWN, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_COMMIT_SIZE, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_COMMIT_SIZE_UPDOWN, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SECTION_OFFSET, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SECTION_OFFSET_UPDOWN, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_VIEW_SIZE, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_VIEW_SIZE_UPDOWN, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_ALLOCATION_TYPE, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_ALLOCATION_TYPE_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_WIN32_PROTECTION, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_MAPPED_NAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_MAPPED_NAME_QUERY, akTop | akRight);

        pAnchors->AddAnchor(hDlg, IDC_MAP_VIEW, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_DATA_EDITOR, akLeftCenter | akTop);
        pAnchors->AddAnchor(hDlg, IDC_UNMAP_VIEW, akRight | akTop);

        pAnchors->AddAnchor(hDlg, IDC_RESULT_FRAME, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_HANDLE_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_HANDLE, akLeft | akRight | akBottom);
    }

    // If we have a tooltip window, init tooltips 
    g_Tooltip.AddToolTip(hDlg, IDC_DESIRED_ACCESS, SectionAccessValues);
    g_Tooltip.AddToolTip(hDlg, IDC_ALLOCATION_ATTRIBUTES, AllocationAttributesValues);
    g_Tooltip.AddToolTip(hDlg, IDC_ALLOCATION_TYPE, AllocationTypeValues);
    g_Tooltip.AddToolTip(hDlg, IDC_MAPPED_NAME, IDS_MAPPED_NAME_HINT);

    // Initialize the combo box
    InitPageProtections(hDlg, IDC_PAGE_PROTECTION, PageProtectionValues);
    InitPageProtections(hDlg, IDC_WIN32_PROTECTION, PageProtectionValues);

    // Initialize the input parameters
    Hex2DlgText64(hDlg, IDC_SECTION_SIZE, pData->MaximumSize.QuadPart);
    Hex2DlgText32(hDlg, IDC_DESIRED_ACCESS, pData->dwSectDesiredAccess);
    Hex2PageProtection(hDlg, IDC_PAGE_PROTECTION, pData->dwSectPageProtection);
    Hex2DlgText32(hDlg, IDC_ALLOCATION_ATTRIBUTES, pData->dwSectAllocAttributes);

    Hex2DlgTextPtr(hDlg, IDC_BASE_ADDRESS,   (DWORD_PTR)pData->pvSectionMappedView);
    Hex2DlgTextPtr(hDlg, IDC_COMMIT_SIZE,    pData->cbSectCommitSize);
    Hex2DlgText64 (hDlg, IDC_SECTION_OFFSET, pData->SectionOffset.QuadPart);
    Hex2DlgTextPtr(hDlg, IDC_VIEW_SIZE,      pData->cbSectViewSize);
    Hex2DlgText32(hDlg, IDC_ALLOCATION_TYPE, pData->dwSectAllocType);
    Hex2PageProtection(hDlg, IDC_WIN32_PROTECTION, pData->dwSectWin32Protect);

    UpdateDialog(hDlg, pData);
    return TRUE;
}

static int OnSetActive(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    HANDLE FileHandle = IsHandleValid(pData->hFile) ? pData->hFile : NULL;
    TCHAR szHandle[48] = _T("NULL");
    HWND hWndChild;

    // Set the file handle into the section frame title
    if((hWndChild = GetDlgItem(hDlg, IDC_SECTION_FRAME)) != NULL)
    {
        if(FileHandle != NULL)
            StringCchPrintf(szHandle, _countof(szHandle), _T("0x%x"), FileHandle);
        SetWindowTextRc(hWndChild, IDC_SECTION_FRAME, szHandle);
    }

    UpdateDialog(hDlg, pData);
    return TRUE;
}

static int OnKillActive(HWND hDlg)
{
    UNREFERENCED_PARAMETER(hDlg);
    return TRUE;
}

static int OnDesiredAccessBrowse(HWND hDlg)
{
    FlagsDialog_OnControl(hDlg, IDS_DESIRED_ACCESS, SectionAccessValues, IDC_DESIRED_ACCESS);
    return TRUE;
}

static int OnAllocAttributesBrowse(HWND hDlg)
{
    FlagsDialog_OnControl(hDlg, IDS_ALLOCATION_ATTRIBUTES, AllocationAttributesValues, IDC_ALLOCATION_ATTRIBUTES);
    return TRUE;
}

static int OnAllocTypeBrowse(HWND hDlg)
{
    FlagsDialog_OnControl(hDlg, IDS_ALLOCATION_TYPE, AllocationTypeValues, IDC_ALLOCATION_TYPE);
    return TRUE;
}

static int OnNtCreateSectionClick(HWND hDlg, UINT nIDCtrl)
{
    TFileTestData * pData = GetDialogData(hDlg);
    POBJECT_ATTRIBUTES pObjectAttributes = NULL;
    OBJECT_ATTRIBUTES ObjAttr;
    UNICODE_STRING SectionName;
    NTSTATUS Status;
    HANDLE FileHandle = NULL;

    // Close the section, if already open
    if(IsHandleValid(pData->hSection))
        OnNtCloseClick(hDlg);

    // Get the values from dialog controls to the dialog data
    if(SaveDialog1(hDlg) != ERROR_SUCCESS)
        return FALSE;

    // Format the object attributes
    if(pData->szSectionName[0] != 0)
    {
        InitializeObjectAttributes(&ObjAttr, &SectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        RtlInitUnicodeString(&SectionName, pData->szSectionName);
        pObjectAttributes = &ObjAttr;
    }

    // Get the file handle for it
    if(IsHandleValid(pData->hFile))
        FileHandle = pData->hFile;

    // Either create a section or open one
    if(nIDCtrl == IDC_NTCREATE_SECTION)
    {
        Status = NtCreateSection(&pData->hSection,
                                  pData->dwSectDesiredAccess,
                                  pObjectAttributes,
                                 &pData->MaximumSize,
                                  pData->dwSectPageProtection,
                                  pData->dwSectAllocAttributes,
                                  FileHandle);
    }
    else
    {
        Status = NtOpenSection(&pData->hSection,
                                pData->dwSectDesiredAccess,
                                pObjectAttributes);
    }

    // Set the result info
    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_HANDLE, Status, pData->hSection);
    UpdateDialog(hDlg, pData);
    return TRUE;
}

static int OnNtCloseClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    NTSTATUS Status = STATUS_SUCCESS;

    // Close the handle
    if(IsHandleValid(pData->hSection))
        Status = NtClose(pData->hSection);
    pData->hSection = NULL;

    // Set the result info
    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_HANDLE, Status, pData->hSection);
    UpdateDialog(hDlg, pData);
    return TRUE;
}

static int OnQueryMappedFileName(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    NTSTATUS Status;
    PUNICODE_STRING Buffer;
    SIZE_T BufferSize = sizeof(UNICODE_STRING) + (MAX_PATH * sizeof(WCHAR));

    if(SaveDialog2(hDlg) == ERROR_SUCCESS)
    {
        __RetryBiggerBuffer:

        // Allocate memory for the string plus zero termination
        if((Buffer = (PUNICODE_STRING)LocalAlloc(LPTR, BufferSize)) != NULL)
        {
            // Query the mapped file name
            Status = NtQueryVirtualMemory(NtCurrentProcess(),
                                          pData->pvSectionMappedView,
                                          MemorySectionName,
                                          Buffer,
                                          BufferSize,
                                         &BufferSize);

            // If failed because of not enough memory
            if(Status == STATUS_BUFFER_OVERFLOW)
            {
                LocalFree(Buffer);
                goto __RetryBiggerBuffer;
            }

            // Report the mapped file name
            SetDlgItemText(hDlg, IDC_MAPPED_NAME, NT_SUCCESS(Status) ? Buffer->Buffer : L"");
            SetResultInfo(hDlg, RSI_NTSTATUS, Status);
            UpdateDialog(hDlg, pData);

            // Free the allocated buffer
            LocalFree(Buffer);
        }
        else
        {
            Status = STATUS_NO_MEMORY;
        }
    }
    return TRUE;
}

static int OnMapViewClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    LARGE_INTEGER SectionOffset;
    NTSTATUS Status;
    SIZE_T ViewSize;
    PVOID BaseAddress;

    // If we have mapped view, unmap it now
    if(pData->bSectionViewMapped)
        OnUnmapViewClick(hDlg);

    // Get the values from dialog controls to the dialog data
    if(SaveDialog2(hDlg) != ERROR_SUCCESS)
        return FALSE;

    // Copy some values to stack
    SectionOffset.QuadPart = pData->SectionOffset.QuadPart;
    BaseAddress = pData->pvSectionMappedView;
    ViewSize = pData->cbSectViewSize;

    // Call the NtMapViewOfSection
    Status = NtMapViewOfSection(pData->hSection,
                                NtCurrentProcess(),
                               &BaseAddress,
                                0,
                                pData->cbSectCommitSize,
                               &SectionOffset,
                               &ViewSize,
                                ViewShare,
                                pData->dwSectAllocType,
                                pData->dwSectWin32Protect);
    if(NT_SUCCESS(Status))
    {
        // If the section offset changed, set it to the dialog control
        if(SectionOffset.QuadPart != pData->SectionOffset.QuadPart)
            Hex2DlgText64(hDlg, IDC_SECTION_OFFSET, SectionOffset.QuadPart);
        if(BaseAddress != pData->pvSectionMappedView)
            Hex2DlgTextPtr(hDlg, IDC_BASE_ADDRESS, (ULONG_PTR)BaseAddress);
        if(ViewSize != pData->cbSectViewSize)
            Hex2DlgTextPtr(hDlg, IDC_VIEW_SIZE, ViewSize);
        
        // Remember the view
        pData->pvSectionMappedView = BaseAddress;
        pData->cbSectViewSize = ViewSize;
        pData->bSectionViewMapped = TRUE;
    }

    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_HANDLE, Status, pData->hSection);
    UpdateDialog(hDlg, pData);
    return TRUE;
}

static int OnDataEditor(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);

    if(SaveDialog2(hDlg) == ERROR_SUCCESS)
        DataEditorDialog(hDlg, pData->pvSectionMappedView, pData->cbSectViewSize);

    return TRUE;
}

static int OnUnmapViewClick(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    NTSTATUS Status;

    // Get the base address where it is mapped
    if(SaveDialog2(hDlg) == ERROR_SUCCESS)
    {
        // Unmap the view from the base address
        Status = NtUnmapViewOfSection(NtCurrentProcess(), pData->pvSectionMappedView);

        // Clear the base address, so the next click on "MapView" will succeed
        Hex2DlgTextPtr(hDlg, IDC_BASE_ADDRESS, NULL);
        pData->pvSectionMappedView = NULL;

        // Clear the view size, so the next click on "MapView" will succeed
        Hex2DlgTextPtr(hDlg, IDC_VIEW_SIZE, 0);
        pData->cbSectViewSize = 0;

        // Show the result
        SetResultInfo(hDlg, RSI_NTSTATUS | RSI_HANDLE, Status, pData->hSection);
        UpdateDialog(hDlg, pData);
    }
    return TRUE;
}

static int OnDeltaPos(HWND hDlg, NMUPDOWN * pNMUpDown)
{
    UINT nIDCtrl = 0;
    bool bIsValuePointer = false;

    switch(pNMUpDown->hdr.idFrom)
    {
        case IDC_SECTION_SIZE_UPDOWN:
            nIDCtrl = IDC_SECTION_SIZE;
            break;

        case IDC_BASE_ADDRESS_UPDOWN:
            nIDCtrl = IDC_BASE_ADDRESS;
            bIsValuePointer = true;
            break;

        case IDC_COMMIT_SIZE_UPDOWN:
            nIDCtrl = IDC_COMMIT_SIZE;
            bIsValuePointer = true;
            break;

        case IDC_SECTION_OFFSET_UPDOWN:
            nIDCtrl = IDC_SECTION_OFFSET;
            break;

        case IDC_VIEW_SIZE_UPDOWN:
            nIDCtrl = IDC_VIEW_SIZE;
            bIsValuePointer = true;
            break;

        default:
            assert(false);
            return FALSE;
    }

    // If we have to set a pointer, do it
    if(bIsValuePointer == false)
    {
        ULONGLONG NewValue;
        ULONGLONG OldValue;

        DlgText2Hex64(hDlg, nIDCtrl, (PLONGLONG)&OldValue);
        NewValue = OldValue - (pNMUpDown->iDelta * 0x1000);
        if(pNMUpDown->iDelta > 0 && NewValue > OldValue)
            NewValue = 0;
        Hex2DlgText64(hDlg, nIDCtrl, NewValue);
    }
    else
    {
        DWORD_PTR NewValue;
        DWORD_PTR OldValue;

        DlgText2HexPtr(hDlg, nIDCtrl, &OldValue);
        NewValue = OldValue - (pNMUpDown->iDelta * 0x1000);
        if(pNMUpDown->iDelta > 0 && NewValue > OldValue)
            NewValue = 0;
        Hex2DlgTextPtr(hDlg, nIDCtrl, NewValue);
    }
    return TRUE;
}

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    if(nNotify == BN_CLICKED)
    {
        switch(nIDCtrl)
        {
            case IDC_DESIRED_ACCESS_BROWSE:
                return OnDesiredAccessBrowse(hDlg);

            case IDC_ALLOCATION_ATTRIBUTES_BROWSE:
                return OnAllocAttributesBrowse(hDlg);

            case IDC_ALLOCATION_TYPE_BROWSE:
                return OnAllocTypeBrowse(hDlg);

            case IDC_NTCREATE_SECTION:
            case IDC_NTOPEN_SECTION:
                return OnNtCreateSectionClick(hDlg, nIDCtrl);

            case IDC_NTCLOSE:
                return OnNtCloseClick(hDlg);

            case IDC_MAPPED_FILE_NAME_QUERY:
                return OnQueryMappedFileName(hDlg);

            case IDC_MAP_VIEW:
                return OnMapViewClick(hDlg);

            case IDC_DATA_EDITOR:
                return OnDataEditor(hDlg);

            case IDC_UNMAP_VIEW:
                return OnUnmapViewClick(hDlg);
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
            return OnKillActive(hDlg);

        case UDN_DELTAPOS:
            return OnDeltaPos(hDlg, (NMUPDOWN *)pNMHDR);
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// Public functions

INT_PTR CALLBACK PageProc04(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // Call tooltip to handle messages
    g_Tooltip.HandleMessages(hDlg, uMsg, wParam, lParam, NULL);

    // Handle other messages
    switch(uMsg)
    {
        case WM_INITDIALOG:
            return OnInitDialog(hDlg, lParam);

        case WM_SIZE:
            return pAnchors->OnMessage(uMsg, wParam, lParam);

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
