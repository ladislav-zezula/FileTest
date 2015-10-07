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

static TFlagInfo DesiredAccessValues[] =
{
    FLAG_INFO_ENTRY(SECTION_QUERY,                TRUE),
    FLAG_INFO_ENTRY(SECTION_MAP_WRITE,            TRUE),
    FLAG_INFO_ENTRY(SECTION_MAP_READ,             TRUE),
    FLAG_INFO_ENTRY(SECTION_MAP_EXECUTE,          TRUE),
    FLAG_INFO_ENTRY(SECTION_EXTEND_SIZE,          TRUE),
    FLAG_INFO_ENTRY(SECTION_MAP_EXECUTE_EXPLICIT, TRUE),

    FLAG_INFO_ENTRY(DELETE,                       TRUE),
    FLAG_INFO_ENTRY(READ_CONTROL,                 TRUE),
    FLAG_INFO_ENTRY(WRITE_DAC,                    TRUE),
    FLAG_INFO_ENTRY(WRITE_OWNER,                  TRUE),
    FLAG_INFO_ENTRY(SYNCHRONIZE,                  TRUE),
    FLAG_INFO_ENTRY(ACCESS_SYSTEM_SECURITY,       TRUE),
    FLAG_INFO_ENTRY(GENERIC_READ,                 TRUE),
    FLAG_INFO_ENTRY(GENERIC_WRITE,                TRUE),
    FLAG_INFO_ENTRY(GENERIC_EXECUTE,              TRUE),
    FLAG_INFO_ENTRY(GENERIC_ALL,                  TRUE),
    FLAG_INFO_END
};

TFlagInfo AllocationAttributesValues[] =
{
    FLAG_INFO_ENTRY(SEC_FILE,            TRUE),
    FLAG_INFO_ENTRY(SEC_IMAGE,           TRUE),
    FLAG_INFO_ENTRY(SEC_PROTECTED_IMAGE, TRUE),
    FLAG_INFO_ENTRY(SEC_RESERVE,         TRUE),
    FLAG_INFO_ENTRY(SEC_COMMIT,          TRUE),
    FLAG_INFO_ENTRY(SEC_NOCACHE,         TRUE),
    FLAG_INFO_ENTRY(SEC_WRITECOMBINE,    TRUE),
    FLAG_INFO_ENTRY(SEC_LARGE_PAGES,     TRUE),
    FLAG_INFO_END,
};


static TFlagInfo AllocationTypeValues[] =
{
    FLAG_INFO_ENTRY(MEM_COMMIT,          TRUE),
    FLAG_INFO_ENTRY(MEM_RESERVE,         TRUE),
    FLAG_INFO_ENTRY(MEM_DECOMMIT,        TRUE),
    FLAG_INFO_ENTRY(MEM_RELEASE,         TRUE),
    FLAG_INFO_ENTRY(MEM_FREE,            TRUE),
    FLAG_INFO_ENTRY(MEM_PRIVATE,         TRUE),
    FLAG_INFO_ENTRY(MEM_MAPPED,          TRUE),
    FLAG_INFO_ENTRY(MEM_RESET,           TRUE),
    FLAG_INFO_ENTRY(MEM_TOP_DOWN,        TRUE),
    FLAG_INFO_ENTRY(MEM_WRITE_WATCH,     TRUE),
    FLAG_INFO_ENTRY(MEM_PHYSICAL,        TRUE),
    FLAG_INFO_ENTRY(MEM_ROTATE,          TRUE),
    FLAG_INFO_ENTRY(MEM_LARGE_PAGES,     TRUE),
    FLAG_INFO_ENTRY(MEM_4MB_PAGES,       TRUE),
    FLAG_INFO_END,
};

static TFlagInfo PageProtectionValues[] =
{
    FLAG_INFO_ENTRY(PAGE_NOACCESS,           TRUE),   
    FLAG_INFO_ENTRY(PAGE_READONLY,           TRUE),   
    FLAG_INFO_ENTRY(PAGE_READWRITE,          TRUE),   
    FLAG_INFO_ENTRY(PAGE_WRITECOPY,          TRUE),   
    FLAG_INFO_ENTRY(PAGE_EXECUTE,            TRUE),   
    FLAG_INFO_ENTRY(PAGE_EXECUTE_READ,       TRUE),   
    FLAG_INFO_ENTRY(PAGE_EXECUTE_READWRITE,  TRUE),   
    FLAG_INFO_ENTRY(PAGE_EXECUTE_WRITECOPY,  TRUE),   
    FLAG_INFO_ENTRY(PAGE_GUARD,              TRUE),
    FLAG_INFO_ENTRY(PAGE_NOCACHE,            TRUE),
    FLAG_INFO_ENTRY(PAGE_WRITECOMBINE,       TRUE),
    FLAG_INFO_END,
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
        while(pFlags->szFlagText != NULL)
        {
            // Format and insert the string to the combo box
            _stprintf(szItemText, _T("[%04X] %s"), pFlags->dwFlag, pFlags->szFlagText);
            ComboBox_AddString(hWndCombo, szItemText);

            // Move to the next flag
            pFlags++;
        }
    }
}

static void Hex2PageProtection(HWND hDlg, UINT nIDCombo, DWORD dwProtection)
{
    HWND hWndCombo = GetDlgItem(hDlg, nIDCombo);
    int nItemIndex = 0;

    if(hWndCombo != NULL)
    {
        // Find the proper page protection
        for(int i = 0; PageProtectionValues[i].szFlagText != NULL; i++)
        {
            if(dwProtection == PageProtectionValues[i].dwFlag)
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
    int nMaxItemIndex = (int)(sizeof(PageProtectionValues) / sizeof(TFlagInfo)) - 1;
    int nItemIndex;

    if(hWndCombo != NULL)
    {
        // Get the selected item
        nItemIndex = ComboBox_GetCurSel(hWndCombo);
        if(nItemIndex == CB_ERR || nItemIndex > nMaxItemIndex)
            nItemIndex = 0;

        // Get the page protection
        return PageProtectionValues[nItemIndex].dwFlag;
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
    int nError;

    GetDlgItemText(hDlg, IDC_SECTION_NAME, pData->szSectionName, _maxchars(pData->szSectionName));

    if((nError = DlgText2Hex64(hDlg, IDC_SECTION_SIZE, &pData->MaximumSize.QuadPart)) != ERROR_SUCCESS)
        return nError;
    if((nError = DlgText2Hex32(hDlg, IDC_DESIRED_ACCESS, &pData->dwSectDesiredAccess)) != ERROR_SUCCESS)
        return nError;
    if((nError = DlgText2Hex32(hDlg, IDC_ALLOCATION_ATTRIBUTES, &pData->dwSectAllocAttributes)) != ERROR_SUCCESS)
        return nError;

    pData->dwSectPageProtection = PageProtection2Hex(hDlg, IDC_PAGE_PROTECTION);
    return ERROR_SUCCESS;
}

static int SaveDialog2(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    int nError;

    if((nError = DlgText2HexPtr(hDlg, IDC_BASE_ADDRESS, (PDWORD_PTR)(&pData->pvSectionMappedView))) != ERROR_SUCCESS)
        return nError;
    if((nError = DlgText2HexPtr(hDlg, IDC_COMMIT_SIZE, (PDWORD_PTR)(&pData->cbSectCommitSize))) != ERROR_SUCCESS)
        return nError;
    if((nError = DlgText2Hex64(hDlg, IDC_SECTION_OFFSET, &pData->SectionOffset.QuadPart)) != ERROR_SUCCESS)
        return nError;
    if((nError = DlgText2HexPtr(hDlg, IDC_VIEW_SIZE, (PDWORD_PTR)(&pData->cbSectViewSize))) != ERROR_SUCCESS)
        return nError;
    if((nError = DlgText2Hex32(hDlg, IDC_ALLOCATION_TYPE, &pData->dwSectAllocType)) != ERROR_SUCCESS)
        return nError;
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
        pAnchors = new TAnchors();
        pAnchors->AddAnchor(hDlg, IDC_SECTION_FRAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SECTION_NAME, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SECTION_SIZE, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_SECTION_SIZE_UPDOWN, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_DESIRED_ACCESS, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_DESIRED_ACCESS_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_PAGE_PROTECTION, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_ALLOCATION_ATTRIBUTES, akLeft | akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_ALLOCATION_ATTRIBUTES_BROWSE, akTop | akRight);
        pAnchors->AddAnchor(hDlg, IDC_FILE_HANDLE, akLeft | akTop | akRight);

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

        pAnchors->AddAnchor(hDlg, IDC_MAP_VIEW, akLeft | akTop);
        pAnchors->AddAnchor(hDlg, IDC_DATA_EDITOR, akLeftCenter | akTop);
        pAnchors->AddAnchor(hDlg, IDC_UNMAP_VIEW, akRight | akTop);

        pAnchors->AddAnchor(hDlg, IDC_RESULT_FRAME, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_STATUS_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_RESULT_STATUS, akLeft | akRight | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_HANDLE_TITLE, akLeft | akBottom);
        pAnchors->AddAnchor(hDlg, IDC_HANDLE, akLeft | akRight | akBottom);
    }

    // If we have a tooltip window, init tooltips 
    g_Tooltip.AddToolTip(hDlg, IDC_DESIRED_ACCESS, DesiredAccessValues);
    g_Tooltip.AddToolTip(hDlg, IDC_ALLOCATION_ATTRIBUTES, AllocationAttributesValues);
    g_Tooltip.AddToolTip(hDlg, IDC_ALLOCATION_TYPE, AllocationTypeValues);

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

    // Either set NULL or the handle value
    if(FileHandle == NULL)
        SetDlgItemText(hDlg, IDC_FILE_HANDLE, _T("NULL"));
    else
        Hex2DlgTextPtr(hDlg, IDC_FILE_HANDLE, (DWORD_PTR)FileHandle);

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
    FlagsDialog(hDlg, IDC_DESIRED_ACCESS, IDS_DESIRED_ACCESS, DesiredAccessValues);
    return TRUE;
}

static int OnAllocAttributesBrowse(HWND hDlg)
{
    FlagsDialog(hDlg, IDC_ALLOCATION_ATTRIBUTES, IDS_ALLOCATION_ATTRIBUTES, AllocationAttributesValues);
    return TRUE;
}

static int OnAllocTypeBrowse(HWND hDlg)
{
    FlagsDialog(hDlg, IDC_ALLOCATION_TYPE, IDS_ALLOCATION_TYPE, AllocationTypeValues);
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
    SetResultInfo(hDlg, Status, pData->hSection);
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
    SetResultInfo(hDlg, Status, pData->hSection);
    UpdateDialog(hDlg, pData);
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

    SetResultInfo(hDlg, Status, pData->hSection);
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
        SetResultInfo(hDlg, Status, pData->hSection);
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
            if(pAnchors != NULL)
                pAnchors->OnSize();
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
