/*****************************************************************************/
/* Page11Ioctl.cpp                        Copyright (c) Ladislav Zezula 2019 */
/*---------------------------------------------------------------------------*/
/* Description :                                                             */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 23.01.19  1.00  Lad  The first version of Page12Ioctl.cpp                 */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local structures

#define WM_COMBO_CHANGED (WM_USER + 0x1000)

struct TIoctlInfo
{
    LPCTSTR szName;
    ULONG IoctlCode;
    ULONG InBufferSize;
    ULONG OutBufferSize;
};

typedef NTSTATUS (NTAPI * NT_IOCTL_API)(
    IN  HANDLE FileHandle,
    IN  HANDLE Event,
    IN  PIO_APC_ROUTINE ApcRoutine,
    IN  PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN  ULONG IoControlCode,
    IN  PVOID InputBuffer,
    IN  ULONG InputBufferLength,
    IN  PVOID OutputBuffer,
    IN  ULONG OutputBufferLength
    );

//-----------------------------------------------------------------------------
// Local variables

static TIoctlInfo IoctlInfoList[] =
{
    { _T("FSCTL_SET_SPARSE"),      FSCTL_SET_SPARSE,      0,              0 },
    { _T("FSCTL_GET_COMPRESSION"), FSCTL_GET_COMPRESSION, 0,              sizeof(USHORT) },
    { _T("FSCTL_SET_COMPRESSION"), FSCTL_SET_COMPRESSION, sizeof(USHORT), 0 },
};

static TAnchors * pAnchors = NULL;

//-----------------------------------------------------------------------------
// Conversion of IOCTL device name to text

static LPCTSTR IoctlDeviceTypeNames[] =
{
    _T("FILE_DEVICE_0"),
    _T("FILE_DEVICE_BEEP"),
    _T("FILE_DEVICE_CD_ROM"),
    _T("FILE_DEVICE_CD_ROM_FILE_SYSTEM"),
    _T("FILE_DEVICE_CONTROLLER"),
    _T("FILE_DEVICE_DATALINK"),
    _T("FILE_DEVICE_DFS"),
    _T("FILE_DEVICE_DISK"),
    _T("FILE_DEVICE_DISK_FILE_SYSTEM"),
    _T("FILE_DEVICE_FILE_SYSTEM"),
    _T("FILE_DEVICE_INPORT_PORT"),
    _T("FILE_DEVICE_KEYBOARD"),
    _T("FILE_DEVICE_MAILSLOT"),
    _T("FILE_DEVICE_MIDI_IN"),
    _T("FILE_DEVICE_MIDI_OUT"),
    _T("FILE_DEVICE_MOUSE"),
    _T("FILE_DEVICE_MULTI_UNC_PROVIDER"),
    _T("FILE_DEVICE_NAMED_PIPE"),
    _T("FILE_DEVICE_NETWORK"),
    _T("FILE_DEVICE_NETWORK_BROWSER"),
    _T("FILE_DEVICE_NETWORK_FILE_SYSTEM"),
    _T("FILE_DEVICE_NULL"),
    _T("FILE_DEVICE_PARALLEL_PORT"),
    _T("FILE_DEVICE_PHYSICAL_NETCARD"),
    _T("FILE_DEVICE_PRINTER"),
    _T("FILE_DEVICE_SCANNER"),
    _T("FILE_DEVICE_SERIAL_MOUSE_PORT"),
    _T("FILE_DEVICE_SERIAL_PORT"),
    _T("FILE_DEVICE_SCREEN"),
    _T("FILE_DEVICE_SOUND"),
    _T("FILE_DEVICE_STREAMS"),
    _T("FILE_DEVICE_TAPE"),
    _T("FILE_DEVICE_TAPE_FILE_SYSTEM"),
    _T("FILE_DEVICE_TRANSPORT"),
    _T("FILE_DEVICE_UNKNOWN"),
    _T("FILE_DEVICE_VIDEO"),
    _T("FILE_DEVICE_VIRTUAL_DISK"),
    _T("FILE_DEVICE_WAVE_IN"),
    _T("FILE_DEVICE_WAVE_OUT"),
    _T("FILE_DEVICE_8042_PORT"),
    _T("FILE_DEVICE_NETWORK_REDIRECTOR"),
    _T("FILE_DEVICE_BATTERY"),
    _T("FILE_DEVICE_BUS_EXTENDER"),
    _T("FILE_DEVICE_MODEM"),
    _T("FILE_DEVICE_VDM"),
    _T("FILE_DEVICE_MASS_STORAGE"),
    _T("FILE_DEVICE_SMB"),
    _T("FILE_DEVICE_KS"),
    _T("FILE_DEVICE_CHANGER"),
    _T("FILE_DEVICE_SMARTCARD"),
    _T("FILE_DEVICE_ACPI"),
    _T("FILE_DEVICE_DVD"),
    _T("FILE_DEVICE_FULLSCREEN_VIDEO"),
    _T("FILE_DEVICE_DFS_FILE_SYSTEM"),
    _T("FILE_DEVICE_DFS_VOLUME"),
    _T("FILE_DEVICE_SERENUM"),
    _T("FILE_DEVICE_TERMSRV"),
    _T("FILE_DEVICE_KSEC"),
    _T("FILE_DEVICE_FIPS"),
    _T("FILE_DEVICE_INFINIBAND"),
    _T("FILE_DEVICE_3C"),
    _T("FILE_DEVICE_3D"),
    _T("FILE_DEVICE_VMBUS"),
    _T("FILE_DEVICE_CRYPT_PROVIDER"),
    _T("FILE_DEVICE_WPD"),
    _T("FILE_DEVICE_BLUETOOTH"),
    _T("FILE_DEVICE_MT_COMPOSITE"),
    _T("FILE_DEVICE_MT_TRANSPORT"),
    _T("FILE_DEVICE_BIOMETRIC"),
    _T("FILE_DEVICE_PMI")
};

static LPCTSTR GetIoctlDeviceType(DWORD dwIoctlCode)
{
    static TCHAR szDeviceType[128];
    DWORD dwDeviceType = DEVICE_TYPE_FROM_CTL_CODE(dwIoctlCode);

    if(dwDeviceType <= _countof(IoctlDeviceTypeNames))
        return IoctlDeviceTypeNames[dwDeviceType];

    StringCchPrintf(szDeviceType, _countof(szDeviceType), _T("0x%X"), dwDeviceType);
    return szDeviceType;
}

//-----------------------------------------------------------------------------
// Conversion of IOCTL method to text

static LPCTSTR IoctlMethodNames[] =
{
    _T("METHOD_BUFFERED"),
    _T("METHOD_IN_DIRECT"),
    _T("METHOD_OUT_DIRECT"),
    _T("METHOD_NEITHER"),
};

LPCTSTR GetIoctlMethod(DWORD dwIoctlCode)
{
    return IoctlMethodNames[METHOD_FROM_CTL_CODE(dwIoctlCode)];
}

//-----------------------------------------------------------------------------
// Conversion of IOCTL code to access name

static LPCTSTR IoctlAccessNames[] =
{
    _T("FILE_ANY_ACCESS"),
    _T("FILE_READ_ACCESS"),
    _T("FILE_WRITE_ACCESS"),
    _T("FILE_READ_ACCESS | FILE_WRITE_ACCESS"),
};

LPCTSTR GetIoctlAccess(DWORD dwIoctlCode)
{
    return IoctlAccessNames[(dwIoctlCode >> 14) & 0x0003];
}

//-----------------------------------------------------------------------------
// Helper functions

static void CompleteAsynchronousOperation(HWND hDlg, TApcEntry * pApc, DWORD dwErrCode, DWORD dwTransferred)
{
    TFileTestData * pData = GetDialogData(hDlg);
    HWND hWndEditor;

    // Convert the error code and number of bytes transferred
    if(pApc->bAsynchronousCompletion)
    {
        if(pApc->bHasIoStatus == false)
        {
            if(!GetOverlappedResult(pData->hFile, &pApc->Overlapped, &dwTransferred, TRUE))
                dwErrCode = GetLastError();
            else
                dwErrCode = ERROR_SUCCESS;
        }
    }

    // If the operation has succeeded, update few UI elements
    if(dwErrCode == ERROR_SUCCESS)
    {
        // If we have an output buffer, copy it to the data buffer
        if(pApc->BufferLength)
        {
            // Copy the data buffer from the APC to our user buffer
            pData->OutData.SetLength(pApc->BufferLength);
            memcpy(pData->OutData.pbData, (pApc + 1), pData->OutData.cbData);

            hWndEditor = GetDlgItem(hDlg, IDC_OUTPUT_DATA);
            DataEditor_SetData(hWndEditor, 0, pData->OutData.pbData, pData->OutData.cbData);
        }
    }

    // Set the information about the operation
    if(pApc->bHasIoStatus)
        SetResultInfo(hDlg, RSI_NTSTATUS | RSI_INFORMATION, pApc->IoStatus.Status, &pApc->IoStatus);
    else
        SetResultInfo(hDlg, RSI_LAST_ERROR | RSI_INFO_INT32, dwErrCode, dwTransferred);

    // Free the APC entry
    FreeApcEntry(pApc);
}

//-----------------------------------------------------------------------------
// Local functions

static void AddAnchorData(HWND hDlg, TAnchors * pAnc, UINT nIDFrame, UINT nIDLabel, UINT nIDLength, UINT nIDSpin, UINT nIDData)
{
    pAnc->AddAnchor(hDlg, nIDFrame, akLeft | akRight | akBottom);
    pAnc->AddAnchor(hDlg, nIDLabel, akLeft | akRight | akBottom);
    pAnc->AddAnchor(hDlg, nIDLength, akLeft | akRight | akBottom);
    pAnc->AddAnchor(hDlg, nIDSpin, akRight | akBottom);
    pAnc->AddAnchor(hDlg, nIDData, akLeft | akRight | akBottom);
}

static void InitializeData(HWND hDlg, UINT nIDLength, UINT nIDData)
{
    HWND hWndChild;

    // Set the length of the data
    Hex2DlgText32(hDlg, nIDLength, 0);

    if ((hWndChild = GetDlgItem(hDlg, nIDData)) != NULL)
    {
        DataEditor_SetDataFormat(hWndChild, PtrPointer32Bit, 0x08);
        DataEditor_SetData(hWndChild, 0, NULL, 0);
    }
}

static void UpdateIoctlData(HWND hDlg, UINT nIDLength)
{
    TFileTestData * pData = GetDialogData(hDlg);
    TDataBlob * pDataBlob = NULL;
    HWND hWndChild = NULL;
    BOOL bTranslated = FALSE;
    UINT dwValue;

    // The dialog must be initialized
    if (pData != NULL)
    {
        // Translate the text value into a number
        dwValue = GetDlgItemInt(hDlg, nIDLength, &bTranslated, FALSE);
        if (bTranslated)
        {
            // Retrieve the data editor handle
            if (nIDLength == IDC_INPUT_DATA_LENGTH)
            {
                hWndChild = GetDlgItem(hDlg, IDC_INPUT_DATA);
                pDataBlob = &pData->InData;
            }
            if (nIDLength == IDC_OUTPUT_DATA_LENGTH)
            {
                hWndChild = GetDlgItem(hDlg, IDC_OUTPUT_DATA);
                pDataBlob = &pData->OutData;
            }

            // If both controls exist, update them
            if (pDataBlob != NULL && hWndChild != NULL)
            {
                // Set the data size and the data itself
                pDataBlob->SetLength(dwValue);
                DataEditor_SetData(hWndChild, 0, pDataBlob->pbData, pDataBlob->cbData);
            }
        }
    }
}

//-----------------------------------------------------------------------------
// Message handlers

static int OnInitDialog(HWND hDlg, LPARAM lParam)
{
    PROPSHEETPAGE * pPage = (PROPSHEETPAGE *)lParam;
    TFileTestData * pData = (TFileTestData *)pPage->lParam;
    HWND hWndChild;
    int nIndex;

    // Save the data pointer into the dialog
    SetDialogData(hDlg, pPage->lParam);

    // Configure dialog resizing
    if(pData->bEnableResizing)
    {
        if ((pAnchors = new TAnchors()) != NULL)
        {
            pAnchors->AddAnchor(hDlg, IDC_IOCTL_REQUEST_FRAME, akAll);
            pAnchors->AddAnchor(hDlg, IDC_IOCTL_CODE, akLeft | akTop | akRight);
            pAnchors->AddAnchor(hDlg, IDC_IOCTL_CODE_DECODED_TITLE, akLeft | akTop | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_IOCTL_CODE_DECODED, akAll);

            AddAnchorData(hDlg, pAnchors, IDC_INPUT_DATA_FRAME, IDC_INPUT_DATA_HINT, IDC_INPUT_DATA_LENGTH, IDC_INPUT_DATA_SPIN, IDC_INPUT_DATA);
            AddAnchorData(hDlg, pAnchors, IDC_OUTPUT_DATA_FRAME, IDC_OUTPUT_DATA_HINT, IDC_OUTPUT_DATA_LENGTH, IDC_OUTPUT_DATA_SPIN, IDC_OUTPUT_DATA);

            pAnchors->AddAnchor(hDlg, IDC_DEVICE_IO_CONTROL1, akLeft | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_DEVICE_IO_CONTROL2, akLeftCenter | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_DEVICE_IO_CONTROL3, akRight | akBottom);

            pAnchors->AddAnchor(hDlg, IDC_RESULT_FRAME, akLeft | akRight | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE_TITLE, akLeft | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_ERROR_CODE, akLeft | akRight | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_INFORMATION_TITLE, akLeft | akBottom);
            pAnchors->AddAnchor(hDlg, IDC_INFORMATION, akLeft | akRight | akBottom);
        }
    }

    // Configure input data
    InitializeData(hDlg, IDC_INPUT_DATA_LENGTH, IDC_INPUT_DATA);
    InitializeData(hDlg, IDC_OUTPUT_DATA_LENGTH, IDC_OUTPUT_DATA);

    // Initialize combo box with the IOCTL list
    if ((hWndChild = GetDlgItem(hDlg, IDC_IOCTL_CODE)) != NULL)
    {
        for (size_t i = 0; i < _countof(IoctlInfoList); i++)
        {
            nIndex = ComboBox_AddString(hWndChild, IoctlInfoList[i].szName);
        }
    }

    return TRUE;
}

static int OnSetActive(HWND hDlg)
{
    TFileTestData * pData = GetDialogData(hDlg);
    BOOL bEnabled = (IsHandleValid(pData->hFile)) ? TRUE : FALSE;

    // Enable/disable the buttons
    EnableDlgItems(hDlg, bEnabled, IDC_DEVICE_IO_CONTROL1, IDC_DEVICE_IO_CONTROL2, IDC_DEVICE_IO_CONTROL3, 0);
    return TRUE;
}

static int OnDeltaPos(HWND hDlg, NMUPDOWN * pNMUpDown, UINT nIDLength)
{
    HWND hWndChild;
    DWORD dwValue = 0;

    if ((hWndChild = GetDlgItem(hDlg, nIDLength)) != NULL)
    {
        // Change the value
        DlgText2Hex32(hDlg, nIDLength, &dwValue);
        dwValue -= pNMUpDown->iDelta;
        if(dwValue & 0x80000000)
            dwValue = 0;
        Hex2DlgText32(hDlg, nIDLength, dwValue);

        // Update the data
        UpdateIoctlData(hDlg, nIDLength);
    }

    return TRUE;
}

static int OnDeltaPos(HWND hDlg, NMUPDOWN * pNMUpDown)
{
    if (pNMUpDown->hdr.idFrom == IDC_INPUT_DATA_SPIN)
        return OnDeltaPos(hDlg, pNMUpDown, IDC_INPUT_DATA_LENGTH);
    if(pNMUpDown->hdr.idFrom == IDC_OUTPUT_DATA_SPIN)
        return OnDeltaPos(hDlg, pNMUpDown, IDC_OUTPUT_DATA_LENGTH);

    return FALSE;
}

static void OnComboBoxEditChange(HWND hDlg)
{
    DWORD dwIoctlCode;

    if(DlgText2Hex32(hDlg, IDC_IOCTL_CODE, &dwIoctlCode) == ERROR_SUCCESS)
    {
        LPCTSTR szDeviceType = GetIoctlDeviceType(dwIoctlCode);
        LPCTSTR szMethod = GetIoctlMethod(dwIoctlCode);
        LPCTSTR szAccess = GetIoctlAccess(dwIoctlCode);
        DWORD dwFunction = (dwIoctlCode >> 2) & 0xFFF;
        TCHAR szText[0x100];

        // Get the device type
        rsprintf(szText, _countof(szText), IDS_IOCTL_FORMAT, szDeviceType, dwFunction, szMethod, szAccess);
        SetDlgItemText(hDlg, IDC_IOCTL_CODE_DECODED, szText);
    }
}

static void OnComboBoxSelChanged(HWND hDlg)
{
    TIoctlInfo * pIoctlInfo;
    HWND hWndChild;
    int nIndex;

    if ((hWndChild = GetDlgItem(hDlg, IDC_IOCTL_CODE)) != NULL)
    {
        if ((nIndex = ComboBox_GetCurSel(hWndChild)) != CB_ERR)
        {
            if(nIndex < _countof(IoctlInfoList))
            {
                // Get the IOCTL info
                pIoctlInfo = &IoctlInfoList[nIndex];

                // Change the combo box's value
                Hex2DlgText32(hDlg, IDC_IOCTL_CODE, pIoctlInfo->IoctlCode);
                OnComboBoxEditChange(hDlg);

                // Set the input data length
                Hex2DlgText32(hDlg, IDC_INPUT_DATA_LENGTH, pIoctlInfo->InBufferSize);
                Hex2DlgText32(hDlg, IDC_OUTPUT_DATA_LENGTH, pIoctlInfo->OutBufferSize);
            }
        }
    }
}

static void OnIoctlClick(HWND hDlg, UINT nIDCtrl)
{
    TFileTestData * pData = GetDialogData(hDlg);
    NT_IOCTL_API NtIoControlApi;
    TApcEntry * pApc;
    NTSTATUS Status;
    LPBYTE OutputBuffer = NULL;
    LPBYTE InputBuffer = NULL;
    ULONG OutputLength = 0;
    ULONG InputLength = 0;
    ULONG IoctlCode = 0;
    DWORD dwTransferred = 0;
    DWORD dwErrCode = ERROR_SUCCESS;

    // Get the lengths
    DlgText2Hex32(hDlg, IDC_OUTPUT_DATA_LENGTH, &OutputLength);
    assert(pData->OutData.cbData == OutputLength);
    DlgText2Hex32(hDlg, IDC_INPUT_DATA_LENGTH, &InputLength);
    assert(pData->InData.cbData == InputLength);
    DlgText2Hex32(hDlg, IDC_IOCTL_CODE, &IoctlCode);
    assert(IoctlCode != 0);

    // Create new APC entry
    pApc = CreateApcEntry(pData, APC_TYPE_IOCTL, OutputLength);
    if(pApc != NULL)
    {
        // Configure the APC
        if((pApc->BufferLength = OutputLength) != 0)
            OutputBuffer = (LPBYTE)(pApc + 1);
        if(InputLength != 0)
            InputBuffer = pData->InData.pbData;

        // Perform function-specific call
        switch (nIDCtrl)
        {
            case IDC_DEVICE_IO_CONTROL1:

                if(!DeviceIoControl(pData->hFile,
                                    IoctlCode,
                                    InputBuffer,
                                    InputLength,
                                    OutputBuffer,
                                    OutputLength,
                                   &dwTransferred,
                                   &pApc->Overlapped))
                {
                    dwErrCode = GetLastError();
                }

                if(dwErrCode == ERROR_IO_PENDING)
                {
                    SetResultInfo(hDlg, RSI_LAST_ERROR | RSI_INFO_INT32, ERROR_IO_PENDING, 0);
                    InsertApcEntry(pData, pApc);
                    return;
                }
                break;

            case IDC_DEVICE_IO_CONTROL2:
            case IDC_DEVICE_IO_CONTROL3:

                // Configure the APC
                NtIoControlApi = (nIDCtrl == IDC_DEVICE_IO_CONTROL2) ? NtDeviceIoControlFile : NtFsControlFile;
                pApc->bHasIoStatus = TRUE;

                // Call the appropriate API
                Status = NtIoControlApi(pData->hFile,
                                        pApc->hEvent,
                                        NULL,
                                        NULL,
                                       &pApc->IoStatus,
                                        IoctlCode,
                                        InputBuffer,
                                        InputLength,
                                        OutputBuffer,
                                        OutputLength);

                // If the read operation ended with STATUS_PENDING, queue the APC
                if(Status == STATUS_PENDING)
                {
                    SetResultInfo(hDlg, RSI_NTSTATUS | RSI_INFORMATION, STATUS_PENDING, &pApc->IoStatus);
                    InsertApcEntry(pData, pApc);
                    return;
                }
                
                pApc->IoStatus.Status = Status;
                break;
        }

        // Complete the read/write operation
        CompleteAsynchronousOperation(hDlg, pApc, dwErrCode, dwTransferred);
    }
    else
    {
        SetResultInfo(hDlg, RSI_LAST_ERROR | RSI_NOINFO, GetLastError());
    }
}

static int OnCommand(HWND hDlg, UINT nNotify, UINT nIDCtrl)
{
    switch (nNotify)
    {
        case EN_CHANGE:
            UpdateIoctlData(hDlg, nIDCtrl);
            return FALSE;

        case CBN_SELENDOK: // Can't change combo box's text right now, need to postpone
            PostMessage(hDlg, WM_COMBO_CHANGED, 0, 0);
            return FALSE;

        case CBN_EDITCHANGE:
            OnComboBoxEditChange(hDlg);
            return FALSE;

        case BN_CLICKED:
            if(nIDCtrl == IDC_DEVICE_IO_CONTROL1 || nIDCtrl == IDC_DEVICE_IO_CONTROL2 || nIDCtrl == IDC_DEVICE_IO_CONTROL3)
                OnIoctlClick(hDlg, nIDCtrl);
            return FALSE;
    }
    
    return TRUE;
}

static int OnNotify(HWND hDlg, NMHDR * pNMHDR)
{
    switch(pNMHDR->code)
    {
        case PSN_SETACTIVE:
            return OnSetActive(hDlg);

        case UDN_DELTAPOS:
            return OnDeltaPos(hDlg, (NMUPDOWN *)pNMHDR);
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// Public functions

INT_PTR CALLBACK PageProc12(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // Handlers specific to our dialog
    switch(uMsg)
    {
        case WM_INITDIALOG:
            OnInitDialog(hDlg, lParam);
            return TRUE;

        case WM_SIZE:
            if(pAnchors != NULL)
                pAnchors->OnSize();
            return FALSE;

        case WM_COMBO_CHANGED:
            OnComboBoxSelChanged(hDlg);
            return FALSE;

        case WM_APC:
            CompleteAsynchronousOperation(hDlg, (TApcEntry *)lParam, 0, 0);
            return TRUE;

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
