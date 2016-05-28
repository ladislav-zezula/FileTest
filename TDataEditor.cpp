/*****************************************************************************/
/* TDataEditor.h                          Copyright (c) Ladislav Zezula 2014 */
/*---------------------------------------------------------------------------*/
/* Description :                                                             */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 18.03.14  1.00  Lad  The first version of TDataEditor.cpp                 */
/*****************************************************************************/

#include "FileTest.h"

//-----------------------------------------------------------------------------
// Local defines

#define DATAEDIT_SPACES_BEFORE_HEXA     2
#define DATAEDIT_SPACES_BEFORE_TEXT     2

#define DATAEDIT_END_OF_LINE   0x7FFFFFFF

//-----------------------------------------------------------------------------
// Data for DataEditor

// Selection mode for MoveCaretTo
enum TSelectMode
{
    SmUnchanged = 0,
    SmStartSelection,
    SmContinueSelection
};

// Internal data structure
struct TEditorData
{
    ULONGLONG BaseAddress;                  // Base address of the data
    LPBYTE   pbEditorDataBegin;             // Pointer to the editor data
    LPBYTE   pbEditorDataEnd;               // Pointer to the editor data
    LPTSTR   szLineBuffer;                  // Buffer for formatting single line
    HFONT    hFont;                         // Currently used font
    HWND     hWndParent;                    // Parent window
    HWND     hWnd;                          // Window handle
    DWORD    dwStyles;                      // Window styles
    DWORD    dwId;                          // Control ID
    ULONG    ExceptionCode;                 // Last exception code

    size_t   nTopIndex;                     // Index of the top line
    size_t   nLines;                        // Number of lines

    int      cbBytesPerLine;                // Number of bytes per line
    int      nPointerSize;                  // Width of the address, in chars
    int      nAddressWidth;                 // Width of the address, in chars
    int      nBeginHexaValues;              // Start of the hexa values in the line
    int      nEndHexaValues;                // End of the hexa values in the line
    int      nBeginTextValues;              // Start of the text values in the line
    int      nEndTextValues;                // End of the hexa values in the line
    int      nHeight;                       // Height of the client area
    int      nWidth;                        // Width of the client area
    int      nLeftOrg;                      // Origin of the left border (0 = default) in pixels
    int      nCharHeight;                   // Height of one character, in screen pixels
    int      nAveCharWidth;                 // Average width of one character, in screen pixels
    int      nTabSize;                      // Size of one tab character, in logical units
    int      nFullVisibleLines;             // Number of fully visible lines
    int      nVisibleLines;                 // Number of visible lines (including the last one, partially visible)
    size_t   nStartSelLine;                 // Start selection
    int      nStartSelCol;                  // Start selection
    size_t   nEndSelLine;                   // End selection
    int      nEndSelCol;                    // End selection
    size_t   nCaretLine;                    // Line of the caret
    int      nCaretCol;                     // Column of the caret
    int      nCaretX;                       // X-Position of the caret
    int      nCaretY;                       // Y-Position of the caret
    bool     bWriteException;
    bool     bReadException;
    bool     bHasCapture;                   // If true if selecting text with the mouse
    bool     bFixedFont;                    // If true, it means that we use fixed font size
    bool     bHasCaret;
};

#define GetEditorData(hWnd)   ((TEditorData *)(LONG_PTR)GetWindowLongPtr(hWnd, GWLP_USERDATA))

//-----------------------------------------------------------------------------
// Local variables

// ASCII to printable characters
BYTE AsciiToPrintableTable[256] = 
{
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E
};

static LPCTSTR IntToHexTable = _T("0123456789ABCDEF");

const LPTSTR szDataEditClassName = _T("DataEditor");

//-----------------------------------------------------------------------------
// Data access functions

static void SendExceptionNotification(
    TEditorData * pData,
    PVOID ExceptionAddress,
    ULONG ExceptionCode,
    BOOL WriteOperation)
{
    DTE_EXCEPTION_DATA Data;

    // Notify the parent about the exception
    Data.hdr.hwndFrom = pData->hWnd;
    Data.hdr.idFrom   = pData->dwId;
    Data.hdr.code     = DEN_EXCEPTION;
    
    Data.ExceptionAddress = ExceptionAddress;
    Data.ExceptionCode    = ExceptionCode;
    Data.WriteOperation   = WriteOperation;
    SendMessage(pData->hWndParent, WM_NOTIFY, pData->dwId, (LPARAM)&Data);
}


static BYTE GuardedReadByte(TEditorData * pData, size_t cbByteOffset)
{
    BYTE OneByte = 0;

    __try
    {
        // Only attempt to read the exception when read exception was not there yet
        if(pData->bReadException == false)
        {
            assert((pData->pbEditorDataBegin + cbByteOffset) < pData->pbEditorDataEnd);
            OneByte = pData->pbEditorDataBegin[cbByteOffset];
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // Notify parent about the exception
        SendExceptionNotification(pData, pData->pbEditorDataBegin + cbByteOffset, GetExceptionCode(), FALSE);

        // Remember that we has a read exception
        pData->ExceptionCode  = GetExceptionCode();
        pData->bReadException = true;
    }

    return OneByte;
}

static void GuardedWriteBuffer(TEditorData * pData, size_t cbByteOffset, LPCVOID pvBuffer, size_t cbLength)
{
    __try
    {
        // Only attempt to read the exception when read exception was not there yet
        if(pData->bWriteException == false)
        {
            assert((pData->pbEditorDataBegin + cbByteOffset) < pData->pbEditorDataEnd);
            memcpy(pData->pbEditorDataBegin + cbByteOffset, pvBuffer, cbLength);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // Notify parent about the exception
        SendExceptionNotification(pData, pData->pbEditorDataBegin + cbByteOffset, GetExceptionCode(), TRUE);

        // Remember that we has a write exception
        pData->ExceptionCode  = GetExceptionCode();
        pData->bWriteException = true;
    }
}

static void PasteTextInternal(TEditorData * pData, LPCSTR szPasteText, size_t PasteOffset, size_t PasteLength)
{
    LPBYTE pbPastePosition = pData->pbEditorDataBegin + PasteOffset;

    // If the paste position is before the end of data, do it
    if(pbPastePosition < pData->pbEditorDataEnd)
    {
        // Check the length of the data
        if((pbPastePosition + PasteLength) > pData->pbEditorDataEnd)
            PasteLength = (size_t)(pData->pbEditorDataEnd - pbPastePosition);

        // Perform the guarded memcopy
        GuardedWriteBuffer(pData, PasteOffset, szPasteText, PasteLength);
    }
}

//-----------------------------------------------------------------------------
// Local functions

// The caller needs to free the buffer using HeapFree(GetProcessHeap(), 0, szText)
static LPSTR QueryClipboardText(HWND hWnd, size_t * pcchTextLength)
{
    HANDLE hGlobal;
    LPCSTR szClipboardText;
    LPSTR szText = NULL;
    size_t cchText = 0;

    // Retrieve data from the clipboard
    if(IsClipboardFormatAvailable(CF_TEXT))
    {
        if(OpenClipboard(hWnd))
        {
            hGlobal = GetClipboardData(CF_TEXT);
            if(hGlobal != NULL)
            {
                szClipboardText = (LPCSTR)GlobalLock(hGlobal);
                if(szClipboardText != NULL)
                {
                    cchText = strlen(szClipboardText);
                    szText = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cchText + 1);
                    if(szText != NULL)
                        memcpy(szText, szClipboardText, cchText);

                    GlobalUnlock(hGlobal);
                }
            }
            CloseClipboard();
        }
    }

    // Give the result to the caller
    if(pcchTextLength != NULL)
        *pcchTextLength = cchText;
    return szText;
}

static LPTSTR FormatPointer(TEditorData * pData, LPTSTR Buffer, ULONGLONG LineAddress)
{
    ULONG PointerHigh;
    ULONG PointerLow = (ULONG)(LineAddress);

    // Put the high DWORD on 64-bit pointer
    if(pData->nPointerSize == 8)
    {
        // Get the high DWORD pointer
        PointerHigh = (ULONG)(LineAddress >> 32);

        // Format the upper DWORD
        *Buffer++ = IntToHexTable[(PointerHigh >> 0x1C) & 0x0F];
        *Buffer++ = IntToHexTable[(PointerHigh >> 0x18) & 0x0F];
        *Buffer++ = IntToHexTable[(PointerHigh >> 0x14) & 0x0F];
        *Buffer++ = IntToHexTable[(PointerHigh >> 0x10) & 0x0F];
        *Buffer++ = IntToHexTable[(PointerHigh >> 0x0C) & 0x0F];
        *Buffer++ = IntToHexTable[(PointerHigh >> 0x08) & 0x0F];
        *Buffer++ = IntToHexTable[(PointerHigh >> 0x04) & 0x0F];
        *Buffer++ = IntToHexTable[(PointerHigh >> 0x00) & 0x0F];

        // Put the separator
        *Buffer++ = _T('\'');
    }

    // Format the upper DWORD
    *Buffer++ = IntToHexTable[(PointerLow >> 0x1C) & 0x0F];
    *Buffer++ = IntToHexTable[(PointerLow >> 0x18) & 0x0F];
    *Buffer++ = IntToHexTable[(PointerLow >> 0x14) & 0x0F];
    *Buffer++ = IntToHexTable[(PointerLow >> 0x10) & 0x0F];
    *Buffer++ = IntToHexTable[(PointerLow >> 0x0C) & 0x0F];
    *Buffer++ = IntToHexTable[(PointerLow >> 0x08) & 0x0F];
    *Buffer++ = IntToHexTable[(PointerLow >> 0x04) & 0x0F];
    *Buffer++ = IntToHexTable[(PointerLow >> 0x00) & 0x0F];

    // Put the end of string
    *Buffer = 0;
    return Buffer;
}

static int FormatOneLine(TEditorData * pData, size_t nLineIndex)
{
    ULONGLONG LineAddress;
    LPBYTE pbDataBegin;
    LPBYTE pbDataPtr;
    LPBYTE pbDataEnd;
    LPTSTR szLineBuffer = pData->szLineBuffer;
    LPTSTR szLineEnd = szLineBuffer + pData->nEndTextValues;
    size_t DataOffset = (nLineIndex * pData->cbBytesPerLine);

    // Get the single line
    if(nLineIndex <= pData->nLines)
    {
        // Copy the address
        LineAddress = pData->BaseAddress + DataOffset;

        // Format the pointer
        szLineBuffer = FormatPointer(pData, szLineBuffer, LineAddress);

        // Put the spaces
        *szLineBuffer++ = _T(' ');
        *szLineBuffer++ = _T(' ');
        
        // Put the space between address and hexa values
        pbDataBegin = pData->pbEditorDataBegin + DataOffset;
        pbDataEnd = pbDataBegin + pData->cbBytesPerLine;

        // If there was an exception before, display the exception text
        pData->bReadException = false;
        GuardedReadByte(pData, DataOffset);
        if(pData->bReadException)
        {
            StringCchPrintf(szLineBuffer, (szLineEnd - szLineBuffer), _T("Exception %08X when reading address %p"), pData->ExceptionCode, pbDataBegin);
            szLineBuffer += _tcslen(szLineBuffer);
            return (int)(szLineBuffer - pData->szLineBuffer);
        }

        // Format all data as hexa values
        for(pbDataPtr = pbDataBegin; pbDataPtr < pbDataEnd; pbDataPtr++)
        {
            if(pbDataPtr < pData->pbEditorDataEnd)
            {
                *szLineBuffer++ = IntToHexTable[*pbDataPtr >> 0x04];
                *szLineBuffer++ = IntToHexTable[*pbDataPtr & 0x0F];
                *szLineBuffer++ = _T(' ');
            }
            else
            {
                *szLineBuffer++ = _T(' ');
                *szLineBuffer++ = _T(' ');
                *szLineBuffer++ = _T(' ');
            }
        }

        // Put the space between hexa values and text values
        *szLineBuffer++ = _T(' ');

        // Put the values as they are
        for(pbDataPtr = pbDataBegin; pbDataPtr < pbDataEnd; pbDataPtr++)
        {
            if(pbDataPtr < pData->pbEditorDataEnd)
            {
                *szLineBuffer++ = AsciiToPrintableTable[pbDataPtr[0]];
            }
            else
            {
                *szLineBuffer++ = _T(' ');
            }
        }
    }

    // Finish the line with zero
    *szLineBuffer = 0;
    return (int)(szLineBuffer - pData->szLineBuffer);
}

static int FindPreviousWord(TEditorData * pData, size_t nLine, int nCol)
{
    int nBeginHexaByte;
    int nCurrentByte;

    UNREFERENCED_PARAMETER(nLine);

    // If the caret position is greater than text view, move it to the begin of the text view
    if(nCol > pData->nBeginTextValues)
        return pData->nBeginTextValues;

    // If the caret position is within the hexa view, move it to the hexa byte
    if(nCol > pData->nBeginHexaValues)
    {
        // Get the current byte we are pointing at
        nCurrentByte = (nCol - pData->nBeginHexaValues) / 3;
        nBeginHexaByte = pData->nBeginHexaValues + (nCurrentByte * 3);
        if(nCol > nBeginHexaByte)
            return nBeginHexaByte;

        // Move to the previous byte
        return pData->nBeginHexaValues + (nCurrentByte - 1) * 3;
    }

    // We assume that we are before the hexa bytes --> go to position 0
    return 0;
}

static int FindNextWord(TEditorData * pData, size_t nLine, int nCol)
{
    int nCurrentByte;

    UNREFERENCED_PARAMETER(nLine);

    // If the caret position is greater than text view, move it to the end
    if(nCol >= pData->nBeginTextValues)
        return pData->nEndTextValues;

    // If the caret position is at the last byte, move it to the text area
    if(nCol >= pData->nEndHexaValues - 2)
        return pData->nBeginTextValues;

    // If the current position is at the hexa values, move to the previous hexa string
    if(nCol >= pData->nBeginHexaValues)
    {
        // Get the current byte we are pointing at
        nCurrentByte = (nCol - pData->nBeginHexaValues) / 3;
        return pData->nBeginHexaValues + (nCurrentByte + 1) * 3;
    }

    // We assume we are past the begin of the text values
    return pData->nBeginHexaValues;
}

static void CreateTextFont(TEditorData * pData)
{
    LOGFONT LogFont;

    // Create font for all windows
    ZeroMemory(&LogFont, sizeof(LOGFONT));
    LogFont.lfWeight         = FW_NORMAL;
    LogFont.lfCharSet        = DEFAULT_CHARSET;
    LogFont.lfQuality        = DEFAULT_QUALITY;
    LogFont.lfPitchAndFamily = FIXED_PITCH;
    LogFont.lfHeight         = -12;
    StringCchCopy(LogFont.lfFaceName, _countof(LogFont.lfFaceName), _T("Courier New"));
    pData->hFont = CreateFontIndirect(&LogFont);

    // If the font couldn't be created, create default one
    if(pData->hFont == NULL)
    {
        LogFont.lfHeight = -15;
        StringCchCopy(LogFont.lfFaceName, _countof(LogFont.lfFaceName), _T("Courier"));
        pData->hFont = CreateFontIndirect(&LogFont);

        // If even that failed, get the default fixed width font
        if(pData->hFont == NULL)
        {
            pData->hFont = (HFONT)GetStockObject(ANSI_FIXED_FONT);
        }
    }

    // Apply the font to the window
    SendMessage(pData->hWnd, WM_SETFONT, (WPARAM)pData->hFont, 0);
}

// Recalculate the view based on new font
static void QueryFontDimensions(TEditorData * pData)
{
    TEXTMETRIC TextMetrics;
    HFONT hOldFont;
    HDC hdc;

    // Get the height of one line
    hdc = GetDC(pData->hWnd);
    if(hdc != NULL)
    {
        hOldFont = (HFONT)SelectObject(hdc, pData->hFont);
        GetTextMetrics(hdc, &TextMetrics);

        // Rememember the height of one line
        pData->nAveCharWidth = TextMetrics.tmAveCharWidth;
        pData->nCharHeight = TextMetrics.tmHeight;
        pData->nTabSize = pData->nAveCharWidth * 4;
        assert(pData->nCharHeight != 0);
        
        // Remember if we are using variable pich font.
        // Note that the TMPF_FIXED_PITCH bit is actually the opposite of what its meaning says
        pData->bFixedFont = (TextMetrics.tmPitchAndFamily & TMPF_FIXED_PITCH) ? false : true;

        // Select the old font and 
        SelectObject(hdc, hOldFont);
        ReleaseDC(pData->hWnd, hdc);
    }
}

static void RecalculateView(TEditorData * pData)
{
    SCROLLINFO si;
    DWORD dwOldStyles;
    DWORD dwNewStyles;
    DWORD dwAddStyles;
    RECT rect;
    size_t cbEditorData;

    // The data must already have been created
    assert(pData != NULL);

    // Update the client size
    GetClientRect(pData->hWnd, &rect);
    pData->nHeight = rect.bottom;
    pData->nWidth = rect.right;
    pData->nLines = 0;

    // Update the total number of lines
    cbEditorData = (size_t)(pData->pbEditorDataEnd - pData->pbEditorDataBegin);
    if(cbEditorData > 0) 
        pData->nLines = ((cbEditorData - 1) / pData->cbBytesPerLine) + 1;

    // Update the number of lines, based on new size
    pData->nFullVisibleLines = (pData->nHeight / pData->nCharHeight);
    pData->nVisibleLines = ((pData->nHeight - 1) / pData->nCharHeight) + 1;

    // Now check if we need to show or remove vertical scroll bar
    dwAddStyles = ((pData->dwStyles & DES_VSCROLL) && (pData->nLines > (size_t)pData->nFullVisibleLines)) ? WS_VSCROLL : 0;
    dwOldStyles = (DWORD)GetWindowLongPtr(pData->hWnd, GWL_STYLE);
    dwNewStyles = (dwOldStyles & ~WS_VSCROLL) | dwAddStyles;

    // If the styles changed, apply them
    if(dwNewStyles != dwOldStyles)
    {
        SetWindowLongPtr(pData->hWnd, GWL_STYLE, dwNewStyles);
        SetWindowPos(pData->hWnd, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    }

    // Do we have vertical scrollbar ?
    if(dwNewStyles & WS_VSCROLL)
    {
        // Update scroll bar. Note that this also calls WM_SIZE,
        // which in turn calls this function.
        ZeroMemory(&si, sizeof(SCROLLINFO));
        si.cbSize = sizeof(SCROLLINFO);
        si.fMask  = SIF_RANGE | SIF_PAGE | SIF_POS;
        si.nPos   = (int)pData->nTopIndex;
        si.nPage  = (pData->nFullVisibleLines > 1) ? (pData->nFullVisibleLines - 1) : 1;
        si.nMax   = (int)((pData->nLines > 1) ? (pData->nLines - 1) : 1);
        SetScrollInfo(pData->hWnd, SB_VERT, &si, FALSE);
    }
}

static void SetBytesPerLine(TEditorData * pData, int cbBytesPerLine)
{
    // Don't accept zero number of bytes per line
    if(cbBytesPerLine <= 0)
        cbBytesPerLine = 0x10;

    // Always initialize the size of pointer
    pData->nPointerSize  = (pData->dwStyles & DES_ADDRESS64) ? sizeof(ULONGLONG) : sizeof(void *);
    pData->nAddressWidth = (pData->nPointerSize == 8) ? 17 : 8;

    // If the bytes per line is being changed
    if(cbBytesPerLine != pData->cbBytesPerLine)
    {
        // Calculate the sizes
        pData->nBeginHexaValues = pData->nAddressWidth + DATAEDIT_SPACES_BEFORE_HEXA;
        pData->nEndHexaValues   = pData->nBeginHexaValues + (cbBytesPerLine * 3) - 1;
        pData->nBeginTextValues = pData->nEndHexaValues + DATAEDIT_SPACES_BEFORE_TEXT;
        pData->nEndTextValues   = pData->nBeginTextValues + cbBytesPerLine;

        // Remember the number of bytes per line
        pData->cbBytesPerLine = cbBytesPerLine;

        // Reallocate the line buffer
        if(pData->szLineBuffer != NULL)
            HeapFree(GetProcessHeap(), 0, pData->szLineBuffer);
        pData->szLineBuffer = (LPTSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (pData->nEndTextValues + 1) * sizeof(TCHAR));
    }

    // Force the view to be recalculated
    RecalculateView(pData);
}

// Calculates the X and Y coordinates of the caret
// - Does NOT set the caret position
// - Does NOT redraw the window
// - Returns TRUE if the caret's position actually changed
static bool RecalcCaretXY(TEditorData * pData, bool * bNeedRedraw)
{
    HFONT hOldFont;
    DWORD TextSize = 0;
    HDC hdc;
    int nSaveCaretX = pData->nCaretX;
    int nSaveCaretY = pData->nCaretY;

    // Calculate the Y-position of the caret
    pData->nCaretY = 0;
    if(pData->nLines > 0 && pData->nCaretLine > pData->nTopIndex)
        pData->nCaretY = ((int)(pData->nCaretLine - pData->nTopIndex) * pData->nCharHeight);
    
    // Calculate the X-position of the caret
    pData->nCaretX = 0;
    if(pData->nLines > 0 && pData->nCaretCol > 0)
    {
        hdc = GetDC(pData->hWnd);
        if(hdc != NULL)
        {
            // Retrieve the n-th line
            FormatOneLine(pData, pData->nCaretLine);
            
            // Calculate the width of the text from the beginning up to the char at the caret pos
            hOldFont = (HFONT)SelectObject(hdc, pData->hFont);
            TextSize = GetTabbedTextExtent(hdc, pData->szLineBuffer, pData->nCaretCol, 1, &pData->nTabSize);
            SelectObject(hdc, hOldFont);
            ReleaseDC(pData->hWnd, hdc);
        }
        
        // Increment the cursor x-pos by the char position
        pData->nCaretX += LOWORD(TextSize);
    }

    // If the X position od the caret got out of the screen, we have to move the org
    if(pData->nCaretX > (pData->nLeftOrg + pData->nWidth))
    {
        pData->nLeftOrg = pData->nCaretX - (pData->nWidth - 10);
        *bNeedRedraw = true;
    }

    // If the caret went out of the view
    if(pData->nCaretX < pData->nLeftOrg)
    {
        pData->nLeftOrg = pData->nCaretX;
        *bNeedRedraw = true;
    }

    // Add the indent constant
    pData->nCaretX = (pData->nCaretX - pData->nLeftOrg) + DATAEDIT_TEXT_INDENT;

    // Return whether the caret's position has been changed or not
    return (bool)(pData->nCaretX != nSaveCaretX || pData->nCaretY != nSaveCaretY);
}

//
// Recalculates the mouse position to caret line and column
//

static void MousePosToCaretPos(TEditorData * pData,
    int nMouseX,
    int nMouseY,
    size_t * piMouseLine,
    int * piMouseCol)
{
    LPTSTR szLineText;
    HFONT hOldFont;
    DWORD TextSize;
    size_t nLineLength = 0;
    size_t nCharIndex1;
    size_t nCharIndex2;
    size_t nCharHalfX;
    HDC hdc;
    size_t nCaretLine;
    int nNextCharTreshold = (pData->nAveCharWidth / 2);
    int nCaretCol;
    int nRealWidth;

    // Adjust the text indent value
    if(nMouseX < DATAEDIT_TEXT_INDENT)
        nMouseX = DATAEDIT_TEXT_INDENT;
    nMouseX = nMouseX + pData->nLeftOrg - DATAEDIT_TEXT_INDENT;

    // Calculate Y character position
    if(nMouseY < 0)
        nCaretLine = pData->nTopIndex - (-nMouseY / pData->nCharHeight) - 1;
    else
        nCaretLine = pData->nTopIndex + (nMouseY / pData->nCharHeight);
    
    // By default, use average char width to calculate cursor X coordinate
    nCaretCol = (nMouseX / pData->nAveCharWidth);

    // Get line text where the caret is
    if(nCaretLine < pData->nLines)
    {
        // Get the text of the line
        nLineLength = FormatOneLine(pData, nCaretLine);
        if(nLineLength != 0)
        {
            if(pData->bFixedFont == false)
            {
                // Set the font into the HDC of the window
                hdc = GetDC(pData->hWnd);
                hOldFont = (HFONT)SelectObject(hdc, pData->hFont);

                // Initialize the search range
                nCharIndex1 = 0;
                nCharIndex2 = nLineLength + 1;
                szLineText = pData->szLineBuffer;

                // Perform binary search
                while(nCharIndex1 < (nCharIndex2 - 1))
                {
                    // Get character in half of the current string range
                    nCharHalfX = nCharIndex1 + max((nCharIndex2 - nCharIndex1) / 2, 1);

                    // Get size of it
                    TextSize = GetTabbedTextExtent(hdc, szLineText, (int)nCharHalfX, 1, &pData->nTabSize);
                    nRealWidth = LOWORD(TextSize) - nNextCharTreshold;

                    // Choose one of the halves
                    if(nRealWidth < nMouseX)
                        nCharIndex1 = nCharHalfX;
                    else
                        nCharIndex2 = nCharHalfX;
                }

                // Get the column 
                nCaretCol = (int)nCharIndex1;

                // Release the HDC of the window
                SelectObject(hdc, hOldFont);
                ReleaseDC(pData->hWnd, hdc);
            }
            else
            {
                // On a fixed-pitch font, it's simple ... 
                nCaretCol = (nMouseX + nNextCharTreshold) / pData->nAveCharWidth;
                if(nCaretCol > (int)(nLineLength + 1))
                    nCaretCol = (int)(nLineLength + 1);
            }
        }
    }

    *piMouseLine = nCaretLine;
    *piMouseCol = nCaretCol;
}

//-----------------------------------------------------------------------------
// Caret movement functions

inline bool HasSelection(TEditorData * pData)
{
    return (bool)(pData->nStartSelLine != pData->nEndSelLine || pData->nStartSelCol != pData->nEndSelCol);
}

inline bool IsReversedSelection(TEditorData * pData)
{
    return ((pData->nEndSelLine < pData->nStartSelLine) || (pData->nStartSelLine == pData->nEndSelLine && pData->nEndSelCol < pData->nStartSelCol));
}

// This method sets the current selection.
// - Does NOT change position of the cursor
// - Does NOT redraw the view
static bool SetSelection(
    TEditorData * pData,
    size_t nStartSelLine,
    int nStartSelCol,
    size_t nEndSelLine,
    int nEndSelCol)
{
    bool bSelectionChanged = false;

    // Only do selection if there are some lines
    if(pData->nLines == 0)
    {
        nStartSelLine = 0;
        nStartSelCol = 0;
        nEndSelLine = 0;
        nEndSelCol = 0;
    }

    // Determine if the selection has actually changed
    if(nStartSelLine != pData->nStartSelLine || nStartSelCol != pData->nStartSelCol)
        bSelectionChanged = true;
    if(nEndSelLine != pData->nEndSelLine || nEndSelCol != pData->nEndSelCol)
        bSelectionChanged = true;

    // Set the selection to the lines
    pData->nStartSelLine = nStartSelLine;
    pData->nStartSelCol = nStartSelCol;
    pData->nEndSelLine = nEndSelLine;
    pData->nEndSelCol = nEndSelCol;
    return bSelectionChanged;
}

// Moves the view and the caret
// Returns true if the entire view needs to be redrawn.
static void MoveTopIndexAndCaretTo(
    TEditorData * pData,
    size_t nNewTopIndex,
    size_t nNewCaretLine,
    int nNewCaretCol,
    TSelectMode SelectionMode)
{
    SCROLLINFO si;
    size_t nNewStartSelLine;
    size_t nMaxTopIndex;
    bool bNeedRedraw = false;
    int nNewStartSelCol;
    int nPageSize;

    // We can not do anything if there are no lines
    if(pData->nLines != 0)
    {
        // The page size is the number of fully visible lines
        // If less than two lines are fully visible, the page size is one line
        nPageSize = (pData->nFullVisibleLines >= 2) ? pData->nFullVisibleLines : 1;

        // Check for moving the top index out of bounds
        nMaxTopIndex = pData->nLines - nPageSize;
        nNewTopIndex = (nNewTopIndex > nMaxTopIndex) ? nMaxTopIndex : nNewTopIndex;

        // Check if we are actually changing the top index
        if(nNewTopIndex != pData->nTopIndex)
        {
            pData->nTopIndex = nNewTopIndex;
            bNeedRedraw = true;
        }

        // Check for moving the caret line out of bounds
        nNewCaretLine = (nNewCaretLine > (pData->nLines - 1)) ? (pData->nLines - 1) : nNewCaretLine;

        // Check for moving the caret column out of bounds
        nNewCaretCol = (nNewCaretCol < 0) ? 0 : nNewCaretCol;
        nNewCaretCol = (nNewCaretCol > (int)pData->nEndTextValues) ? (int)pData->nEndTextValues : nNewCaretCol;

        // Set the new caret position
        pData->nCaretLine = nNewCaretLine;
        pData->nCaretCol = nNewCaretCol;

        // Update the selection
        nNewStartSelLine = (SelectionMode == SmStartSelection) ? nNewCaretLine : pData->nStartSelLine;
        nNewStartSelCol = (SelectionMode == SmStartSelection) ? nNewCaretCol : pData->nStartSelCol;
        if(SetSelection(pData, nNewStartSelLine, nNewStartSelCol, nNewCaretLine, nNewCaretCol))
            bNeedRedraw = true;

        // If we need to redraw the view, do it
        if(bNeedRedraw)
        {
            // Redraw the view
            InvalidateRect(pData->hWnd, NULL, FALSE);

            // Do we have vertical scrollbar ?
            if(pData->dwStyles & DES_VSCROLL)
            {
                ZeroMemory(&si, sizeof(SCROLLINFO));
                si.cbSize = sizeof(SCROLLINFO);
                si.fMask  = SIF_PAGE | SIF_POS;
                si.nPos   = (int)pData->nTopIndex;
                si.nPage  = nPageSize;
                SetScrollInfo(pData->hWnd, SB_VERT, &si, TRUE);
            }
        }

        // Recalculate the caret's X and Y position and move the caret.
        // Move the caret position, if it changed
        if(pData->bHasCaret && RecalcCaretXY(pData, &bNeedRedraw))
            SetCaretPos(pData->nCaretX, pData->nCaretY);
    }
}

// Changes the top index, keeps the caret position
static void MoveTopIndexTo(TEditorData * pData, size_t nNewTopIndex)
{
    MoveTopIndexAndCaretTo(pData, nNewTopIndex, pData->nCaretLine, pData->nCaretCol, SmContinueSelection);
}

// Moves a caret to new position. If the caret moves out of the current view,
// the view is scrolled to ensure that the caret is visible
static void MoveCaret_ScrollView(
    TEditorData * pData,
    size_t nNewCaretLine,
    int nNewCaretCol,
    TSelectMode SelectionMode)
{
    size_t nNewTopIndex = pData->nTopIndex;
    int nPageSize = (pData->nFullVisibleLines >= 2) ? pData->nFullVisibleLines : 1;

    // If the caret goes before the top index, move the top index as well
    if(nNewCaretLine < nNewTopIndex)
        nNewTopIndex = nNewCaretLine;

    // If the new caret line is below the last visible line, move top index down
    if((nNewTopIndex + nPageSize - 1) < nNewCaretLine && nNewCaretLine <= pData->nLines)
        nNewTopIndex = (nNewCaretLine - nPageSize + 1);

    MoveTopIndexAndCaretTo(pData, nNewTopIndex, nNewCaretLine, nNewCaretCol, SelectionMode);
}

//-----------------------------------------------------------------------------
// WM_ message handlers

static void OnCreate(HWND hWnd, LPCREATESTRUCT pCreateParams)
{
    TEditorData * pData = new TEditorData;

    // Pre-init the editor data
    ZeroMemory(pData, sizeof(TEditorData));
    pData->hWndParent = pCreateParams->hwndParent;
    pData->dwStyles = pCreateParams->style;
    pData->hWnd  = hWnd;
    pData->dwId  = (DWORD)(DWORD_PTR)pCreateParams->hMenu;

    // Remove the VS_VISIBLE style, as we want it to show the real state
    pData->dwStyles &= ~WS_VISIBLE;

    // Remember the editor data
    SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pData);

    // We need to recalculate view for new font
    CreateTextFont(pData);
    QueryFontDimensions(pData);

    // Set the default number of bytes per line
    SetBytesPerLine(pData, 0x10);
}

static void OnShowWindow(HWND hWnd, WPARAM wParam)
{
    TEditorData * pData = GetEditorData(hWnd);

    pData->dwStyles = (pData->dwStyles & ~WS_VISIBLE) | (wParam ? WS_VISIBLE : 0);
}

static void OnSize(HWND hWnd, LPARAM lParam)
{
    TEditorData * pData = GetEditorData(hWnd);

    pData->nHeight = GET_Y_LPARAM(lParam);
    pData->nWidth = GET_X_LPARAM(lParam);
}

static void OnSetFocus(HWND hWnd)
{
    TEditorData * pData = GetEditorData(hWnd);

    // Create the text caret
    if(CreateCaret(hWnd, NULL, 1, pData->nCharHeight))
    {
        // Force recalculating the caret position, otherwise
        // the position remains unchanged from previously focused window
        SetCaretPos(pData->nCaretX, pData->nCaretY);
        ShowCaret(hWnd);
        pData->bHasCaret = true;
    }

    // Notify the parent that we received focus
    SendMessage(pData->hWndParent, WM_COMMAND, MAKEWPARAM(pData->dwId, EN_SETFOCUS), (LPARAM)pData->hWnd);
}

static void OnKillFocus(HWND hWnd)
{
    TEditorData * pData = GetEditorData(hWnd);

    // If we have capture active, we have to release it
    if(pData->bHasCapture)
    {
        ReleaseCapture();
        pData->bHasCapture = false;
    }

    // If we have caret, we have to get rid of it
    if(pData->bHasCaret)
    {
        HideCaret(hWnd);
        DestroyCaret();
        pData->bHasCaret = false;
    }
}

static LRESULT OnKeyDown(HWND hWnd, WPARAM wParam, LPARAM /* lParam */)
{
    TEditorData * pData = GetEditorData(hWnd);
    TSelectMode SelectionMode;
    UINT uKeyCode = (UINT)wParam;
    size_t nNewCaretLine;
    size_t nNewTopIndex;
    int nNewCaretCol = pData->nCaretCol;
    bool bIsShiftPressed = false;
    bool bIsCtrlPressed = false;

    // Do nothing if there are no lines
    if(pData->nLines == 0)
        return TRUE;

    // Get the state of the Shift key
    if(GetAsyncKeyState(VK_SHIFT) & 0x8000)
        bIsShiftPressed = true;
    if(GetAsyncKeyState(VK_CONTROL) & 0x8000)
        bIsCtrlPressed = true;

    // Determine the selection mode
    SelectionMode = bIsShiftPressed ? SmContinueSelection : SmStartSelection;

    // Perform key-specific action    
    switch(uKeyCode)
    {
        case VK_SHIFT:
        case VK_CONTROL:
        case VK_MENU:
            break;

        case VK_HOME:

            // Ctrl+Shift+Home: Moves the caret to the first char of the document with selection
            // Ctrl+Home: Moves the caret to the first char of the document
            // Shift+Home: Moves the caret to the first char with selection
            // Home: Moves the caret to the first char
            nNewTopIndex  = bIsCtrlPressed ? 0 : pData->nTopIndex;
            nNewCaretLine = bIsCtrlPressed ? 0 : pData->nCaretLine;
            MoveTopIndexAndCaretTo(pData, nNewTopIndex, nNewCaretLine, 0, SelectionMode);
            break;

        case VK_PRIOR:

            // Ctrl+Shift+PageUp: Moves the caret to the top line of the page with selection
            // Ctrl+PageUp: Moves the caret to the top line of the page
            // Shift+PageUp: Moves the caret one page up with selection
            // PageUp: Moves the top index one page up, keeps relative caret position
            nNewTopIndex = (pData->nTopIndex > (size_t)pData->nFullVisibleLines) ? (pData->nTopIndex - pData->nFullVisibleLines) : 0;
            nNewTopIndex = (bIsCtrlPressed == false) ? nNewTopIndex : pData->nTopIndex;
            nNewCaretLine = (pData->nCaretLine > (size_t)pData->nFullVisibleLines) ? (pData->nCaretLine - pData->nFullVisibleLines) : 0;
            nNewCaretLine = (bIsCtrlPressed == false) ? nNewCaretLine : pData->nTopIndex;
            MoveTopIndexAndCaretTo(pData, nNewTopIndex, nNewCaretLine, pData->nCaretCol, SelectionMode);
            break;

        case VK_UP:

            // Ctrl+Shift+ArrowUp: Nothing
            // Ctrl+ArrowUp: Moves the view up by one line, does not change selection or cursor pos
            // Shift+ArrowUp: Moves the caret one line up with selection
            // ArrowUp: Moves the caret one line up
            if(bIsCtrlPressed == false)
            {
                nNewCaretLine = (pData->nCaretLine > 0) ? (pData->nCaretLine - 1) : 0;
                MoveCaret_ScrollView(pData, nNewCaretLine, pData->nCaretCol, SelectionMode);
            }
            else if(bIsShiftPressed == false)
            {
                nNewTopIndex = (pData->nTopIndex > 0) ? (pData->nTopIndex - 1) : 0;
                MoveTopIndexAndCaretTo(pData, nNewTopIndex, pData->nCaretLine, pData->nCaretCol, SmContinueSelection);
            }
            break;

        case VK_LEFT:

            // Ctrl+Shift+ArrowLeft: Move one word left with selection
            // Ctrl+ArrowLeft: Move one word left
            // Shift+ArrowLeft: Moves the caret one line left with selection
            // ArrowLeft: Moves the caret one line left
            nNewCaretCol = bIsCtrlPressed ? FindPreviousWord(pData, pData->nCaretLine, pData->nCaretCol) : (pData->nCaretCol - 1);
            MoveCaret_ScrollView(pData, pData->nCaretLine, nNewCaretCol, SelectionMode);
            break;

        case VK_RIGHT:

            // Ctrl+Shift+ArrowRight: Move one word right with selection
            // Ctrl+ArrowRight: Move one word right
            // Shift+ArrowRight: Moves the caret one line right with selection
            // ArrowRight: Moves the caret one line right
            nNewCaretCol = bIsCtrlPressed ? FindNextWord(pData, pData->nCaretLine, pData->nCaretCol) : (pData->nCaretCol + 1);
            MoveCaret_ScrollView(pData, pData->nCaretLine, nNewCaretCol, SelectionMode);
            break;

        case VK_DOWN:

            // Ctrl+Shift+ArrowDown: Nothing
            // Ctrl+ArrowDown: Moves the view down by one line, does not change selection or cursor pos
            // Shift+ArrowDown: Moves the caret one line down with selection
            // ArrowDown: Moves the caret one line down
            if(bIsCtrlPressed == false)
            {
                MoveCaret_ScrollView(pData, pData->nCaretLine + 1, pData->nCaretCol, SelectionMode);
            }
            else if(bIsShiftPressed == false)
            {
                MoveTopIndexAndCaretTo(pData, pData->nTopIndex + 1, pData->nCaretLine, pData->nCaretCol, SmContinueSelection);
            }
            break;

        case VK_NEXT:

            // Ctrl+Shift+PageDown: Moves the caret to the bottom line of the page with selection
            // Ctrl+PageDown: Moves the caret to the bottom line of the page
            // Shift+PageDown: Moves the caret one page down with selection
            // PageDown: Moves the top index one page down, but caret remains 
            nNewTopIndex  = (bIsCtrlPressed == false) ? (pData->nTopIndex + pData->nFullVisibleLines) : pData->nTopIndex;
            nNewCaretLine = (bIsCtrlPressed == false) ? (pData->nCaretLine + pData->nFullVisibleLines) : (pData->nTopIndex + pData->nFullVisibleLines - 1);
            MoveTopIndexAndCaretTo(pData, nNewTopIndex, nNewCaretLine, pData->nCaretCol, SelectionMode);
            break;

        case VK_END:

            // Ctrl+Shift+End: Moves the caret to the last char of the document with selection
            // Ctrl+End: Moves the caret to the last char of the document
            // Shift+End: Moves the caret to the first char with selection
            // End: Moves the caret to the last char
            nNewTopIndex  = bIsCtrlPressed ? (pData->nLines - pData->nFullVisibleLines) : pData->nTopIndex;
            nNewCaretLine = bIsCtrlPressed ? pData->nLines : pData->nCaretLine;
            MoveTopIndexAndCaretTo(pData, nNewTopIndex, nNewCaretLine, DATAEDIT_END_OF_LINE, SelectionMode);
            break;

        case VK_INSERT:
            if(bIsCtrlPressed)
                SendMessage(hWnd, WM_COPY, 0, 0);
            else if(bIsShiftPressed)
                SendMessage(hWnd, WM_PASTE, 0, 0);
            return TRUE;

        case VK_DELETE:
            if(bIsShiftPressed)
            {
                SendMessage(hWnd, WM_CUT, 0, 0);
                return TRUE;
            }
            break;

        case 'C':
        case 'c':
            if(bIsCtrlPressed)
                SendMessage(hWnd, WM_COPY, 0, 0);
            break;

        case 'X':
        case 'x':
            if(bIsCtrlPressed)
            {
                SendMessage(hWnd, WM_CUT, 0, 0);
                return TRUE;
            }
            break;

        case 'V':
        case 'v':
            if(bIsCtrlPressed)
            {
                SendMessage(hWnd, WM_PASTE, 0, 0);
                return TRUE;
            }
            break;
    }

    return TRUE;
}

static LRESULT OnChar(HWND hWnd, WPARAM wParam, LPARAM /* lParam */)
{
    TEditorData * pData = GetEditorData(hWnd);
    BYTE ByteEntered;
    BYTE ByteAndMask;
    BYTE ByteOrMask;
    BYTE OneByte = (BYTE)wParam;
    size_t nLineOffset;
    size_t nNewCaretLine = pData->nCaretLine;
    int nNewCaretCol;
    int nByteIndex;
    int nRemainder;

    // Get the offset of the 0-th byte in the line
    nLineOffset = pData->nCaretLine * pData->cbBytesPerLine;

    // Is the cursor in the hexa part?
    if(pData->nBeginHexaValues <= pData->nCaretCol && pData->nCaretCol < pData->nEndHexaValues)
    {
        // Convert the key to a hexadecimal digit
        if('a' <= wParam && wParam <= 'z')
            wParam -= ('a' - 'A');
        if('A' <= wParam && wParam <= 'Z')
            wParam -= ('A' - '9' - 1);
        if(0x30 <= wParam && wParam < 0x40)
        {
            // Get the byte index and remainder
            nByteIndex = (pData->nCaretCol - pData->nBeginHexaValues) / 3;
            nRemainder = (pData->nCaretCol - pData->nBeginHexaValues) % 3;

            // Are we within the range of the data?
            if((pData->pbEditorDataBegin + nLineOffset + nByteIndex) < pData->pbEditorDataEnd)
            {
                // Only if we are in the first upper or lower half of the BYTE
                if(nRemainder == 0 || nRemainder == 1)
                {
                    // Read one byte from the mapped data
                    OneByte = GuardedReadByte(pData, nLineOffset + nByteIndex);

                    // Replace the given 4 bits
                    ByteEntered = (BYTE)(wParam - '0');
                    ByteAndMask = nRemainder ? 0xF0 : 0x0F;
                    ByteOrMask  = nRemainder ? ByteEntered : (ByteEntered << 0x04);
                    OneByte = (OneByte & ByteAndMask) | ByteOrMask;

                    // Write the byte back
                    GuardedWriteBuffer(pData, nLineOffset + nByteIndex, &OneByte, 1);
                }

                // Determine the next caret position
                nNewCaretCol = pData->nCaretCol + nRemainder + 1;
                if(nNewCaretCol >= pData->nEndHexaValues)
                {
                    nNewCaretCol = pData->nBeginHexaValues;
                    nNewCaretLine++;
                }

                // Move the caret
                MoveCaret_ScrollView(pData, nNewCaretLine, nNewCaretCol, SmStartSelection);
            }
        }

        return 0;
    }

    // Are we within the text data range?
    if(pData->nBeginTextValues <= pData->nCaretCol && pData->nCaretCol < pData->nEndTextValues)
    {
        // Get the byte index and remainder
        nByteIndex = (pData->nCaretCol - pData->nBeginTextValues);

        // Are we within the range of the data?
        if((pData->pbEditorDataBegin + nLineOffset + nByteIndex) < pData->pbEditorDataEnd)
        {
            // Write the entire byte
            GuardedWriteBuffer(pData, nLineOffset + nByteIndex, &OneByte, 1);

            // Determine the next caret position
            nNewCaretCol = pData->nCaretCol + 1;
            if(nNewCaretCol >= pData->nEndTextValues)
            {
                nNewCaretCol = pData->nBeginTextValues;
                nNewCaretLine++;
            }

            // Move the caret
            MoveCaret_ScrollView(pData, nNewCaretLine, nNewCaretCol, SmStartSelection);
        }
    }
    return TRUE;
}

static void OnPaste(HWND hWnd)
{
    TEditorData * pData = GetEditorData(hWnd);
    size_t nLineOffset = pData->nCaretLine * pData->cbBytesPerLine;
    size_t cchPasteText = 0;
    LPSTR szPasteText;
    int nByteIndex = -1;

    // Is the cursor before the hexa part?
    if(pData->nCaretCol < pData->nBeginHexaValues)
        nByteIndex = 0;

    // Is the cursor within the hexa part?
    else if(pData->nCaretCol < pData->nEndHexaValues)
        nByteIndex = (pData->nCaretCol - pData->nBeginHexaValues) / 3;

    // Is the cursor between the hexa part and the text part?
    else if(pData->nCaretCol < pData->nBeginTextValues)
        nByteIndex = pData->cbBytesPerLine;

    // Is the cursor in the text part?
    else if(pData->nCaretCol <= pData->nEndTextValues)
        nByteIndex = (pData->nCaretCol - pData->nBeginTextValues);

    // Otherwise, put it at after end of the current line
    else
        nByteIndex = pData->cbBytesPerLine;

    // Retrieve the text from the clipboard
    szPasteText = QueryClipboardText(hWnd, &cchPasteText);
    if(szPasteText != NULL)
    {
        DTE_PASTE_DATA Data;

        // Notify the parent about the exception
        Data.hdr.hwndFrom = pData->hWnd;
        Data.hdr.idFrom   = pData->dwId;
        Data.hdr.code     = DEN_PASTE;
        Data.szPasteText  = szPasteText;
        Data.PasteOffset  = nLineOffset + nByteIndex;
        Data.PasteLength  = cchPasteText;
        Data.bHandled     = FALSE;
        SendMessage(pData->hWndParent, WM_NOTIFY, pData->dwId, (LPARAM)&Data);

        // If the parent hasn't handled the message, we copy the data to the internal data
        // Note that the internal paste routine will never extend the data,
        // and will cut any data that would go beyond the end of the buffer
        if(Data.bHandled == FALSE)
        {
            PasteTextInternal(pData, Data.szPasteText, Data.PasteOffset, Data.PasteLength);
            InvalidateRect(hWnd, NULL, TRUE);
        }

        // Free the text buffer
        HeapFree(GetProcessHeap(), 0, szPasteText);
    }
}

static void OnLButtonDown(HWND hWnd, int nMouseX, int nMouseY)
{
    TEditorData * pData = GetEditorData(hWnd);
    size_t nCaretLine;
    int nCaretCol;

    if(pData->bHasCapture == false)
    {
        // Get focus, if we don't have it yet
        if(GetFocus() != hWnd)
            SetFocus(hWnd);

        // Start capture
        SetCapture(hWnd);
        pData->bHasCapture = true;

        // Recalculate the mouse position to character position and save it
        MousePosToCaretPos(pData, nMouseX, nMouseY, &nCaretLine, &nCaretCol);

        // Clear the current selection
        MoveCaret_ScrollView(pData, nCaretLine, nCaretCol, SmStartSelection);
    }
}

static void OnMouseMove(HWND hWnd, int nMouseX, int nMouseY)
{
    TEditorData * pData = GetEditorData(hWnd);
    size_t nCaretLine;
    int nCaretCol;

    if(pData->bHasCapture)
    {
        // Normalize mouse X position
        if(nMouseX < 0)
            nMouseX = 0;

        // Recalculate the mouse position to character position and save it
        MousePosToCaretPos(pData, nMouseX, nMouseY, &nCaretLine, &nCaretCol);

        // Set the caret position
        MoveCaret_ScrollView(pData, nCaretLine, nCaretCol, SmContinueSelection);
    }
}

static void OnMouseWheel(HWND hWnd, UINT uDistance)
{
    TEditorData * pData = GetEditorData(hWnd);
    size_t nNewTopIndex;

    // Do nothing if there is mouse capture or if there is more lines than the visible ones
    if(pData->bHasCapture || pData->nLines == 0)
        return;

    // Negative value means that the wheel has been moved down
    // Positive value means that the wheel has been moved up
    if((uDistance & 0x8000) == 0)
        nNewTopIndex = (pData->nTopIndex > 3) ? pData->nTopIndex - 3 : 0;
    else
        nNewTopIndex = pData->nTopIndex + 3;

    MoveTopIndexAndCaretTo(pData, nNewTopIndex, pData->nCaretLine, pData->nCaretCol, SmContinueSelection);
}

static void OnLButtonUp(HWND hWnd)
{
    TEditorData * pData = GetEditorData(hWnd);

    if(pData->bHasCapture)
    {
        ReleaseCapture();
        pData->bHasCapture = false;
    }
}

static void OnVertScroll(HWND hWnd, WPARAM wParam)
{
    TEditorData * pData = GetEditorData(hWnd);
    SCROLLINFO si;

    switch(LOWORD(wParam))
    {
        case SB_PAGEUP:
            MoveTopIndexTo(pData, pData->nTopIndex - (pData->nFullVisibleLines - 1));
            break;

        case SB_LINEUP:
            MoveTopIndexTo(pData, pData->nTopIndex - 1);
            break;

        case SB_THUMBTRACK:
            si.cbSize = sizeof(SCROLLINFO);
            si.fMask  = SIF_ALL;
            GetScrollInfo(hWnd, SB_VERT, &si);
            MoveTopIndexTo(pData, si.nTrackPos);
            break;

        case SB_LINEDOWN:
            MoveTopIndexTo(pData, pData->nTopIndex + 1);
            break;

        case SB_PAGEDOWN:
            MoveTopIndexTo(pData, pData->nTopIndex +  (pData->nFullVisibleLines - 1));
            break;
    }
}

static void OnPaint(HWND hWnd)
{
    TEditorData * pData = GetEditorData(hWnd);
    PAINTSTRUCT ps;
    HGDIOBJ hOldFont;
    RECT LineRect;
    RECT TempRect;
    UINT uOldAlign;
    HDC hPaintDC;
    size_t nStartSelLine = pData->nStartSelLine;
    size_t nEndSelLine = pData->nEndSelLine;
    size_t nLineIndex = nLineIndex = pData->nTopIndex;
    int nStartSelCol = pData->nStartSelCol;
    int nEndSelCol = pData->nEndSelCol;

    // Get start and end of selection in the proper order
    if(IsReversedSelection(pData))
    {
        nStartSelLine = pData->nEndSelLine;
        nStartSelCol = pData->nEndSelCol;
        nEndSelLine = pData->nStartSelLine;
        nEndSelCol = pData->nStartSelCol;
    }

    // Prepare rectagle for top line
    LineRect.left   = 0;
    LineRect.top    = 0;
    LineRect.right  = pData->nWidth;
    LineRect.bottom = pData->nCharHeight;

    // Start painting
    BeginPaint(hWnd, &ps);
    hPaintDC = ps.hdc;
    hOldFont = SelectObject(hPaintDC, pData->hFont);
    uOldAlign = SetTextAlign(hPaintDC, TA_LEFT | TA_TOP);

    // Draw all lines
    while(LineRect.top < pData->nHeight)
    {
        LPTSTR szLineText;
        LONG TextSize = 0;
        int nStartSelection = 0;
        int nEndSelection = 0;
        int nLengthToDraw;
        int nLineLength;
        int nStartDraw;
        int x, y;

        // Reset left position to left edge of the view
        LineRect.left = 0;

        // Is this line in the invalidated area?
        if(IntersectRect(&TempRect, &LineRect, &ps.rcPaint))
        {
            // If the line is within range
            if(nLineIndex < pData->nLines)
            {
                nLineLength = FormatOneLine(pData, nLineIndex);
                szLineText = pData->szLineBuffer;
                nStartDraw = 0;

                // Determine selection
                if(nLineIndex == nStartSelLine)
                    nStartSelection = nStartSelCol;
                if(nLineIndex == nEndSelLine)
                    nEndSelection = nEndSelCol;
                if(nStartSelLine <= nLineIndex && nLineIndex < nEndSelLine)
                    nEndSelection = nLineLength;

                // Fill the mini-rect between left edge of the view and left edge of the text
                if(pData->nLeftOrg < DATAEDIT_TEXT_INDENT)
                {
                    LineRect.right = DATAEDIT_TEXT_INDENT;
                    SetBkColor(hPaintDC, DATAEDIT_COLOR_NORMAL_BG);
                    ExtTextOut(hPaintDC, 0, 0, ETO_OPAQUE, &LineRect, NULL, 0, NULL);
                    LineRect.right = pData->nWidth;
                }

                // Calculate the text position
                x = DATAEDIT_TEXT_INDENT - pData->nLeftOrg;
                y = LineRect.top;

                // Draw the plain text before the selection
                if(nStartSelection > nStartDraw)
                {
                    SetTextColor(hPaintDC, DATAEDIT_COLOR_NORMAL_FG);
                    SetBkColor(hPaintDC, DATAEDIT_COLOR_NORMAL_BG);
        
                    nLengthToDraw = (nStartSelection - nStartDraw);
                    TextSize = TabbedTextOut(hPaintDC, x, y, szLineText, nLengthToDraw, 1, &pData->nTabSize, 0);
                    nStartDraw += nLengthToDraw;
                    szLineText += nLengthToDraw;
                    x += LOWORD(TextSize);
                }

                // Draw the selected text
                if(nEndSelection > nStartDraw)
                {
                    SetTextColor(hPaintDC, DATAEDIT_COLOR_SELECTION_FG);
                    SetBkColor(hPaintDC, DATAEDIT_COLOR_SELECTION_BG);

                    nLengthToDraw = (nEndSelection - nStartDraw);
                    TextSize = TabbedTextOut(hPaintDC, x, y, szLineText, nLengthToDraw, 1, &pData->nTabSize, 0);
                    nStartDraw += nLengthToDraw;
                    szLineText += nLengthToDraw;
                    x += LOWORD(TextSize);
                }

                // Draw the end
                if(nLineLength > nStartDraw)
                {
                    SetTextColor(hPaintDC, DATAEDIT_COLOR_NORMAL_FG);
                    SetBkColor(hPaintDC, DATAEDIT_COLOR_NORMAL_BG);

                    nLengthToDraw = (int)(nLineLength - nStartDraw);
                    TextSize = TabbedTextOut(hPaintDC, x, y, szLineText, nLengthToDraw, 1, &pData->nTabSize, 0);
                    x += LOWORD(TextSize);
                }

                // Finish the line by filling extra space behind the text
                if(LineRect.left < LineRect.right)
                {
                    // Get the current pen position
                    LineRect.left = x;
                    LineRect.right = pData->nWidth;
                    SetBkColor(hPaintDC, DATAEDIT_COLOR_NORMAL_BG);
                    ExtTextOut(hPaintDC, 0, 0, ETO_OPAQUE, &LineRect, NULL, 0, NULL);
                }
            }
            else    
            {
                // Paint the entire line as empty filled rectangle
                SetBkColor(hPaintDC, DATAEDIT_COLOR_NORMAL_BG);
                ExtTextOut(hPaintDC, 0, 0, ETO_OPAQUE, &LineRect, NULL, 0, NULL);
            }
        }

        // Move the RECT to one line down
        LineRect.top = LineRect.bottom;
        LineRect.bottom = LineRect.top + pData->nCharHeight;
        nLineIndex++;
    }

    // Finish painting
    SetTextAlign(hPaintDC, uOldAlign);
    SelectObject(hPaintDC, hOldFont);
    EndPaint(hWnd, &ps);
}

static void OnDestroy(HWND hWnd)
{
    TEditorData * pData = GetEditorData(hWnd);

    if(pData != NULL)
    {
        // Delete the line buffer
        if(pData->szLineBuffer != NULL)
            HeapFree(GetProcessHeap(), 0, pData->szLineBuffer);
        pData->szLineBuffer = NULL;

        // Delete the data itself
        delete pData;
    }
}

//-----------------------------------------------------------------------------
// Window procedure

static LRESULT WINAPI WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
        case WM_CREATE:
            OnCreate(hWnd, (LPCREATESTRUCT)lParam);
            break;
                                         
        case WM_SETFONT:
            return 0;

        case WM_SHOWWINDOW:
            OnShowWindow(hWnd, wParam);
            break;

        case WM_SIZE:
            OnSize(hWnd, lParam);
            break;

        case WM_SETTEXT:
            return TRUE;

        case WM_SETFOCUS:
            OnSetFocus(hWnd);
            break;

        case WM_KILLFOCUS:
            OnKillFocus(hWnd);
            break;

        case WM_GETTEXTLENGTH:
            return 0;

        case WM_GETTEXT:
            return 0;

        case WM_KEYDOWN:
            if(OnKeyDown(hWnd, wParam, lParam))
                return 0;
            break;

        case WM_CHAR:
            OnChar(hWnd, wParam, lParam);
            return 1;

        case WM_PASTE:
            OnPaste(hWnd);
            return 1;

        case WM_LBUTTONDOWN:
        case WM_RBUTTONDOWN:
            OnLButtonDown(hWnd, (signed short)LOWORD(lParam), (signed short)HIWORD(lParam));
            break;

        case WM_MOUSEMOVE:
            OnMouseMove(hWnd, (signed short)LOWORD(lParam), (signed short)HIWORD(lParam));
            break;

        case WM_MOUSEWHEEL:
            OnMouseWheel(hWnd, HIWORD(wParam));
            return 0;

        case WM_LBUTTONUP:
        case WM_RBUTTONUP:
            OnLButtonUp(hWnd);
            break;

        case WM_VSCROLL:
            OnVertScroll(hWnd, wParam);
            return 0;

        case WM_PAINT:
            OnPaint(hWnd);
            break;

        case WM_ERASEBKGND:
            return 1;       // All drawing is done on the OnPaint

        case WM_GETDLGCODE:
            return (DLGC_WANTARROWS | DLGC_WANTCHARS);

        case WM_DESTROY:
            OnDestroy(hWnd);
            break;
    }

    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

//-----------------------------------------------------------------------------
// Public functions

int RegisterDataEditor(HINSTANCE hInst)
{
    WNDCLASSEX wc;
    int nError = ERROR_SUCCESS;

    // Register the class
    wc.cbSize = sizeof(WNDCLASSEX);
    if(!GetClassInfoEx(hInst, szDataEditClassName, &wc))
    {
        // Register the class
        ZeroMemory(&wc, sizeof(WNDCLASSEX));
        wc.cbSize        = sizeof(WNDCLASSEX);
        wc.style         = CS_DBLCLKS;
        wc.lpfnWndProc   = WindowProc;
        wc.hInstance     = hInst;
        wc.hCursor       = LoadCursor(NULL, IDC_IBEAM);
        wc.hIcon         = NULL;
        wc.hbrBackground = NULL;
        wc.lpszClassName = szDataEditClassName;
        if(!RegisterClassEx(&wc))
            nError = GetLastError();
    }
    return nError;
}

int DataEditor_SetBytesPerLine(HWND hWndDataEdit, int cbBytesPerLine)
{
    TEditorData * pData = GetEditorData(hWndDataEdit);

    // Verify the validity of the window and data
    if(pData == NULL)
        return ERROR_INVALID_PARAMETER;

    // Apply the byte count
    SetBytesPerLine(pData, cbBytesPerLine);
    return ERROR_SUCCESS;
}

// Applies the new data
int DataEditor_SetData(HWND hWndDataEdit, ULONGLONG BaseAddress, LPVOID pvData, SIZE_T cbData)
{
    TEditorData * pData = GetEditorData(hWndDataEdit);

    // Verify the validity of the window and data
    if(pData == NULL)
        return ERROR_INVALID_PARAMETER;

    // Apply the new data region
    pData->BaseAddress = BaseAddress;
    pData->pbEditorDataBegin = (LPBYTE)pvData;
    pData->pbEditorDataEnd = (LPBYTE)pvData + cbData;

    // Move the caret to the position 0, 0
    pData->nStartSelLine = pData->nEndSelLine = 0;
    pData->nStartSelCol = pData->nEndSelCol = 0;

    // Clear information about an exception
    pData->bWriteException = false;
    pData->bReadException = false;

    // Recalculate the view
    RecalculateView(pData);
    InvalidateRect(hWndDataEdit, NULL, TRUE);
    return ERROR_SUCCESS;
}
