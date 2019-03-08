/*****************************************************************************/
/* TDataEditor.h                          Copyright (c) Ladislav Zezula 2014 */
/*---------------------------------------------------------------------------*/
/* Description :                                                             */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 18.03.14  1.00  Lad  The first version of TDataEditor.h                   */
/*****************************************************************************/

#ifndef __TDATAEDITOR_H__
#define __TDATAEDITOR_H__

//-----------------------------------------------------------------------------
// Defines

#define DATAEDIT_COLOR_NORMAL_FG       RGB(0,    0,    0)
#define DATAEDIT_COLOR_NORMAL_BG       RGB(255, 255, 255)

#define DATAEDIT_COLOR_SELECTION_FG    RGB(255, 255, 255)
#define DATAEDIT_COLOR_SELECTION_BG    RGB(49,  106, 197)

#define DATAEDIT_TEXT_INDENT           2            // Number of pixels before the first character

// Data Editor styles
#define DES_HSCROLL                    0x00000010
#define DES_VSCROLL                    0x00000020

enum TPointerFormat
{
    PtrPlatformSpecific = 0,
    PtrPointer32Bit,
    PtrPointer64Bit
};

//-----------------------------------------------------------------------------
// Messages for data editor (via WM_NOTIFY)

#define DEN_EXCEPTION (WM_USER + 0x1000)

typedef struct _DTE_EXCEPTION_DATA
{
    NMHDR hdr;                                      // Common header
    PVOID ExceptionAddress;                         // Address where the exception happened
    ULONG ExceptionCode;
    BOOL  WriteOperation;
} DTE_EXCEPTION_DATA, *PDTE_EXCEPTION_DATA;

#define DEN_PASTE            (WM_USER + 0x1001)

typedef struct _DTE_PASTE_DATA
{
    NMHDR hdr;                                      // Common header
    LPCSTR szPasteText;                             // Pointer to the text to be pasted
    SIZE_T PasteOffset;                             // Offset in the data corresponding to the current cursor position
    SIZE_T PasteLength;                             // Length of the text being pasted
    BOOL bHandled;                                  // If someone sets this to TRUE, then data editor will not process it fuhrter

} DTE_PASTE_DATA, *PDTE_PASTE_DATA;

//-----------------------------------------------------------------------------
// Class name of the data editor

extern const LPTSTR szDataEditClassName;

//-----------------------------------------------------------------------------
// Data Editor interface

// Registers the data editor
int RegisterDataEditor(HINSTANCE hInst);

// Applies the new data
int DataEditor_SetData(HWND hWndDataEdit, ULONGLONG BaseAddress, LPVOID pvData, SIZE_T cbData);

// Sets the pointer format
int DataEditor_SetDataFormat(HWND hWndDataEdit, TPointerFormat PtrFormat, SIZE_T cbBytesPerLine);

#endif // __TDATAEDITOR_H__
