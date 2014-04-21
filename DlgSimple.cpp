/*****************************************************************************/
/* DlgSimple.cpp                          Copyright (c) Ladislav Zezula 2014 */
/*---------------------------------------------------------------------------*/
/* Description: Common module for a few simple dialogs                       */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 18.03.14  1.00  Lad  The first version of DlgSimple.cpp                   */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Message handler

static INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM /* lParam */)
{
    UINT nIDCtrl;
    UINT nIDNotify;

    // Dialog initialization
    switch(uMsg)
    {
        case WM_INITDIALOG:
            return TRUE;

        case WM_COMMAND:
            nIDNotify = HIWORD(wParam);
            nIDCtrl = LOWORD(wParam);

            if(nIDNotify == BN_CLICKED)
                EndDialog(hDlg, nIDCtrl);
            break;
    }

    return FALSE;
}

//-----------------------------------------------------------------------------
// Dialog functions

INT_PTR ObjectIDActionDialog(HWND hParent)
{
    return DialogBox(g_hInst, MAKEINTRESOURCE(IDD_OBJECT_ID_MORE), hParent, DialogProc);
}

INT_PTR DirectoryActionDialog(HWND hParent)
{
    return DialogBox(g_hInst, MAKEINTRESOURCE(IDD_DIRECTORY_ACTION), hParent, DialogProc);
}

INT_PTR DataPasteOperationDialog(HWND hParent)
{
    return DialogBox(g_hInst, MAKEINTRESOURCE(IDD_DATA_PASTE_OPERATION), hParent, DialogProc);
}

INT_PTR SectionEditorDialog(HWND hParent)
{
    return DialogBox(g_hInst, MAKEINTRESOURCE(IDD_DATA_PASTE_OPERATION), hParent, DialogProc);
}
