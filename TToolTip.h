/*****************************************************************************/
/* TToolTip.h                             Copyright (c) Ladislav Zezula 2014 */
/*---------------------------------------------------------------------------*/
/* Interface to class TTooltip, used as helper for displaying flags          */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 16.03.14  1.00  Lad  The first version of TToolTip.h                      */
/*****************************************************************************/

#ifndef __TTOOLTIP_H__
#define __TTOOLTIP_H__

//-----------------------------------------------------------------------------
// Definition of the TTooltip class

class TToolTip
{
    public:

    TToolTip();
    ~TToolTip();

    // Initializes the tooltip. Call once per application
    BOOL Initialize(HINSTANCE hInst, HWND hWndParent);
    void Destroy();
    
    // Adds a flag-based tooltip for the specified child window
    BOOL AddToolTip(HWND hDlg, UINT nIDCtrl, TFlagInfo * pFlags);
    BOOL AddToolTip(HWND hDlg, UINT nIDCtrl, UINT nIDTip);
    
    // Handles all messages    
    LRESULT HandleMessages(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL * pbHandled);

    protected:

    BOOL AddToolTipInternal(HWND hDlg, UINT nIDCtrl, LPCTSTR szTip, TFlagInfo * pFlags);
    void OnGetTooltipText(LPNMTTDISPINFO pTTDispInfo);

    LPTSTR szToolTipText;       // Text for preparing the buffer
    size_t cchTooltipText;      // Length of the buffer 
    HWND hWndToolTip;           // Handle to the tooltip window
};

#endif // __TTOOLTIP_H__
