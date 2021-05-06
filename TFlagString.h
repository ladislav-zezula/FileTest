/*****************************************************************************/
/* TFlagString.h                          Copyright (c) Ladislav Zezula 2021 */
/*---------------------------------------------------------------------------*/
/* Convertor of flags to string lists                                        */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 22.04.21  1.00  Lad  Created                                              */
/*****************************************************************************/

#ifndef __TFLAGSTRING_H__
#define __TFLAGSTRING_H__

//-----------------------------------------------------------------------------
// Helper functions

inline const char * GetBitSeparator()
{
    return " | ";
}

inline const char * GetBitSeparatorNewLine()
{
    return " |\r\n";
}

inline const char * GetNewLineSeparator()
{
    return "\r\n";
}

//-----------------------------------------------------------------------------
// Structure describing the flag information - name, value, mask

#define FLAGINFO_ALLSET             0xFFFFFFFF
#define FLAGINFO_BITV(value)        { #value, value, value }
#define FLAGINFO_NUMV(value)        { #value, value, FLAGINFO_ALLSET }
#define FLAGINFO_MASK(mask,value)   { #value, value, mask }
#define FLAGINFO_SEPARATOR()        { (LPCSTR)1, 0, 0 }
#define FLAGINFO_END()              { (LPCSTR)0, 0, 0 }

struct TFlagInfo
{
    bool IsValuePresent(unsigned int dwBitMask)
    {
        return (IsSeparator() == false) && ((dwBitMask & dwMask) == (dwValue & dwMask));
    }

    bool IsSeparator()
    {
        return (szFlagText == (LPCSTR)1);
    }

    bool IsTerminator()
    {
        return (szFlagText == NULL);
    }

    const char * szFlagText;
    unsigned int dwValue;
    unsigned int dwMask;
};

//-----------------------------------------------------------------------------
// Extended version of TFlagInfo for dialogs

struct TDlgFlagInfo : public TFlagInfo
{
    TDlgFlagInfo(const char * text, unsigned int value, unsigned int mask, unsigned int btn)
    {
        szFlagText = text;
        dwValue = value;
        dwMask = mask;
        dwButtonType = btn;
    }

    unsigned int dwButtonType;
};

//-----------------------------------------------------------------------------
// The TFlagString class

class TFlagString : public TFastString<TCHAR>
{
    public:

    TFlagString(TFlagInfo * pFlags, unsigned int dwBitMask, const char * szNextSep = NULL) : TFastString<TCHAR>()
    {
        // Only if we have some flags given
        if(pFlags != NULL)
        {
            // Configure separators
            const char * szNextSeparator = (szNextSep != NULL) ? szNextSep : GetBitSeparator();
            const char * szSeparator = "";

            // Parse all flags and add them to the buffer
            for(size_t i = 0; !pFlags->IsTerminator(); i++, pFlags++)
            {
                if(pFlags->IsValuePresent(dwBitMask))
                {
                    AppendSeparatorAndText(szSeparator, pFlags->szFlagText);
                    szSeparator = szNextSeparator;
                    dwBitMask = dwBitMask & ~pFlags->dwMask;
                }
            }

            // Is there a nonzero value left?
            if(dwBitMask != 0)
            {
                char szLeftOver[0x20];

                StringCchPrintfA(szLeftOver, _countof(szLeftOver), "0x%08x", dwBitMask);
                AppendSeparatorAndText(szSeparator, szLeftOver);
            }
        }

        // Nothing appended?
        if(IsEmpty())
        {
            AppendString(_T("0"));
        }
    }

    protected:

    void AppendSeparatorAndText(const char * szSeparator, const char * szFlagText)
    {
        size_t nLength1 = strlen(szSeparator);
        size_t nLength2 = strlen(szFlagText);

        // Append separator, if needed
        if(EnsureSpace(Length() + nLength1 + nLength2))
        {
#ifdef _UNICODE
            MultiByteToWideChar(CP_ACP, 0, szSeparator, -1, m_pBufferPtr, (int)nLength1);
            MultiByteToWideChar(CP_ACP, 0, szFlagText, -1, m_pBufferPtr+nLength1, (int)nLength2);
#else
            memcpy(m_pBufferPtr, szSeparator, nLength1);
            memcpy(m_pBufferPtr+nLength1, szFlagText, nLength2);
#endif
            m_pBufferPtr += (nLength1 + nLength2);
        }
    }
};

#endif // __TFLAGSTRING_H__
