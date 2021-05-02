/*****************************************************************************/
/* TFastString.h                          Copyright (c) Ladislav Zezula 2017 */
/*---------------------------------------------------------------------------*/
/* Helper class for growable string buffers                                  */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 27.11.17  1.00  Lad  The first version of TFastString.h                   */
/*****************************************************************************/

#ifndef __TFASTSTRING_H__
#define __TFASTSTRING_H__

//-----------------------------------------------------------------------------
// All allocations are done against global process heap handle

extern HANDLE g_hHeap;

//-----------------------------------------------------------------------------
// Useful functions

template <typename XCHAR>
bool IsSpace(XCHAR ch)
{
    return (0 < ch && ch <= 0x20);
}

template <typename XCHAR>
FORCEINLINE XCHAR * SkipSpaces(const XCHAR * sz)
{
    while(0 < *sz && *sz <= 0x20)
        sz++;
    return (XCHAR *)sz;
}

template <typename XCHAR>
FORCEINLINE XCHAR * SkipNonSpaces(const XCHAR * sz)
{
    while(sz[0] != 0 && sz[0] > 0x20)
        sz++;
    return (XCHAR *)sz;
}

template <typename XCHAR>
FORCEINLINE XCHAR * SkipSpacesAndCommas(const XCHAR * sz)
{
    while((0 < *sz && *sz <= 0x20) || *sz == ',')
        sz++;
    return (XCHAR *)sz;
}

FORCEINLINE size_t StringLength(const char * szStr)
{
    return (szStr != NULL) ? strlen(szStr) : 0;
}

FORCEINLINE size_t StringLength(const wchar_t * szStr)
{
    return (szStr != NULL) ? wcslen(szStr) : 0;
}

template <typename XCHAR>
static DWORD HashString(const XCHAR * szString)
{
    DWORD dwHash = 0x7EEEEEE7;

    // Sanity check
    assert(szString != NULL);

    // Add the string
    while(szString[0] != 0)
    {
        dwHash = (dwHash >> 24) + (dwHash << 5) + dwHash + szString[0];
        szString++;
    }

    return dwHash;
}

//-----------------------------------------------------------------------------
// Common implementation of the fast string

template <typename XCHAR>
class TFastString
{
    public:

    typedef const XCHAR * LPCXSTR;
    typedef XCHAR * LPXSTR;

    TFastString()
    {
        Init();
    }

    virtual ~TFastString()
    {
        if(m_pBuffer != m_StaticBuff)
            HeapFree(g_hHeap, 0, m_pBuffer);
        m_pBuffer = m_StaticBuff;
    }

    void InitFromLPCWSTR(LPCWSTR szStringW)
    {
        // Check for NULL and empty strings
        if(szStringW && szStringW[0])
        {
            // Calculate length of the string
            size_t nWideLength = wcslen(szStringW);

            // Converting LPWSTR -> LPSTR?
            if(m_nCharSize == sizeof(CHAR))
            {
                size_t nAnsiLength = nWideLength;
                size_t nTryCount = 0;

                __TryAgain:

                // Make sure that the string is reset
                Reset();

                // Make sure there is enough space for the string
                if(EnsureSpace(nAnsiLength))
                {
                    // Convert the WIDE string to ANSI string
                    nAnsiLength = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, szStringW, (int)nWideLength, (LPSTR)m_pBuffer, (int)nAnsiLength, NULL, NULL);
                    if(nAnsiLength != 0)
                    {
                        m_pBufferPtr = m_pBuffer + nAnsiLength;
                    }

                    // If failed, we check whether this is a buffer overflow
                    else if(GetLastError() == ERROR_INSUFFICIENT_BUFFER)
                    {
                        nAnsiLength = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, szStringW, (int)nWideLength, NULL, 0, NULL, NULL);
                        if(nTryCount++ == 0)
                        {
                            goto __TryAgain;
                        }
                    }
                }
            }
            else
            {
                if(EnsureSpace(nWideLength))
                {
                    memcpy(m_pBuffer, szStringW, nWideLength * sizeof(XCHAR));
                    m_pBufferPtr = m_pBuffer + nWideLength;
                }
            }
        }
        else
        {
            m_pBufferPtr = m_pBuffer;
        }

        // Make sure we're zero terminated
        m_pBufferPtr[0] = 0;
    }

    void InitFromLPCSTR(LPCSTR szStringA)
    {
        // Check for NULL and empty strings
        if(szStringA && szStringA[0])
        {
            // Calculate length of the string
            size_t nAnsiLength = strlen(szStringA);

            // Converting LPSTR -> LPWSTR?
            if(m_nCharSize == sizeof(WCHAR))
            {
                size_t nWideLength = nAnsiLength;
                size_t nTryCount = 0;

                __TryAgain:

                // Make sure that the string is reset
                Reset();

                // Make sure there is enough space for the string
                if(EnsureSpace(nWideLength))
                {
                    // Convert the WIDE string to ANSI string
                    nWideLength = MultiByteToWideChar(CP_ACP, 0, szStringA, (int)nAnsiLength, (LPWSTR)m_pBuffer, (int)nWideLength);
                    if(nWideLength != 0)
                    {
                        m_pBufferPtr = m_pBuffer + nWideLength;
                    }

                    // If failed, we check whether this is a buffer overflow
                    else if(GetLastError() == ERROR_INSUFFICIENT_BUFFER)
                    {
                        nAnsiLength = MultiByteToWideChar(CP_ACP, 0, szStringA, (int)nAnsiLength, NULL, 0);
                        if(nTryCount++ == 0)
                        {
                            goto __TryAgain;
                        }
                    }
                }
            }
            else
            {
                if(EnsureSpace(nAnsiLength))
                {
                    memcpy(m_pBuffer, szStringA, nAnsiLength * sizeof(XCHAR));
                    m_pBufferPtr = m_pBuffer + nAnsiLength;
                }
            }
        }
        else
        {
            m_pBufferPtr = m_pBuffer;
        }

        // Make sure we're zero terminated
        m_pBufferPtr[0] = 0;
    }

    bool AppendChar(XCHAR chOneChar)
    {
        // Ensure that there is space for one character
        if(!EnsureSpace(1))
            return false;

        // Insert the character
        *m_pBufferPtr++ = chOneChar;
        return true;
    }

    bool AppendChars(XCHAR chOneChar, size_t nCount)
    {
        // Ensure that there is space for one character
        if(!EnsureSpace(nCount))
            return false;

        // Insert the character
        for(size_t i = 0; i < nCount; i++)
            m_pBufferPtr[i] = chOneChar;
        m_pBufferPtr += nCount;
        return true;
    }

    bool AppendString(LPCXSTR szString, size_t nLength)
    {
        // Ensure that there is enough space in the buffers
        if(!EnsureSpace(nLength))
            return false;

        memcpy(m_pBufferPtr, szString, nLength * sizeof(XCHAR));
        m_pBufferPtr += nLength;
        return true;
    }

    bool AppendString(LPCXSTR szString)
    {
        return AppendString(szString, StringLength(szString));
    }

    LPCXSTR PutEosAt(LPCXSTR szPosition)
    {
        LPXSTR szBufferPos = (LPXSTR)(szPosition);

        if(m_pBuffer <= szBufferPos && szBufferPos <= m_pBufferPtr)
            szBufferPos[0] = 0;
        return m_pBuffer;
    }

    void TrimLeftAndRight(bool(*PfnIsTrimChar)(XCHAR ch))
    {
        LPXSTR pTrimRight = m_pBufferPtr;
        LPXSTR pTrimLeft = m_pBuffer;

        // Trim left
        while(pTrimLeft < pTrimRight && PfnIsTrimChar(pTrimLeft[0]))
            pTrimLeft++;

        // Trim right
        while(pTrimRight > pTrimLeft && PfnIsTrimChar(pTrimRight[-1]))
            pTrimRight--;

        // Perform memmove, if we trimmed something from the left
        if(pTrimLeft > m_pBuffer)
            memmove(m_pBuffer, pTrimLeft, (pTrimRight - pTrimLeft) * sizeof(TCHAR));
        m_pBuffer[pTrimRight - pTrimLeft] = 0;
        m_pBufferPtr = m_pBuffer + (pTrimRight - pTrimLeft);
    }


    void TrimSpaces()
    {
        TrimLeftAndRight(IsSpace);
    }

    bool CutLastChar()
    {
        if(m_pBufferPtr > m_pBuffer)
        {
            m_pBufferPtr--;
            return true;
        }
        return false;
    }

    // Initializes the string a-new
    void Init()
    {
        // Set the string to the static array
        m_pBuffer = m_StaticBuff;
        m_pBufferPtr = m_pBuffer;
        m_pBufferEnd = m_pBuffer + _countof(m_StaticBuff) - 1;
        m_nCharSize = sizeof(XCHAR);

        // Terminate the string with zero
        m_StaticBuff[0] = 0;
    }

    // Sets the string to have zero length. Also makes it zero terminated.
    void Reset()
    {
        m_pBufferPtr = m_pBuffer;
        m_pBuffer[0] = 0;
    }

    // Returns the buffer as string. Ensures that it's zero terminated.
    LPCXSTR GetStr()
    {
        m_pBufferPtr[0] = 0;
        return m_pBuffer;
    }

    // Very fast conversion from LPCWSTR. If XCHAR == WCHAR
    // the function just returns the original pointer
    LPCXSTR GetLPCXSTR(LPCWSTR szStringW)
    {
        // Must be non-NULL and non-empty
        if(szStringW != NULL)
        {
            // Conversion from LPCWSTR to LPCSTR?
            if(m_nCharSize == sizeof(CHAR))
            {
                InitFromLPCWSTR(szStringW);
                return GetStr();
            }
            else
            {
                return (LPCXSTR)(szStringW);
            }
        }
        return NULL;
    }

    // Very fast conversion from LPCSTR. If XCHAR == CHAR,
    // the function just returns the original pointer
    LPCXSTR GetLPCXSTR(LPCSTR szStringA)
    {
        // Must be non-NULL and non-empty
        if(szStringA != NULL)
        {
            // Conversion from LPCSTR to LPCWSTR?
            if(m_nCharSize == sizeof(WCHAR))
            {
                InitFromLPCSTR(szStringA);
                return GetStr();
            }
            else
            {
                return (LPCXSTR)(szStringA);
            }
        }
        return NULL;
    }

    LPCXSTR GetBuffer() const
    {
        return m_pBuffer;
    }

    bool SetLength(size_t nLength)
    {
        // Make sure there is enough space in the bufer
        if(nLength > (size_t)(m_pBufferEnd - m_pBuffer))
        {
            if(!EnsureSpace(nLength - Length()))
            {
                return false;
            }
        }

        // Adjust pointers
        assert((m_pBuffer + nLength) < m_pBufferEnd);
        m_pBufferPtr = m_pBuffer + nLength;
        return true;
    }

    size_t Length() const
    {
        return m_pBufferPtr - m_pBuffer;
    }

    bool IsEmpty() const
    {
        return (m_pBufferPtr == m_pBuffer);
    }

    operator LPCXSTR()
    {
        return GetStr();
    }

    XCHAR operator[](size_t nIndex) const
    {
        if((m_pBuffer + nIndex) > m_pBufferPtr)
            return 0;
        return m_pBuffer[nIndex];
    }

    protected:

    bool EnsureSpace(size_t nReserve)
    {
        // Would we go beyond the buffer if we added that number of chars?
        if((m_pBufferPtr + nReserve) > m_pBufferEnd)
        {
            size_t nMaxLength = (m_pBufferEnd - m_pBuffer);
            size_t nLength = (m_pBufferPtr - m_pBuffer);

            // Calculate new needed size
            while ((nLength + nReserve) > nMaxLength)
                nMaxLength <<= 1;

            // Allocate new buffer
            if(m_pBuffer == m_StaticBuff)
            {
                // First reallocation: Allocate brand new.
                m_pBuffer = (LPXSTR)HeapAlloc(g_hHeap, 0, ((nMaxLength + 1) * sizeof(XCHAR)));
                if(m_pBuffer == NULL)
                {
                    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                    return false;
                }

                memcpy(m_pBuffer, m_StaticBuff, nLength * sizeof(XCHAR));
            }

            // Reallocate old buffer
            else
            {
                // Second reallocation: Use HeapReAlloc
                LPXSTR pNewBuffer = (LPXSTR)HeapReAlloc(g_hHeap, 0, m_pBuffer, ((nMaxLength + 1) * sizeof(XCHAR)));

                // Failed - the old buffer is still allocated
                if(pNewBuffer == NULL)
                {
                    HeapFree(g_hHeap, 0, m_pBuffer);
                    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                    return false;
                }

                // Remember the new buffer
                m_pBuffer = pNewBuffer;
            }

            // Adjust buffers
            m_pBufferEnd = m_pBuffer + nMaxLength;
            m_pBufferPtr = m_pBuffer + nLength;
        }

        return true;
    }

    LPXSTR m_pBuffer;               // Pointer to the begin of the buffer
    LPXSTR m_pBufferPtr;            // Pointer to the current position in the buffer
    LPXSTR m_pBufferEnd;            // Pointer to the end of the buffer. There is always 1 extra character!
    size_t m_nCharSize;             // sizeof(XCHAR)
    XCHAR m_StaticBuff[0x80];       // For shorter strings, we use static buffer
};

//-----------------------------------------------------------------------------
// Convertor from UNICODE string to ANSI string

struct TAnsiString : public TFastString<CHAR>
{
    TAnsiString()
    {}

    TAnsiString(LPCSTR szString)
    {
        InitFromLPCSTR(szString);
    }

    TAnsiString(LPCWSTR szString)
    {
        InitFromLPCWSTR(szString);
    }
};

//-----------------------------------------------------------------------------
// Convertor from ANSI string to UNICODE string

struct TWideString : public TFastString<WCHAR>
{
    TWideString()
    {}

    TWideString(LPCSTR szString)
    {
        InitFromLPCSTR(szString);
    }

    TWideString(LPCWSTR szString)
    {
        InitFromLPCWSTR(szString);
    }
};

#endif // __TFASTSTRING_H__
