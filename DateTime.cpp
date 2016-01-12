/*****************************************************************************/
/* DateTime.cpp                           Copyright (c) Ladislav Zezula 2009 */
/*---------------------------------------------------------------------------*/
/* Description: Conversion module TEXT <==> FILETIME                         */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 24.06.09  1.00  Lad  The first version of DateTime.cpp                    */
/*****************************************************************************/

#include "FileTest.h"
#include "resource.h"

//-----------------------------------------------------------------------------
// Local variables

static PSYSTEMTIME pTempSt = NULL;
static LPCTSTR szTempDateTime = NULL;
static LPTSTR szStringBufferBegin = NULL;
static LPTSTR szStringBuffer = NULL;
static LPTSTR szStringBufferEnd = NULL;
static BOOL bDateConverted = FALSE;
static BOOL bTimeConverted = FALSE;

//-----------------------------------------------------------------------------
// Local functions

static DWORD GetDateFormatToken(LPCTSTR szDateFormat, LPDWORD pdwTokenLength)
{
    TCHAR chFirstChar = *szDateFormat;
    DWORD dwEqualChars = 0;
    DWORD dwToken = 0;

    // Ignore empty strings
    if(*szDateFormat != 0)
    {
        // Remember the first char from the date/time format
        chFirstChar = *szDateFormat++;
        dwToken = chFirstChar;
        dwEqualChars++;

        // Keep going till there is the same character
        while(*szDateFormat == chFirstChar)
        {
            // Add the next character to the token
            // If the token is longer than 4 equal character,
            // the extra characters are simply cut.
            if(dwEqualChars < 4)
            {
                dwToken = (dwToken << 0x08) | *szDateFormat; 
                dwEqualChars++;
            }

            // Nove to the next character in the token
            szDateFormat++;
        }
    }

    // Return the result
    if(pdwTokenLength != NULL)
        *pdwTokenLength = dwEqualChars;
    return dwToken;
}

static WORD LocaleNameToNumber(LPCTSTR szStr, LCID lcMin, LCID lcMax, LCID lcExtra, int * piNameLength)
{
    TCHAR szLocaleName[80];
    LCID lcid;
    int nLength;

    // Set the length to zero as default
    *piNameLength = 0;

    // We have to go from December downto January. THe reason behind this
    // is that we might confuse "1" with "10".
    for(lcid = lcMax; lcid >= lcMin; lcid--)
    {
        // Get the localized month name
        nLength = GetLocaleInfo(LOCALE_USER_DEFAULT, lcid, szLocaleName, _maxchars(szLocaleName));
        if(nLength == 0)
            break;

        // If the month name is identical, we found it
        if(!_tcsnicmp(szStr, szLocaleName, (nLength - 1)))
        {
            *piNameLength = (nLength - 1);
            return (WORD)(lcid - lcMin + 1);
        }
    }

    // Last chance: check extra locale (for example, 13th month name)
    if(lcExtra != 0)
    {
        // Get the localized 13th month name
        nLength = GetLocaleInfo(LOCALE_USER_DEFAULT, lcExtra, szLocaleName, _maxchars(szLocaleName));
        if(nLength > 1)
        {
            // If the month name is identical, we found it
            if(!_tcsnicmp(szStr, szLocaleName, (nLength - 1)))
            {
                *piNameLength = (nLength - 1);
                return 13;
            }
        }
    }

    // Invalid or unrecognized locale name
    return 0xFFFF;
}

// Converts locale-specific month name to month number
// Only converts genitives
static WORD MonthNameGenitiveToNumber(LPCTSTR szStr, int * piMonthNameLength)
{
    SYSTEMTIME stTemp = {0};
    TCHAR szMonthName[80];
    int nLength;

    // Prepare the temporary SYSTEMTIME structure
    // Note: The recommended way to get month name as genitive is to use GetDateFormat
    // with "ddMMMM" and compare month name starting at second position
    stTemp.wDay = 1;
    stTemp.wYear = 2000;

    // Go through all month names.
    for(stTemp.wMonth = 1; stTemp.wMonth <= 13; stTemp.wMonth++)
    {
        // Get genitive of month name
        nLength = GetDateFormat(LOCALE_USER_DEFAULT, 0, &stTemp, _T("ddMMMM"), szMonthName, _maxchars(szMonthName));
        if(nLength < 3)
            break;

        // Compare the month name
        if(!_tcsnicmp(szStr, &szMonthName[2], nLength - 3))
        {
            *piMonthNameLength = (nLength - 3);
            return stTemp.wMonth;
        }
    }

    // Month name genitive not recognized
    return 0xFFFF;
}

// Try to recognize the AM/PM string
static BOOL AmPmNameToWord(LPCTSTR szStr, WORD & wHourModifier, int & nAmPmNameLength)
{
    TCHAR szAmPmStr[10];
    int nLength;

    // Check AM
    nLength = GetLocaleInfo(LOCALE_USER_DEFAULT, LOCALE_S1159, szAmPmStr, _maxchars(szAmPmStr));
    if(nLength > 0 && szStr[0] == szAmPmStr[0])
    {
        nAmPmNameLength = nLength;
        wHourModifier = 0;
        return TRUE;
    }

    // Check PM
    nLength = GetLocaleInfo(LOCALE_USER_DEFAULT, LOCALE_S2359, szAmPmStr, _maxchars(szAmPmStr));
    if(nLength > 0 && szStr[0] == szAmPmStr[0])
    {
        nAmPmNameLength = nLength;
        wHourModifier = 12;
        return TRUE;
    }

    // Not recognized
    return FALSE;
}

static BOOL ConvertTextToDate(PSYSTEMTIME pSt, LPCTSTR szDateTimeStr, LPTSTR szDateFormat)
{
    SYSTEMTIME st = {0};
    LPTSTR szEndChar;
    DWORD dwTokenLength;
    DWORD dwToken;
    BOOL bMonthConverted = FALSE;
    BOOL bYearConverted = FALSE;
    BOOL bDayConverted = FALSE;
    WORD wDummy;
    int nLength;

    // Remove any leading spaces from szDateTimeStr
    while(*szDateTimeStr == _T(' '))
        szDateTimeStr++;

    while(*szDateFormat != 0 && *szDateTimeStr != 0)
    {
        // Skip spaces
        while(szDateTimeStr[0] == _T(' '))
            szDateTimeStr++;
        while(szDateFormat[0] == _T(' '))
            szDateFormat++;

        dwToken = GetDateFormatToken(szDateFormat, &dwTokenLength);
        switch(dwToken)
        {
            // "d": Day of month as digits with no leading zero for single-digit days. 
            // "dd" : Day of month as digits with leading zero for single-digit days.
            case 'd':
            case 'dd':
            {
                // Day must not be there yet
                if(bDayConverted)
                    return FALSE;

                // Store day number to SYSTEMTIME structure
                st.wDay = (WORD)StrToInt(szDateTimeStr, &szEndChar, 10);
                if(IsCharAlpha(szEndChar[0]) || st.wDay == 0 || st.wDay > 31)
                    return FALSE;

                szDateTimeStr = szEndChar;
                szDateFormat += dwTokenLength;
                bDayConverted = TRUE;
                break;
            }

            // "ddd": Day of week as a three-letter abbreviation (LOCALE_SABBREVDAYNAME)
            // "dddd": Day of week as its full name (LOCALE_SDAYNAME).
            case 'ddd':
            case 'dddd':
            {
                // Convert the day of week. However, ignore the result of the conversion,
                // as day of week is not necessary to get the FILETIME and would require
                // the user to enter correct day of week
                wDummy = LocaleNameToNumber(szDateTimeStr, LOCALE_SDAYNAME1, LOCALE_SDAYNAME7, 0, &nLength);
                if(wDummy == 0xFFFF)
                    return FALSE;

                szDateFormat  += dwTokenLength;
                szDateTimeStr += nLength;
                break;
            }

            // "M": Month as digits with no leading zero for single-digit months.
            // "MM": Month as digits with leading zero for single-digit months.
            // "MMM": Month as a three-letter abbreviation. The function
            //        uses the LOCALE_SABBREVMONTHNAME value associated with the specified locale. 
            // "MMMM": Month as its full name. The function uses the LOCALE_SMONTHNAME
            //         value associated with the specified locale. 
            case 'M':
            case 'MM':
            case 'MMM':
            case 'MMMM':
            {
                // Month must not be there yet
                if(bMonthConverted)
                    return FALSE;

                // Try to convert it from genitive
                st.wMonth = MonthNameGenitiveToNumber(szDateTimeStr, &nLength);
                if(1 <= st.wMonth && st.wMonth <= 13)
                {
                    szDateFormat  += dwTokenLength;
                    szDateTimeStr += nLength;
                    bMonthConverted = TRUE;
                    break;
                }

                // Try to convert it from nominative of the full name
                st.wMonth = LocaleNameToNumber(szDateTimeStr, LOCALE_SMONTHNAME1, LOCALE_SMONTHNAME12, LOCALE_SMONTHNAME13, &nLength);
                if(1 <= st.wMonth && st.wMonth <= 13)
                {
                    szDateFormat  += dwTokenLength;
                    szDateTimeStr += nLength;
                    bMonthConverted = TRUE;
                    break;
                }

                // Try to convert it from the short name
                st.wMonth = LocaleNameToNumber(szDateTimeStr, LOCALE_SABBREVMONTHNAME1, LOCALE_SABBREVMONTHNAME12, LOCALE_SABBREVMONTHNAME13, &nLength);
                if(1 <= st.wMonth && st.wMonth <= 13)
                {
                    szDateFormat  += dwTokenLength;
                    szDateTimeStr += nLength;
                    bMonthConverted = TRUE;
                    break;
                }

                // Try to convert it from the number
                st.wMonth = (WORD)StrToInt(szDateTimeStr, &szEndChar, 10);
                if(IsCharAlpha(szEndChar[0]) || st.wMonth == 0 || st.wMonth > 12)
                    return FALSE;
                
                szDateFormat += dwTokenLength;
                szDateTimeStr = szEndChar;
                bMonthConverted = TRUE;
                break;
            }

            // "y": Year as last two digits, but with no leading zero for years less than 10.
            // "yy": Year as last two digits, but with leading zero for years less than 10.
            // "yyy": Invalid year, but we accept it
            // "yyyy": Year represented by full four digits.
            case 'y':
            case 'yy':
            case 'yyy':
            case 'yyyy':
            {
                // Convert year as digit
                st.wYear = (WORD)StrToInt(szDateTimeStr, &szEndChar, 10);
                if(IsCharAlpha(szEndChar[0]))
                    return FALSE;
                
                // Respect 2-digit years
                if(dwTokenLength == 1 || dwTokenLength == 2)
                {
                    if(80 <= st.wYear && st.wYear < 100)
                        st.wYear += 1900;
                    else
                        st.wYear += 2000;
                }

                // We don't accept years less than 1600
                if(st.wYear < 1600)
                    return FALSE;
                bYearConverted = TRUE;
                szDateTimeStr = szEndChar;
                szDateFormat += dwTokenLength;
                break;
            }

            // All other chars are considered unexpected
            default:
                return FALSE;
        }

        // Skip equal characters
        while(szDateTimeStr[0] != 0 && szDateTimeStr[0] == szDateFormat[0])
        {
            szDateTimeStr++;
            szDateFormat++;
        }
    }

    // If all three (day-month-year) were converted, we're done
    if(bDayConverted && bMonthConverted && bYearConverted)
    {
        szTempDateTime = szDateTimeStr;
        pSt->wDay = st.wDay;
        pSt->wMonth = st.wMonth;
        pSt->wYear = st.wYear;
        return TRUE;
    }

    return FALSE;
}

static BOOL ConvertTextToTime(PSYSTEMTIME pSt, LPCTSTR szDateTimeStr, LPTSTR szTimeFormat)
{
    SYSTEMTIME st = {0};
    LPTSTR szEndChar;
    DWORD dwTokenLength;
    DWORD dwToken;
    WORD wHourModifier = 0;             // 0 or 12, depends on AM/PM string
    BOOL bHourConverted = FALSE;
    BOOL bMinuteConverted = FALSE;
    BOOL bSecondConverted = FALSE;
    BOOL b12HourFormat = FALSE;
    BOOL bAmPmFound = FALSE;
    int nLength;

    // Remove any leading spaces from szDateTimeStr
    while(*szDateTimeStr == _T(' '))
        szDateTimeStr++;

    while(*szTimeFormat != 0 && *szDateTimeStr != 0)
    {
        // Skip spaces
        while(szDateTimeStr[0] == _T(' '))
            szDateTimeStr++;
        while(szTimeFormat[0] == _T(' '))
            szTimeFormat++;

        dwToken = GetDateFormatToken(szTimeFormat, &dwTokenLength);
        switch(dwToken)
        {
            // "h": Hours with no leading zero for single-digit hours; 12-hour clock.
            // "hh" : Hours with leading zero for single-digit hours; 12-hour clock.
            case 'h':
            case 'hh':
            {
                // Store day number to SYSTEMTIME structure
                st.wHour = (WORD)StrToInt(szDateTimeStr, &szEndChar, 10);
                if(IsCharAlpha(szEndChar[0]) || st.wHour > 12)
                    return FALSE;

                b12HourFormat = TRUE;
                szDateTimeStr = szEndChar;
                szTimeFormat += dwTokenLength;
                break;
            }

            // "H": Hours with no leading zero for single-digit hours; 24-hour clock.
            // "HH": Hours with leading zero for single-digit hours; 24-hour clock.
            case 'H':
            case 'HH':
            {
                // Store day number to SYSTEMTIME structure
                st.wHour = (WORD)StrToInt(szDateTimeStr, &szEndChar, 10);
                if(IsCharAlpha(szEndChar[0]) || st.wHour > 23)
                    return FALSE;

                bHourConverted = TRUE;
                szDateTimeStr = szEndChar;
                szTimeFormat += dwTokenLength;
                break;
            }

            // "m": Minutes with no leading zero for single-digit minutes.
            // "mm": Minutes with leading zero for single-digit minutes.
            case 'm':
            case 'mm':
            {
                // Store day number to SYSTEMTIME structure
                st.wMinute = (WORD)StrToInt(szDateTimeStr, &szEndChar, 10);
                if(IsCharAlpha(szEndChar[0]) || st.wMinute > 59)
                    return FALSE;

                bMinuteConverted = TRUE;
                szDateTimeStr = szEndChar;
                szTimeFormat += dwTokenLength;
                break;
            }


            // "s": Seconds with no leading zero for single-digit seconds.
            // "ss": Seconds with leading zero for single-digit seconds.
            case 's':
            case 'ss':
            {
                // Store day number to SYSTEMTIME structure
                st.wSecond = (WORD)StrToInt(szDateTimeStr, &szEndChar, 10);
                if(IsCharAlpha(szEndChar[0]) || st.wSecond > 59)
                    return FALSE;

                bSecondConverted = TRUE;
                szDateTimeStr = szEndChar;
                szTimeFormat += dwTokenLength;
                break;
            }

            // "t": One character time-marker string, such as A or P.
            // "tt": Multicharacter time-marker string, such as AM or PM.
            case 't':
            case 'tt':
            {
                // Try to recognize the string
                if(AmPmNameToWord(szDateTimeStr, wHourModifier, nLength) == FALSE)
                    return FALSE;

                bAmPmFound = TRUE;
                szDateTimeStr += nLength;
                szTimeFormat += dwTokenLength;
                break;
            }

            // All other chars are considered unexpected
            default:
                return FALSE;
        }

        // Skip equal characters
        while(szDateTimeStr[0] != 0 && szDateTimeStr[0] == szTimeFormat[0])
        {
            szDateTimeStr++;
            szTimeFormat++;
        }

        // If both 12-hour and AM/PM string have been found,
        // consider hour as converted
        if(bHourConverted == FALSE && b12HourFormat && bAmPmFound)
        {
            st.wHour = st.wHour + wHourModifier;
            bHourConverted = TRUE;
        }
    }

    // If all three (hour-minute-second) were converted, we're done
    if(bHourConverted && bMinuteConverted && bSecondConverted)
    {
        pSt->wHour = st.wHour;
        pSt->wMinute = st.wMinute;
        pSt->wSecond = st.wSecond;
        return TRUE;
    }

    // If only hour and minute have been converted, it's OK
    if(bHourConverted && bMinuteConverted && bSecondConverted == FALSE)
    {
        pSt->wHour = st.wHour;
        pSt->wMinute = st.wMinute;
        pSt->wSecond = 0;
        return TRUE;
    }

    // If time is not present at all, we consider this as OK
    if(bHourConverted == FALSE && bMinuteConverted == FALSE && bSecondConverted == FALSE )
    {
        pSt->wHour = 0;
        pSt->wMinute = 0;
        pSt->wSecond = 0;
        return TRUE;
    }

    return FALSE;
}


static BOOL CALLBACK CollectFormatsProc(LPTSTR szFormat)
{
    if(wcsstr(szStringBufferBegin, szFormat) == NULL)
    {
        while(szStringBuffer < szStringBufferEnd && *szFormat != 0)
            *szStringBuffer++ = *szFormat++;

        if(szStringBuffer < szStringBufferEnd)
            *szStringBuffer++ = _T('\n');
    }
    return TRUE;
}

static BOOL CALLBACK EnumDateFormatsProc(LPTSTR szDateFormat)
{
    if(ConvertTextToDate(pTempSt, szTempDateTime, szDateFormat))
    {
        bDateConverted = TRUE;
        return FALSE;
    }
    return TRUE;
}

static BOOL CALLBACK EnumTimeFormatsProc(LPTSTR szTimeFormat)
{
    if(ConvertTextToTime(pTempSt, szTempDateTime, szTimeFormat))
    {
        bTimeConverted = TRUE;
        return FALSE;
    }
    return TRUE;
}

static LPTSTR FileTimeToLargeInteger(
    LPTSTR szBuffer,
    LPTSTR szEndChar,
    PFILETIME pFt)
{
    TCHAR szTemp[0x20];

    // Format the filetime
    StringCchPrintf(szTemp, _countof(szTemp), _T("%08lX-%08lX"), pFt->dwHighDateTime, pFt->dwLowDateTime);

    // Copy to target buffer
    for(int i = 0; szTemp[i] != 0; i++)
    {
        if(szEndChar > szBuffer)
            *szBuffer++ = szTemp[i];
    }

    // Return the new buffer pointer
    return szBuffer;
}

static int FileTimeToHumanReadableText(
    LPTSTR szBuffer,
    LPTSTR szEndChar,
    PFILETIME pFt,
    BOOL bEncloseInParentheses)
{
    SYSTEMTIME st;
    FILETIME lft;
    LPTSTR szSaveBuffer = szBuffer;
    int nLength;

    // Verify blank or invalid date(s)
    if(pFt->dwHighDateTime == 0xFFFFFFFF && pFt->dwLowDateTime == 0xFFFFFFFF)
        return 0;
    if(pFt->dwHighDateTime == 0 && pFt->dwLowDateTime == 0)
        return 0;

    // Convert the filetime to local file time
    if(!FileTimeToLocalFileTime(pFt, &lft))
        return 0;
    if(!FileTimeToSystemTime(&lft, &st))
        return 0;

    // Add the opening parenthesis, if needed
    if(bEncloseInParentheses && szEndChar > szBuffer)
        *szBuffer++ = _T('(');

    // Format the date
    nLength = GetDateFormat(LOCALE_USER_DEFAULT, DATE_LONGDATE, &st, NULL, szBuffer, (int)(szEndChar - szBuffer));
    if(nLength > 0)
        szBuffer += (nLength - 1);

    // Add space as separator
    if(szEndChar > szBuffer)
        *szBuffer++ = _T(' ');

    // Format the time
    nLength = GetTimeFormat(LOCALE_USER_DEFAULT, 0, &st, NULL, szBuffer, (int)(szEndChar - szBuffer));
    if(nLength > 0)
        szBuffer += (nLength - 1);

    // Add closing bracket
    if(bEncloseInParentheses && szEndChar > szBuffer)
        *szBuffer++ = _T(')');

    return (int)(szBuffer - szSaveBuffer);
}

//-----------------------------------------------------------------------------
// Public functions

LPTSTR FileTimeToText(
    LPTSTR szBuffer,
    LPTSTR szEndChar,
    PFILETIME pFt,
    BOOL bTextForEdit)
{
    int nLength;

    if(bTextForEdit == FALSE)
    {
        // First part: date as LARGE_INTEGER
        szBuffer = FileTimeToLargeInteger(szBuffer, szEndChar, pFt);

        // Add one space
        if(szEndChar > szBuffer)
            *szBuffer++ = _T(' ');

        // Append the filetime in human-readable form
        nLength = FileTimeToHumanReadableText(szBuffer,
                                              szEndChar,
                                              pFt,
                                              TRUE);
        szBuffer += nLength;
    }
    else
    {
        // Attempt to convert the filetime to human-readable form
        nLength = FileTimeToHumanReadableText(szBuffer,
                                              szEndChar,
                                              pFt,
                                              FALSE);

        // If failed, just convert it to LARGE_INTEGER
        if(nLength == 0)
        {
            szBuffer = FileTimeToLargeInteger(szBuffer, szEndChar, pFt);
        }
        else
        {
            szBuffer += nLength;
        }
    }

    return szBuffer;
}

NTSTATUS TextToFileTime(LPCTSTR szText, PFILETIME pFt)
{
    SYSTEMTIME st = {0};
    FILETIME ft;
    LPTSTR szEndChar = NULL;

    // Prepare the local variables to be filled by callbacks
    bDateConverted = FALSE;
    bTimeConverted = FALSE;
    szTempDateTime = szText;
    pTempSt = &st;

    // First of all, try to convert the filetime from human-readable form
    if(bDateConverted == FALSE)
        EnumDateFormats(EnumDateFormatsProc, LOCALE_USER_DEFAULT, DATE_SHORTDATE);
    if(bDateConverted == FALSE)
        EnumDateFormats(EnumDateFormatsProc, LOCALE_USER_DEFAULT, DATE_LONGDATE);
    if(bTimeConverted == FALSE)
        EnumTimeFormats(EnumTimeFormatsProc, LOCALE_USER_DEFAULT, 0);

    // If both date and time converted, we have succeeded
    if(bDateConverted && bTimeConverted)
    {
        if(!SystemTimeToFileTime(&st, &ft))
            return STATUS_INVALID_DATA_FORMAT;
        if(!LocalFileTimeToFileTime(&ft, pFt))
            return STATUS_INVALID_DATA_FORMAT;
        return STATUS_SUCCESS;
    }

    // Try to convert 64-bit value in the form of ################ or 0x################
    if(Text2Hex64(szText, (PLONGLONG)&ft) != ERROR_SUCCESS)
    {
        // Try to convert the 64-bit value in the form of ########-########
        ft.dwHighDateTime = StrToInt(szText, &szEndChar, 16);
        if(szEndChar == NULL || szEndChar[0] != _T('-'))
            return STATUS_INVALID_DATA_FORMAT;

        ft.dwLowDateTime = StrToInt(szEndChar+1, &szEndChar, 16);
        if(szEndChar[0] != 0 && szEndChar[0] != _T(' '))
            return STATUS_INVALID_DATA_FORMAT;
    }

    // We accept "FFFFFFFF-FFFFFFFF" as input
    if(ft.dwHighDateTime == 0xFFFFFFFF && ft.dwLowDateTime == 0xFFFFFFFF)
    {
        pFt->dwHighDateTime = ft.dwHighDateTime;
        pFt->dwLowDateTime = ft.dwLowDateTime;
        return STATUS_SUCCESS;
    }

    // We accept "00000000-00000000" as input
    if(ft.dwHighDateTime == 0 && ft.dwLowDateTime == 0)
    {
        pFt->dwHighDateTime = ft.dwHighDateTime;
        pFt->dwLowDateTime = ft.dwLowDateTime;
        return STATUS_SUCCESS;
    }

    // Convert from local time to file time
    if(LocalFileTimeToFileTime(&ft, pFt))
        return STATUS_SUCCESS;

    // Conversion failed
    return STATUS_INVALID_DATA_FORMAT;
}

BOOL GetSupportedDateTimeFormats(
    LPCTSTR szDateFormatPrefix,
    LPCTSTR szTimeFormatPrefix,
    LPTSTR szBuffer,
    int nMaxChars)
{
    // Initialize the global strings
    szStringBufferBegin = szBuffer;
    szStringBuffer      = szBuffer;
    szStringBufferEnd   = szBuffer + nMaxChars - 1;

    // Put the date format prefix, if any
    if(szStringBuffer != NULL)
    {
        while(szStringBuffer < szStringBufferEnd && *szDateFormatPrefix != 0)
            *szStringBuffer++ = *szDateFormatPrefix++;
    }

    // Put the date formats
    EnumDateFormats(CollectFormatsProc, LOCALE_USER_DEFAULT, DATE_SHORTDATE);
    EnumDateFormats(CollectFormatsProc, LOCALE_USER_DEFAULT, DATE_LONGDATE);

    // Put the time format prefix, if any
    if(szStringBuffer != NULL)
    {
        while(szStringBuffer < szStringBufferEnd && *szTimeFormatPrefix != 0)
            *szStringBuffer++ = *szTimeFormatPrefix++;
    }

    // Put the time formats
    EnumTimeFormats(CollectFormatsProc, LOCALE_USER_DEFAULT, 0);

    // Terminate the string and return
    *szStringBuffer = 0;
    return TRUE;
}
