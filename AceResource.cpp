/*****************************************************************************/
/* AceResource.cpp                        Copyright (c) Ladislav Zezula 2023 */
/*---------------------------------------------------------------------------*/
/* Description:                                                              */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 23.11.23  1.00  Lad  Created                                              */
/*****************************************************************************/

#include "FileTest.h"

//-----------------------------------------------------------------------------
// Local functions

static LPWSTR SafeStringRead(LPBYTE pbPtr, LPBYTE pbEnd, ULONG Offset, PULONG pcbMoveBy)
{
    LPWSTR szString;
    LPBYTE pbString;
    ULONG cbMoveBy;

    // Update the pbPtr
    pbString = pbPtr = (pbPtr + Offset);

    // Determine the length of the string
    while((pbPtr + sizeof(WCHAR)) <= pbEnd)
    {
        if(*(WCHAR *)(pbPtr) == 0)
            break;
        pbPtr += sizeof(WCHAR);
    }

    // Calculate ther length of the string
    cbMoveBy = (ULONG)(pbPtr - pbString) + sizeof(WCHAR);

    // Allocate and copy the string
    if((szString = (LPWSTR)LocalAlloc(LPTR, cbMoveBy)) != NULL)
        memmove(szString, pbString, cbMoveBy);

    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbMoveBy;
    return szString;
}


//-----------------------------------------------------------------------------
// Public functions

PCLAIM_SECURITY_ATTRIBUTE_V1 ClaimSecurityAttributeRel2Abs(
    LPBYTE pbPtr,
    LPBYTE pbEnd,
    PULONG pcbMoveBy)
{
    PCLAIM_SECURITY_ATTRIBUTE_V1 pSecAttrAbs = NULL;
    LPWSTR szAttributeName = NULL;
    ULONG cbAttributeName = 0;
    ULONG cbMoveBy = 0;

    if((pbPtr + sizeof(CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1)) <= pbEnd)
    {
        PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 pSecAttrRel = (PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1)(pbPtr);

        // Read the attribute name
        cbMoveBy = sizeof(CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1);
        szAttributeName = SafeStringRead(pbPtr, pbEnd, pSecAttrRel->Name, &cbAttributeName);

        // Update the length
        if((pSecAttrRel->Name + cbAttributeName) > cbMoveBy)
            cbMoveBy = pSecAttrRel->Name + cbAttributeName;

        // Give the cbMoveBy
        if(pcbMoveBy != NULL)
            pcbMoveBy[0] = cbMoveBy;
    }
    else
    {
        SetLastError(ERROR_BAD_FORMAT);
    }

    return pSecAttrAbs;
}
