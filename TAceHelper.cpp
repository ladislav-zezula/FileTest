/*****************************************************************************/
/* TAceHelper.cpp                         Copyright (c) Ladislav Zezula 2016 */
/*---------------------------------------------------------------------------*/
/* Description :                                                             */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 26.03.16  1.00  Lad  The first version of TAceHelper.cpp                  */
/*****************************************************************************/

#include "FileTest.h"

//-----------------------------------------------------------------------------
// Local variables

static GUID NullGuid = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};

//-----------------------------------------------------------------------------
// Constructor and destructor

ACE_HELPER::ACE_HELPER()
{
    memset(this, 0, sizeof(ACE_HELPER));
}

ACE_HELPER::~ACE_HELPER()
{
    Reset();
}

//-----------------------------------------------------------------------------
// Public functions

bool ACE_HELPER::SetAceType(DWORD dwAceType)
{
    switch(dwAceType)
    {
        case ACCESS_ALLOWED_ACE_TYPE:                   // Simple ACEs:
        case ACCESS_DENIED_ACE_TYPE:                    // {Header-Mask-SidStart}
        case SYSTEM_AUDIT_ACE_TYPE:
        case SYSTEM_ALARM_ACE_TYPE:
            AceLayout = ACE_LAYOUT_SIMPLE;
            break;

        case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:          // Compound ACEs:
            AceLayout = ACE_LAYOUT_COMPOUND;            // {Header-Mask-CompoundType-Reserved-ServerSid-CliendSid}
            break;

        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:            // Object ACEs:
        case ACCESS_DENIED_OBJECT_ACE_TYPE:             // {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart-Condition}
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
        case SYSTEM_ALARM_OBJECT_ACE_TYPE:
            AceLayout = ACE_LAYOUT_OBJECT;
            break;

        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:          // Conditional ACEs:
        case ACCESS_DENIED_CALLBACK_ACE_TYPE:           // {Header-Mask-SidStart-Condition}
        case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
        case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
            AceLayout = ACE_LAYOUT_CONDITION;
            break;

        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:   // Conditional object ACEs:
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:    // {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart-Condition}
        case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
        case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
            AceLayout = ACE_LAYOUT_OBJECT_CONDITION;
            break;

        case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
            AceLayout = ACE_LAYOUT_MANDATORY;
            break;

        case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
            AceLayout = ACE_LAYOUT_RESOURCE;            // Contains the CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 structure
            break;

        default:
            AceLayout = ACE_FIELD_HEADER | ACE_FIELD_ACCESS_MASK;
            break;
    }

    // Remember the ACE type
    AceType = (BYTE)(dwAceType);
    return true;
}

bool ACE_HELPER::SetAce(PACE_HEADER pAceHeader)
{
    bool bResult;

    // Verify ACE type and set the ACE layout
    if((bResult = SetAceType(pAceHeader->AceType)) != false)
    {
        LPBYTE pbAceEnd = (LPBYTE)(pAceHeader) + pAceHeader->AceSize;
        LPBYTE pbAcePtr = (LPBYTE)(pAceHeader + 1);

        // Fill-in the header (always included)
        if(AceLayout & ACE_FIELD_HEADER)
        {
            AceFlags = pAceHeader->AceFlags;
            AceSize = pAceHeader->AceSize;
        }

        // Is there the ACE::Mask?
        if(AceLayout & (ACE_FIELD_ACCESS_MASK | ACE_FIELD_ADS_ACCESS_MASK | ACE_FIELD_MANDATORY_MASK))
        {
            Mask = *(PDWORD)(pbAcePtr);
            pbAcePtr += sizeof(DWORD);
        }

        // Is there the ACE::Flags
        if(AceLayout & ACE_FIELD_FLAGS)
        {
            // Copy the ACE::Flags
            Flags = *(PDWORD)(pbAcePtr);
            pbAcePtr += sizeof(DWORD);

            // ACE::ObjectType is only present if ACE_OBJECT_TYPE_PRESENT is in the flags
            if(Flags & ACE_OBJECT_TYPE_PRESENT)
            {
                memcpy(&ObjectType, pbAcePtr, sizeof(GUID));
                pbAcePtr += sizeof(GUID);
            }

            // Is there the ACE::InheritedObjectType?
            if(Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
            {
                memcpy(&InheritedObjectType, pbAcePtr, sizeof(GUID));
                pbAcePtr += sizeof(GUID);
            }
        }

        // Get the compound ACE type
        if(AceLayout & (ACE_FIELD_CTYPE | ACE_FIELD_CRESERVED))
        {
            CompoundAceType = *(PUSHORT)(pbAcePtr);
            CompoundReserved = *(PUSHORT)(pbAcePtr + sizeof(USHORT));
            pbAcePtr += sizeof(USHORT) + sizeof(USHORT);
        }

        // Get the pointer to (server|mandatory) SID
        if(AceLayout & (ACE_FIELD_ACCESS_SID | ACE_FIELD_SERVER_SID | ACE_FIELD_MANDATORY_SID))
        {
            pbAcePtr += GetLengthSid(Sid[0] = (PSID)(pbAcePtr));
            FreeFlags &= ~ACE_HELPER_NEED_FREE_SID0;
        }

        // Get the pointer to (server|mandatory) SID
        if(AceLayout & ACE_FIELD_CLIENT_SID)
        {
            pbAcePtr += GetLengthSid(Sid[1] = (PSID)(pbAcePtr));
            FreeFlags &= ~ACE_HELPER_NEED_FREE_SID1;
        }

        // Get the CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 and convert it to pointer-based structure
        if((AceLayout & ACE_FIELD_CSA_V1) && (pbAcePtr < pbAceEnd))
        {
            AttrRel = CaptureExtraStructure(pbAcePtr, pbAceEnd, &AttrRelLength);
            pbAcePtr += AttrRelLength;
        }

        // Get the ACE condition. Example: C:\Program Files\WindowsApps\<any folder>
        if((AceLayout & ACE_FIELD_CONDITION) && (pbAcePtr < pbAceEnd))
        {
            Condition = CaptureExtraStructure(pbAcePtr, pbAceEnd, &ConditionLength);
            pbAcePtr += ConditionLength;
        }
    }
    return bResult;
}

// pNewSid could be NULL if we want just to free the existing SID[nSidIndex]
void ACE_HELPER::SetAllocatedSid(PSID pNewSid, size_t nSidIndex)
{
    DWORD dwFreeFlag = ACE_HELPER_NEED_FREE_SID0 << nSidIndex;

    // Free the old SID
    if((Sid[nSidIndex] != NULL) && (FreeFlags & dwFreeFlag))
        RtlFreeSid(Sid[nSidIndex]);
    Sid[nSidIndex] = NULL;

    // Store the new one
    if(pNewSid != NULL)
        Sid[nSidIndex] = pNewSid;

    // Update the flags in AceLayout
    FreeFlags = (pNewSid != NULL) ? (FreeFlags | dwFreeFlag) : (FreeFlags & ~dwFreeFlag);
}

PACE_HEADER ACE_HELPER::BuildAce(DWORD dwAceType, ACCESS_MASK AccessMask, LPBYTE pbBuffer, size_t cbBuffer)
{
    PACE_HEADER pAceHeader = (PACE_HEADER)(pbBuffer);
    LPBYTE pbEnd = pbBuffer + cbBuffer;
    LPBYTE pbPtr = pbBuffer;
    ULONG GuidFlags = Flags;

    // We do not support ACEs with condition
    if((AceLayout & ACE_FIELD_CONDITION) && (Condition != NULL))
        return NULL;

    // Save values to the ACE_HELPER
    if(!SetAceType(dwAceType))
        return NULL;
    Mask = AccessMask;

    // Fill-in the header
    if(AceLayout & ACE_FIELD_HEADER)
    {
        if((pbPtr + sizeof(ACE_HEADER)) > pbEnd)
            return NULL;
        pAceHeader->AceType = AceType;
        pAceHeader->AceFlags = AceFlags;
        pAceHeader->AceSize = sizeof(ACE_HEADER);
        pbPtr += sizeof(ACE_HEADER);
    }

    // Fill-in the ACE:Mask
    pbPtr = PutAceValue(pbPtr, pbEnd, &AccessMask, (ACE_FIELD_ACCESS_MASK | ACE_FIELD_ADS_ACCESS_MASK | ACE_FIELD_MANDATORY_MASK), sizeof(ACCESS_MASK));
    if(pbPtr == NULL)
        return NULL;

    // Fill-in the ACE::Flags
    pbPtr = PutAceValue(pbPtr, pbEnd, &GuidFlags, ACE_FIELD_FLAGS, sizeof(GuidFlags));
    if(pbPtr == NULL)
        return NULL;

    // Fill-in the ACE::CompoundAceType
    pbPtr = PutAceValue(pbPtr, pbEnd, &CompoundAceType, ACE_FIELD_CTYPE, sizeof(CompoundAceType));
    if(pbPtr == NULL)
        return NULL;

    // Fill-in the ACE::CompoundReserved
    pbPtr = PutAceValue(pbPtr, pbEnd, &CompoundReserved, ACE_FIELD_CRESERVED, sizeof(CompoundReserved));
    if(pbPtr == NULL)
        return NULL;

    // Fill-in the ACE::ObjectType
    if(GuidFlags & ACE_OBJECT_TYPE_PRESENT)
    {
        pbPtr = PutAceValue(pbPtr, pbEnd, &ObjectType, ACE_FIELD_OBJECT_TYPE1, sizeof(ObjectType));
        if(pbPtr == NULL)
            return NULL;
    }

    // Fill-in the ACE::InheritedObjectType
    if(GuidFlags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
    {
        pbPtr = PutAceValue(pbPtr, pbEnd, &InheritedObjectType, ACE_FIELD_OBJECT_TYPE2, sizeof(InheritedObjectType));
        if(pbPtr == NULL)
            return NULL;
    }

    // Fill-in the (server, mandatory) SID
    if(AceLayout & (ACE_FIELD_ACCESS_SID | ACE_FIELD_SERVER_SID))
    {
        if((pbPtr = PutAceValueSid(pbPtr, pbEnd, Sid[0])) == NULL)
            return NULL;
    }

    // Fill-in the client SID
    if(AceLayout & ACE_FIELD_CLIENT_SID)
    {
        if((pbPtr = PutAceValueSid(pbPtr, pbEnd, Sid[1])) == NULL)
            return NULL;
    }

    // Fill-in the mandatory SID
    if(AceLayout & ACE_FIELD_MANDATORY_SID)
    {
        if((pbPtr = PutAceValueSid(pbPtr, pbEnd, Sid[0])) == NULL)
            return NULL;
    }

    //
    // TODO: Fill-in the condition
    //

    // Fixup the ACE size
    pAceHeader->AceSize = (WORD)(pbPtr - (LPBYTE)pAceHeader);
    return pAceHeader;
}

void ACE_HELPER::Reset()
{
    DWORD dwFreeFlag = ACE_HELPER_NEED_FREE_SID0;

    // Free the SIDs
    for(size_t i = 0; i < _countof(Sid); i++, dwFreeFlag = dwFreeFlag << 1)
    {
        if((Sid[i] != NULL) && (FreeFlags & dwFreeFlag))
            RtlFreeSid(Sid[i]);
        Sid[i] = NULL;
    }

    // Free the condition
    if(Condition != NULL)
        delete[] Condition;
    Condition = NULL;

    // Free the security attributes
    if(AttrRel != NULL)
        delete [] AttrRel;
    AttrRel = NULL;

    // Reset everything to zero
    memset(this, 0, sizeof(ACE_HELPER));
}

LPBYTE ACE_HELPER::PutAceValue(LPBYTE PtrAclData, LPBYTE PtrAclEnd, PVOID PtrValue, DWORD dwLayoutMask, DWORD ValueSize)
{
    // Only if the value is present
    if(AceLayout & dwLayoutMask)
    {
        // Is there enough space in the ACL?
        if((DWORD)(PtrAclEnd - PtrAclData) < ValueSize)
            return NULL;

        // Copy the value
        memcpy(PtrAclData, PtrValue, ValueSize);
        PtrAclData += ValueSize;
    }

    // Return the new pointer
    return PtrAclData;
}

LPBYTE ACE_HELPER::PutAceValueSid(LPBYTE PtrAclData, LPBYTE PtrAclEnd, PSID pSourceSid)
{
    LPBYTE pbResult = NULL;
    ULONG SidLength;
    bool bFreeSid = false;

    // If no SID is given, create one with Everyone
    if(pSourceSid == NULL)
    {
        pSourceSid = CreateNewSid(AceType, SECURITY_MANDATORY_MEDIUM_RID);
        bFreeSid = true;
    }

    // If we have that SID, add it to the ACE data
    if(pSourceSid != NULL)
    {
        SidLength = RtlLengthSid(pSourceSid);

        if((PtrAclData + SidLength) <= PtrAclEnd)
        {
            memmove(PtrAclData, pSourceSid, SidLength);
            pbResult = PtrAclData + SidLength;
        }

        if(bFreeSid)
        {
            RtlFreeSid(pSourceSid);
        }
    }
    return pbResult;
}

LPBYTE ACE_HELPER::CaptureExtraStructure(LPBYTE pbPtr, LPBYTE pbEnd, size_t * pcbMoveBy)
{
    LPBYTE pbExtraStructure = NULL;
    size_t cbExtraStructure = 0;

    // Allocate copy of the values
    if(pbPtr < pbEnd)
    {
        if((pbExtraStructure = new BYTE[pbEnd - pbPtr]) != NULL)
        {
            memmove(pbExtraStructure, pbPtr, pbEnd - pbPtr);
            cbExtraStructure = pbEnd - pbPtr;
        }
    }

    // Give the values to the caller
    if(pcbMoveBy != NULL)
        pcbMoveBy[0] = cbExtraStructure;
    return pbExtraStructure;
}
