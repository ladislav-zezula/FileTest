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

static DWORD AceLayouts[] = 
{
/* 0x00 */ ACE_LAYOUT_SIMPLE,               // ACCESS_ALLOWED_ACE = {Header-Mask-SidStart}
/* 0x01 */ ACE_LAYOUT_SIMPLE,               // ACCESS_DENIED_ACE = {Header-Mask-SidStart}
/* 0x02 */ ACE_LAYOUT_SIMPLE,               // SYSTEM_AUDIT_ACE = {Header-Mask-SidStart}
/* 0x03 */ ACE_LAYOUT_SIMPLE,               // SYSTEM_ALARM_ACE = {Header-Mask-SidStart}

/* 0x04 */ ACE_LAYOUT_COMPOUND,             // COMPOUND_ACCESS_ALLOWED_ACE = {Header-Mask-CompoundType-Reserved-ServerSid-CliendSid}

/* 0x05 */ ACE_LAYOUT_OBJECT,               // ACCESS_ALLOWED_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart}
/* 0x06 */ ACE_LAYOUT_OBJECT,               // ACCESS_DENIED_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart}
/* 0x07 */ ACE_LAYOUT_OBJECT,               // SYSTEM_AUDIT_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart}
/* 0x08 */ ACE_LAYOUT_OBJECT,               // SYSTEM_ALARM_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart}

/* 0x09 */ ACE_LAYOUT_CONDITION,            // ACCESS_ALLOWED_CALLBACK_ACE = {Header-Mask-SidStart-Condition}
/* 0x0A */ ACE_LAYOUT_CONDITION,            // ACCESS_DENIED_CALLBACK_ACE = {Header-Mask-SidStart-Condition}
/* 0x0B */ ACE_LAYOUT_OBJECT_CONDITION,     // ACCESS_ALLOWED_CALLBACK_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart-Condition}
/* 0x0C */ ACE_LAYOUT_OBJECT_CONDITION,     // ACCESS_DENIED_CALLBACK_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart-Condition}
/* 0x0D */ ACE_LAYOUT_CONDITION,            // SYSTEM_AUDIT_CALLBACK_ACE = {Header-Mask-SidStart-Condition}
/* 0x0E */ ACE_LAYOUT_CONDITION,            // SYSTEM_ALARM_CALLBACK_ACE = {Header-Mask-SidStart-Condition}
/* 0x0F */ ACE_LAYOUT_OBJECT_CONDITION,     // SYSTEM_AUDIT_CALLBACK_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart-Condition}
/* 0x10 */ ACE_LAYOUT_OBJECT_CONDITION,     // SYSTEM_ALARM_CALLBACK_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart-Condition}

/* 0x11 */ ACE_LAYOUT_MANDATORY             // SYSTEM_MANDATORY_LABEL_ACE = {Header-MandatoryMask-MandatorySidStart}
};

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
    // Set the ACE layout. For unknown ACEs, just use header and access mask.
    if(dwAceType < _countof(AceLayouts))
        AceLayout = AceLayouts[dwAceType];
    else
        AceLayout = ACE_FIELD_HEADER | ACE_FIELD_ACCESS_MASK;

    // Remember the ACE layour and ACE type
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

        // Get the ACE condition. Example: C:\Program Files\WindowsApps\<any folder>
        if((AceLayout & ACE_FIELD_CONDITION) && (pbAcePtr < pbAceEnd))
        {
            if((ConditionLength = (DWORD)(pbAceEnd - pbAcePtr)) != 0)
            {
                if((Condition = new BYTE[ConditionLength]) != NULL)
                {
                    memcpy(Condition, pbAcePtr, ConditionLength);
                }
            }
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

PACE_HEADER ACE_HELPER::BuildAce(LPBYTE pbBuffer, size_t cbBuffer)
{
    PACE_HEADER pAceHeader = (PACE_HEADER)(pbBuffer);
    LPBYTE pbEnd = pbBuffer + cbBuffer;
    LPBYTE pbPtr = pbBuffer;
    ULONG GuidFlags = Flags;

    // We do not support ACEs with condition
    if((AceLayout & ACE_FIELD_CONDITION) && (Condition != NULL))
        return NULL;

    // Fill-in the header
    if(AceLayout & ACE_FIELD_HEADER)
    {
        if((pbPtr + sizeof(ACE_HEADER)) > pbEnd)
            return NULL;
        pAceHeader->AceType = (BYTE)AceType;
        pAceHeader->AceFlags = (BYTE)AceFlags;
        pAceHeader->AceSize = sizeof(ACE_HEADER);
        pbPtr += sizeof(ACE_HEADER);
    }

    // Fill-in the ACE:Mask
    pbPtr = PutAceValue(pbPtr, pbEnd, &Mask, (ACE_FIELD_ACCESS_MASK | ACE_FIELD_ADS_ACCESS_MASK | ACE_FIELD_MANDATORY_MASK), sizeof(ACCESS_MASK));
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
    pbPtr = PutAceValueSid(pbPtr, pbEnd, Sid[0], (ACE_FIELD_ACCESS_SID | ACE_FIELD_SERVER_SID));
    if(pbPtr == NULL)
        return NULL;

    // Fill-in the mandatory SID
    pbPtr = PutAceValueSid(pbPtr, pbEnd, Sid[0], ACE_FIELD_MANDATORY_SID);
    if(pbPtr == NULL)
        return NULL;

    // Fill-in the client SID
    pbPtr = PutAceValueSid(pbPtr, pbEnd, Sid[1], ACE_FIELD_CLIENT_SID);
    if(pbPtr == NULL)
        return NULL;

    //
    // TODO: Fill-in the condition
    //

    // Fixup the ACE size
    pAceHeader->AceSize = (WORD)(pbPtr - (LPBYTE)pAceHeader);
    return pAceHeader;
}

// Adds itself as an ACE to the ACL
bool ACE_HELPER::AddToAcl(PACL pAcl)
{
    PACE_HEADER pAceHeader;
    LPBYTE PtrAclData = (LPBYTE)(pAcl + 1);
    LPBYTE PtrAclEnd = (LPBYTE)pAcl + pAcl->AclSize;

    // Don't try to push in an unsupported ACE
    if(AceLayout == 0)
        return false;

    // Find the space after all present ACEs.
    for(BYTE i = 0; i < pAcl->AceCount; i++)
    {
        if(!GetAce(pAcl, i, (LPVOID *)&pAceHeader))
            return false;
        PtrAclData += pAceHeader->AceSize;
    }

    // Build the ACE in-place
    if((pAceHeader = BuildAce(PtrAclData, (PtrAclEnd - PtrAclData))) == NULL)
        return false;
    pAcl->AceCount = pAcl->AceCount + 1;

    // The ACL must have ACL_REVISION_DS if it contains any object ACEs
    // https://technet.microsoft.com/cs-cz/aa379293
    if(ACCESS_ALLOWED_OBJECT_ACE_TYPE <= pAceHeader->AceType && pAceHeader->AceType <= SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE)
        pAcl->AclRevision = ACL_REVISION_DS;
    return true;
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

LPBYTE ACE_HELPER::PutAceValueSid(LPBYTE PtrAclData, LPBYTE PtrAclEnd, PSID pSourceSid, DWORD dwLayoutMask)
{
    LPBYTE pbResult = PtrAclData;
    ULONG SidLength;
    bool bFreeSid = false;

    // Only if we have that SID present
    if(AceLayout & dwLayoutMask)
    {
        // Reset the return pointer for case it fails
        pbResult = NULL;

        // If no SID is given, create one with Everyone
        if(pSourceSid == NULL)
        {
            if(dwLayoutMask & ACE_FIELD_MANDATORY_SID)
            {
                pSourceSid = CreateMandatoryLabelSid();
                bFreeSid = true;
            }
            else
            {
                pSourceSid = CreateAccessSid();
                bFreeSid = true;
            }
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
    }
    return pbResult;
}

PSID ACE_HELPER::CreateAccessSid()
{
    SID_IDENTIFIER_AUTHORITY SiaWorld = SECURITY_WORLD_SID_AUTHORITY;
    PSID pSid = NULL;

    RtlAllocateAndInitializeSid(&SiaWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pSid);
    return pSid;
}

PSID ACE_HELPER::CreateMandatoryLabelSid()
{
    SID_IDENTIFIER_AUTHORITY SiaLabel = SECURITY_MANDATORY_LABEL_AUTHORITY;

    PSID pSid = NULL;

    RtlAllocateAndInitializeSid(&SiaLabel, 1, SECURITY_MANDATORY_MEDIUM_RID, 0, 0, 0, 0, 0, 0, 0, &pSid);
    return pSid;
}
