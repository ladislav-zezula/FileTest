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
        Sid_Free(Sid[nSidIndex]);
    Sid[nSidIndex] = NULL;

    // Store the new one
    if(pNewSid != NULL)
        Sid[nSidIndex] = pNewSid;

    // Update the flags in AceLayout
    FreeFlags = (pNewSid != NULL) ? (FreeFlags | dwFreeFlag) : (FreeFlags & ~dwFreeFlag);
}

// Adds itself as an ACE to the ACL
bool ACE_HELPER::AddToAcl(PACL pAcl)
{
    PACE_HEADER pAceHeader;
    LPBYTE PtrAclData = (LPBYTE)(pAcl + 1);
    LPBYTE PtrAclEnd = (LPBYTE)pAcl + pAcl->AclSize;

    // Don't try to push in an unsupported ACE
    if(AceType == ACCESS_ALLOWED_COMPOUND_ACE_TYPE || AceType > SYSTEM_MANDATORY_LABEL_ACE_TYPE)
        return false;

    // Find the space after all present ACEs.
    for(BYTE i = 0; i < pAcl->AceCount; i++)
    {
        if(!GetAce(pAcl, i, (LPVOID *)&pAceHeader))
            return false;
        PtrAclData += pAceHeader->AceSize;
    }

    // Now we have the pointer to the ACE. Insert it there
    pAceHeader = (PACE_HEADER)PtrAclData;
    if((PtrAclEnd - PtrAclData) < sizeof(ACE_HEADER))
        return false;

    // Fill-in the header
    pAceHeader->AceType  = (BYTE)AceType;
    pAceHeader->AceFlags = (BYTE)AceFlags;
    pAceHeader->AceSize  = sizeof(ACE_HEADER);
    PtrAclData = (LPBYTE)(pAceHeader + 1);

    // Fill-in the mask
    PtrAclData = PutAceValue(PtrAclData, PtrAclEnd, &Mask, (ACE_FIELD_ACCESS_MASK | ACE_FIELD_ADS_ACCESS_MASK | ACE_FIELD_MANDATORY_MASK), sizeof(ACCESS_MASK));
    if(PtrAclData == NULL)
        return false;

    // Fill-in the ACE::flags
    if(AceLayout & ACE_FIELD_FLAGS)
    {
        // If we have the object, get the ACE_OBJECT_TYPE_PRESENT flag there
        if(!(ObjectType == NullGuid))
            Flags |= ACE_OBJECT_TYPE_PRESENT;
        if(!(InheritedObjectType == NullGuid))
            Flags |= ACE_INHERITED_OBJECT_TYPE_PRESENT;

        PtrAclData = PutAceValue(PtrAclData, PtrAclEnd, &Flags, ACE_FIELD_FLAGS, sizeof(DWORD));
        if(PtrAclData == NULL)
            return false;
    }                             

    // Fill-in the object type, only if the ACE_OBJECT_TYPE_PRESENT is present in the ACE::Flags
    if(Flags & ACE_OBJECT_TYPE_PRESENT)
    {
        PtrAclData = PutAceValue(PtrAclData, PtrAclEnd, &ObjectType, ACE_FIELD_OBJECT_TYPE1, sizeof(GUID));
        if(PtrAclData == NULL)
            return false;
    }

    // Fill-in the inherited object type, only if the ACE_INHERITED_OBJECT_TYPE_PRESENT is present in the ACE::Flags
    if(Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
    {
        // Fill-in the inherited object type
        PtrAclData = PutAceValue(PtrAclData, PtrAclEnd, &InheritedObjectType, ACE_FIELD_OBJECT_TYPE2, sizeof(GUID));
        if(PtrAclData == NULL)
            return false;
    }

    // Fill-in the (server, mandatory) SID
    if(AceLayout & (ACE_FIELD_ACCESS_SID | ACE_FIELD_SERVER_SID | ACE_FIELD_MANDATORY_SID))
    {
        PtrAclData = PutAceValue(PtrAclData, PtrAclEnd, Sid[0], (ACE_FIELD_ACCESS_SID | ACE_FIELD_SERVER_SID | ACE_FIELD_MANDATORY_SID), GetLengthSid(Sid[0]));
        if(PtrAclData == NULL)
            return false;
    }

    // Fill-in the client SID
    if(AceLayout & ACE_FIELD_CLIENT_SID)
    {
        PtrAclData = PutAceValue(PtrAclData, PtrAclEnd, Sid[1], ACE_FIELD_SERVER_SID, GetLengthSid(Sid[1]));
        if(PtrAclData == NULL)
            return false;
    }

    // TODO: Fill-in the extra data

    // The ACL must have ACL_REVISION_DS if it contains any object ACEs
    // https://technet.microsoft.com/cs-cz/aa379293
    if(ACCESS_ALLOWED_OBJECT_ACE_TYPE <= AceType && AceType <= SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE)
        pAcl->AclRevision = ACL_REVISION_DS;

    // Get the size of the ACE
    pAceHeader->AceSize = (WORD)(PtrAclData - (LPBYTE)pAceHeader);
    pAcl->AceCount = pAcl->AceCount + 1;
    return true;
}

void ACE_HELPER::Reset()
{
    DWORD dwFreeFlag = ACE_HELPER_NEED_FREE_SID0;

    // Free the SIDs
    for(size_t i = 0; i < _countof(Sid); i++, dwFreeFlag = dwFreeFlag << 1)
    {
        if((Sid[i] != NULL) && (FreeFlags & dwFreeFlag))
            FreeSid(Sid[i]);
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
