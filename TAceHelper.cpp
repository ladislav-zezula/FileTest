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
    ACE_LAYOUT_SIMPLE,                      // ACCESS_ALLOWED_ACE = {Header-Mask-SidStart}
    ACE_LAYOUT_SIMPLE,                      // ACCESS_DENIED_ACE = {Header-Mask-SidStart}
    ACE_LAYOUT_SIMPLE,                      // SYSTEM_AUDIT_ACE = {Header-Mask-SidStart}
    ACE_LAYOUT_SIMPLE,                      // SYSTEM_ALARM_ACE = {Header-Mask-SidStart}

    ACE_LAYOUT_UNKNOWN,                     // ACCESS_ALLOWED_COMPOUND_ACE = Unknown layout

    ACE_LAYOUT_OBJECT,                      // ACCESS_ALLOWED_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart}
    ACE_LAYOUT_OBJECT,                      // ACCESS_DENIED_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart}
    ACE_LAYOUT_OBJECT,                      // SYSTEM_AUDIT_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart}
    ACE_LAYOUT_OBJECT,                      // SYSTEM_ALARM_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart}

    ACE_LAYOUT_SIMPLE2,                     // ACCESS_ALLOWED_CALLBACK_ACE = {Header-Mask-SidStart-OpaqueResMgrData}
    ACE_LAYOUT_SIMPLE2,                     // ACCESS_DENIED_CALLBACK_ACE = {Header-Mask-SidStart-OpaqueResMgrData}
    ACE_LAYOUT_OBJECT2,                     // ACCESS_ALLOWED_CALLBACK_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart-OpaqueResMgrData}
    ACE_LAYOUT_OBJECT2,                     // ACCESS_DENIED_CALLBACK_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart-OpaqueResMgrData}
    ACE_LAYOUT_SIMPLE2,                     // SYSTEM_AUDIT_CALLBACK_ACE = {Header-Mask-SidStart-OpaqueResMgrData}
    ACE_LAYOUT_SIMPLE2,                     // SYSTEM_ALARM_CALLBACK_ACE = {Header-Mask-SidStart-OpaqueResMgrData}
    ACE_LAYOUT_OBJECT2,                     // SYSTEM_AUDIT_CALLBACK_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart-OpaqueResMgrData}
    ACE_LAYOUT_OBJECT2,                     // SYSTEM_ALARM_CALLBACK_OBJECT_ACE = {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart-OpaqueResMgrData}

    ACE_LAYOUT_MANDATORY                    // SYSTEM_MANDATORY_LABEL_ACE = {Header-MandatoryMask-MandatorySidStart}
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
    SetAllocatedSid(NULL);
}

//-----------------------------------------------------------------------------
// Public functions

// In Page09Security.cpp
void Sid_Free(PSID pSid);

bool ACE_HELPER::SetAceType(DWORD dwAceType)
{
    // Verify ACE type and set the ACE layout
    if(dwAceType > SYSTEM_MANDATORY_LABEL_ACE_TYPE || AceLayouts[dwAceType] == ACE_LAYOUT_UNKNOWN)
        return false;

    // Remember the ACE layour and ACE type
    AceLayout = AceLayouts[dwAceType];
    AceType = (BYTE)dwAceType;
    return true;
}

bool ACE_HELPER::SetAce(PACE_HEADER pAceHeader)
{
    LPBYTE PtrAceData;
    bool bResult;

    // Verify ACE type and set the ACE layout
    bResult = SetAceType(pAceHeader->AceType);
    if(bResult)
    {
        // Fill-in the header (always included)
        AceFlags = pAceHeader->AceFlags;
        AceSize  = pAceHeader->AceSize;

        // Now get ready for variable ACE layouts
        PtrAceData = (LPBYTE)(pAceHeader + 1);

        // Is there the ACE::Mask?
        if(AceLayout & (ACE_FIELD_ACCESS_MASK | ACE_FIELD_ADS_ACCESS_MASK | ACE_FIELD_MANDATORY_MASK))
        {
            Mask = *(PDWORD)PtrAceData;
            PtrAceData += sizeof(DWORD);
        }

        // Is there the ACE::Flags
        if(AceLayout & ACE_FIELD_FLAGS)
        {
            // Copy the ACE::Flags
            Flags = *(PDWORD)PtrAceData;
            PtrAceData += sizeof(DWORD);

            // ACE::ObjectType is only present if ACE_OBJECT_TYPE_PRESENT is in the flags
            if(Flags & ACE_OBJECT_TYPE_PRESENT)
            {
                memcpy(&ObjectType, PtrAceData, sizeof(GUID));
                PtrAceData += sizeof(GUID);
            }

            // Is there the ACE::InheritedObjectType?
            if(Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
            {
                memcpy(&InheritedObjectType, PtrAceData, sizeof(GUID));
                PtrAceData += sizeof(GUID);
            }
        }

        // Get the pointer to SID
        if(AceLayout & (ACE_FIELD_ACCESS_SID | ACE_FIELD_MANDATORY_SID))
        {
            Sid = (PSID)PtrAceData;
            AceLayout &= ~ACE_FIELD_NEED_FREE_SID;
        }
    }

    return bResult;
}

// pSid could be NULL if we want just to free the existing SID
void ACE_HELPER::SetAllocatedSid(PSID pSid)
{
    // Free the old SID
    if((Sid != NULL) && (AceLayout & ACE_FIELD_NEED_FREE_SID))
        Sid_Free(Sid);
    Sid = NULL;

    // Store the new one
    AceLayout = (pSid != NULL) ? (AceLayout | ACE_FIELD_NEED_FREE_SID) : (AceLayout & ~ACE_FIELD_NEED_FREE_SID);
    Sid = pSid;
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
        PtrAclData = PutAceValue(PtrAclData, PtrAclEnd, &ObjectType, ACE_FIELD_OBJECT_TYPE, sizeof(GUID));
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

    // Fill-in the SID
    PtrAclData = PutAceValue(PtrAclData, PtrAclEnd, Sid, (ACE_FIELD_ACCESS_SID | ACE_FIELD_MANDATORY_SID), GetLengthSid(Sid));
    if(PtrAclData == NULL)
        return false;
    
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
    memset(&AceType, 0, FIELD_OFFSET(ACE_HELPER, Sid) - FIELD_OFFSET(ACE_HELPER, AceType));
    SetAllocatedSid(NULL);
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
