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

// SID_IDENTIFIER_AUTHORITY SiaWorld = SECURITY_WORLD_SID_AUTHORITY;
const BYTE SidEveryone[0x0C]  = {0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};

// SID_IDENTIFIER_AUTHORITY SiaWorld = SECURITY_NT_AUTHORITY;
const BYTE SidLocAdmins[0x10] = {0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00};

// SID_IDENTIFIER_AUTHORITY SiaWorld = SECURITY_NT_AUTHORITY;
const BYTE SidLocUsers[0x10] = {0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x21, 0x02, 0x00, 0x00};

// SID_IDENTIFIER_AUTHORITY SiaLabel = SECURITY_MANDATORY_LABEL_AUTHORITY;
const BYTE SidLabelMedium[0x0C] = {0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00};

// SID_IDENTIFIER_AUTHORITY SiaPolicy = SECURITY_SCOPED_POLICY_ID_AUTHORITY;
const BYTE SidSystemAce17[0x0C] = {0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00};

// SID_IDENTIFIER_AUTHORITY SiaTrust = SECURITY_PROCESS_TRUST_AUTHORITY;
const BYTE SidSystemAce19[0x10] = {0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x02, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00};

// Dummy condition for various reasons
// Obtained from "c:\Program Files\WindowsApps\Microsoft.ZuneMusic_11.2310.8.0_neutral_~_8wekyb3d8bbwe" 
static const BYTE DummyCondition[] =
{
    0x61, 0x72, 0x74, 0x78, 0xf8, 0x1c, 0x00, 0x00, 0x00, 0x57, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x3a,
    0x00, 0x2f, 0x00, 0x2f, 0x00, 0x53, 0x00, 0x59, 0x00, 0x53, 0x00, 0x41, 0x00, 0x50, 0x00, 0x50,
    0x00, 0x49, 0x00, 0x44, 0x00, 0x10, 0x42, 0x00, 0x00, 0x00, 0x4d, 0x00, 0x69, 0x00, 0x63, 0x00,
    0x72, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x66, 0x00, 0x74, 0x00, 0x2e, 0x00, 0x5a, 0x00,
    0x75, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x56, 0x00, 0x69, 0x00, 0x64, 0x00, 0x65, 0x00, 0x6f, 0x00,
    0x5f, 0x00, 0x38, 0x00, 0x77, 0x00, 0x65, 0x00, 0x6b, 0x00, 0x79, 0x00, 0x62, 0x00, 0x33, 0x00,
    0x64, 0x00, 0x38, 0x00, 0x62, 0x00, 0x62, 0x00, 0x77, 0x00, 0x65, 0x00, 0x86, 0x00, 0x00, 0x00
};

//-----------------------------------------------------------------------------
// Constructor and destructor

ACE_HELPER::ACE_HELPER(DWORD dwAceType, PSID pSid)
{
    // Set the object to default values
    memset(this, 0, sizeof(ACE_HELPER));
    Mask = INVALID_ACCESS_MASK;

    // Set the ACE type
    SetAceType(dwAceType);

    // Put the main SID. If not provided, choose a default SID
    if(pSid == NULL)
        pSid = GetDefaultSid(dwAceType);
    SetSid(pSid, 0);
}

ACE_HELPER::ACE_HELPER(ACE_CSA_HELPER & CsaHelper, PSID pSid)
{
    // Set the object to default values
    memset(this, 0, sizeof(ACE_HELPER));

    // Set the ACE type. Prevent construction of ACE resource
    AceType = SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE;
    Mask = FILE_READ_DATA;

    // Set the default SID
    pSid = (pSid != NULL) ? pSid : (PSID)(SidEveryone);
    SetSid(pSid, 0);

    // Set the resource
    SetResource(CsaHelper);
}

ACE_HELPER::~ACE_HELPER()
{
    Reset();
}

void ACE_HELPER::Reset()
{
    // Free the SIDs
    for(size_t i = 0; i < _countof(Sid); i++)
    {
        if(Sid[i] != NULL)
            LocalFree(Sid[i]);
        Sid[i] = NULL;
    }

    // Free the condition
    if(Condition != NULL)
        delete[] Condition;
    Condition = NULL;

    // Free the security attributes
    if(AttrRel != NULL)
        delete[] AttrRel;
    AttrRel = NULL;

    // Reset everything to zero
    memset(this, 0, sizeof(ACE_HELPER));

    // Set to default values
    AceType = ACCESS_ALLOWED_ACE_TYPE;
    Mask    = GENERIC_ALL;
    Sid[0]  = (PSID)(SidEveryone);
    Sid[1]  = (PSID)(SidLocAdmins);
}

//-----------------------------------------------------------------------------
// Public functions

bool ACE_HELPER::SetAceType(DWORD dwAceType)
{
    // Set the ACE type
    AceType = (BYTE)(dwAceType);

    // Perform ACE-specific initialization
    switch(dwAceType)
    {
        case ACCESS_ALLOWED_ACE_TYPE:                       // Simple ACEs:
        case ACCESS_DENIED_ACE_TYPE:                        // {Header-Mask-SidStart}
        case SYSTEM_AUDIT_ACE_TYPE:
        case SYSTEM_ALARM_ACE_TYPE:
            Mask = (Mask != INVALID_ACCESS_MASK) ? Mask : GENERIC_ALL;
            AceLayout = ACE_LAYOUT_SIMPLE;
            break;

        case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:              // Compound ACEs:
            Mask = (Mask != INVALID_ACCESS_MASK) ? Mask : GENERIC_ALL;
            CompoundAceType |= COMPOUND_ACE_IMPERSONATION;
            AceLayout = ACE_LAYOUT_COMPOUND;                // {Header-Mask-CompoundType-Reserved-ServerSid-CliendSid}
            SetSid(SidEveryone, 1);
            break;

        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:                // Object ACEs:
        case ACCESS_DENIED_OBJECT_ACE_TYPE:                 // {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart-Condition}
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
        case SYSTEM_ALARM_OBJECT_ACE_TYPE:
            Mask = (Mask != INVALID_ACCESS_MASK) ? Mask : ADS_RIGHT_DS_READ_PROP;
            AceLayout = ACE_LAYOUT_OBJECT;
            break;

        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:              // Conditional ACEs:
        case ACCESS_DENIED_CALLBACK_ACE_TYPE:               // {Header-Mask-SidStart-Condition}
        case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
        case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
            Mask = (Mask != INVALID_ACCESS_MASK) ? Mask : GENERIC_ALL;
            AceLayout = ACE_LAYOUT_CONDITION;
            SetCondition(DummyCondition, sizeof(DummyCondition));
            break;

        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:       // Conditional object ACEs:
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:        // {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart-Condition}
        case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
        case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
            Mask = (Mask != INVALID_ACCESS_MASK) ? Mask : GENERIC_ALL;
            AceLayout = ACE_LAYOUT_OBJECT_CONDITION;
            SetCondition(DummyCondition, sizeof(DummyCondition));
            break;

        case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
            Mask = (Mask != INVALID_ACCESS_MASK) ? Mask : SYSTEM_MANDATORY_LABEL_NO_WRITE_UP;
            AceLayout = ACE_LAYOUT_MANDATORY;
            break;

        case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
            Mask = (Mask != INVALID_ACCESS_MASK) ? Mask : FILE_READ_DATA;
            if(AttrRel == NULL)
                SetDummyResource();
            AceLayout = ACE_LAYOUT_RESOURCE;                // Contains the CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 structure
            break;

        case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
            Mask = (Mask != INVALID_ACCESS_MASK) ? Mask : FILE_READ_DATA;
            AceLayout = ACE_LAYOUT_POLICY_ID;
            AceFlags |= INHERIT_ONLY_ACE;
            break;

        case SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE:
            Mask = (Mask != INVALID_ACCESS_MASK) ? Mask : FILE_READ_DATA;
            AceLayout = ACE_LAYOUT_TRUST_ID;
            AceFlags |= INHERIT_ONLY_ACE;
            break;

        case SYSTEM_ACCESS_FILTER_ACE_TYPE:
            Mask = (Mask != INVALID_ACCESS_MASK) ? Mask : FILE_READ_DATA;
            AceLayout = ACE_LAYOUT_TRUST_ID_CONDITION;
            AceFlags |= TRUST_PROTECTED_FILTER_ACE_FLAG;
            SetCondition(DummyCondition, sizeof(DummyCondition));
            break;

        default:    // Unknown ACE type. Just assume ACE_HEADER and AccessMask
            Mask = (Mask != INVALID_ACCESS_MASK) ? Mask : GENERIC_ALL;
            AceLayout = ACE_FIELD_HEADER | ACE_FIELD_ACCESS_MASK;
            break;
    }
    return true;
}

bool ACE_HELPER::SetAce(PACE_HEADER pAceHeader)
{
    PSID pSid;
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
        if(AceLayout & (ACE_FIELD_COMPOUND_TYPE | ACE_FIELD_COMPOUND_RSVD))
        {
            CompoundAceType = *(PUSHORT)(pbAcePtr);
            CompoundReserved = *(PUSHORT)(pbAcePtr + sizeof(USHORT));
            pbAcePtr += sizeof(USHORT) + sizeof(USHORT);
        }

        // Get the pointer to (server|mandatory) SID
        if(AceLayout & (ACE_FIELD_SID | ACE_FIELD_MANDATORY_SID | ACE_FIELD_MANDATORY_MASK))
        {
            if((pSid = SetSid(pbAcePtr, 0)) != NULL)
                pbAcePtr += GetLengthSid(pSid);
        }

        // Get the pointer to (server|mandatory) SID
        if(AceLayout & ACE_FIELD_CLIENT_SID)
        {
            if((pSid = SetSid(pbAcePtr, 1)) != NULL)
                pbAcePtr += GetLengthSid(pSid);
        }

        // Get the CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 and convert it to pointer-based structure
        if((AceLayout & ACE_FIELD_CSA_V1) && (pbAcePtr < pbAceEnd))
        {
            if(SetResource(pbAcePtr, (pbAceEnd - pbAcePtr)))
                pbAcePtr += AttrRelLength;
        }

        // Get the ACE condition. Example: C:\Program Files\WindowsApps\<any folder>
        if((AceLayout & ACE_FIELD_CONDITION) && (pbAcePtr < pbAceEnd))
        {
            if(SetCondition(pbAcePtr, (pbAceEnd - pbAcePtr)))
                pbAcePtr += ConditionLength;
        }
    }
    return bResult;
}

// pSid could be NULL if we want just to free the existing SID[nSidIndex]
PSID ACE_HELPER::SetSid(LPCVOID lpSid, size_t nSidIndex)
{
    PSID pSid = (PSID)(lpSid);
    ULONG cbSid;

    // Free the old SID
    if(Sid[nSidIndex] != NULL)
        LocalFree(Sid[nSidIndex]);
    Sid[nSidIndex] = NULL;

    // Store the new one
    if(pSid != NULL && (cbSid = RtlLengthSid(pSid)) != 0)
    {
        if((Sid[nSidIndex] = (PSID)LocalAlloc(LPTR, cbSid)) != NULL)
        {
            memcpy(Sid[nSidIndex], pSid, cbSid);
        }
    }

    // Return the new SID
    return Sid[nSidIndex];
}

bool ACE_HELPER::SetResource(LPCVOID lpAttrRel, size_t cbAttrRel)
{
    LPBYTE pbAttrRel = (LPBYTE)(lpAttrRel);

    AttrRel = CaptureExtraStructure(pbAttrRel, pbAttrRel + cbAttrRel, &AttrRelLength);
    return (AttrRel && AttrRelLength);
}

bool ACE_HELPER::SetCondition(LPCVOID lpCondition, size_t cbCondition)
{
    LPBYTE pbCondition = (LPBYTE)(lpCondition);

    Condition = CaptureExtraStructure(pbCondition, pbCondition + cbCondition, &ConditionLength);
    return (Condition && ConditionLength);
}

bool ACE_HELPER::SetResource(ACE_CSA_HELPER & CsaHelper)
{
    PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 pAttrRel;
    ULONG cbAttrRel = 0;
    bool bResult = false;

    // Export the resource object
    if((pAttrRel = CsaHelper.Export(&cbAttrRel)) != NULL)
    {
        bResult = SetResource(pAttrRel, cbAttrRel);
        LocalFree(pAttrRel);
    }
    return bResult;
}

bool ACE_HELPER::SetDummyResource()
{
    ACE_CSA_HELPER CsaHelper;

    // Construct the resource object
    CsaHelper.Create(L"RESOURCE_STRINGS", CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING, 4, L"Daenerys", L"Targaryen", L"Tyrion", L"Lannister");
    CsaHelper.Flags = CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;
    return SetResource(CsaHelper);
}

PACE_HEADER ACE_HELPER::Export(LPBYTE pbBuffer, size_t cbBuffer)
{
    PACE_HEADER pAceHeader = (PACE_HEADER)(pbBuffer);
    LPBYTE pbEnd = pbBuffer + cbBuffer;
    LPBYTE pbPtr = pbBuffer;
    ULONG GuidFlags = Flags;

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
    pbPtr = PutAceValue(pbPtr, pbEnd, &Mask, (ACE_FIELD_ACCESS_MASK | ACE_FIELD_ADS_ACCESS_MASK | ACE_FIELD_MANDATORY_MASK), sizeof(ACCESS_MASK));
    if(pbPtr == NULL)
        return NULL;

    // Fill-in the ACE::Flags
    pbPtr = PutAceValue(pbPtr, pbEnd, &GuidFlags, ACE_FIELD_FLAGS, sizeof(GuidFlags));
    if(pbPtr == NULL)
        return NULL;

    // Fill-in the ACE::CompoundAceType
    pbPtr = PutAceValue(pbPtr, pbEnd, &CompoundAceType, ACE_FIELD_COMPOUND_TYPE, sizeof(CompoundAceType));
    if(pbPtr == NULL)
        return NULL;

    // Fill-in the ACE::CompoundReserved
    pbPtr = PutAceValue(pbPtr, pbEnd, &CompoundReserved, ACE_FIELD_COMPOUND_RSVD, sizeof(CompoundReserved));
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

    // Fill-in the (server, mandatory, policy, trust) SID
    if(AceLayout & ACE_FIELD_PRIMARY_SID_MASK)
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

    // Fill-in the CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1
    if(AceLayout & ACE_FIELD_CSA_V1)
    {
        if((pbPtr = PutAceValueBinary(pbPtr, pbEnd, AttrRel, AttrRelLength)) == NULL)
            return NULL;
    }

    // Fill-in the CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1
    if((AceLayout & ACE_FIELD_CONDITION) && (Condition != NULL))
    {
        if((pbPtr = PutAceValueBinary(pbPtr, pbEnd, Condition, ConditionLength)) == NULL)
            return NULL;
    }

    // Fixup the ACE size
    pAceHeader->AceSize = (WORD)(pbPtr - (LPBYTE)pAceHeader);
    return pAceHeader;
}

PACE_HEADER ACE_HELPER::AddToAcl(PACL pAcl)
{
    PACE_HEADER pAceHeader;
    PACE_HEADER pTemp = NULL;
    LPBYTE pbPtr = (LPBYTE)(pAcl) + sizeof(ACL);
    LPBYTE pbEnd = (LPBYTE)(pAcl) + pAcl->AclSize;

    // Skip all ACEs
    if(pAcl->AceCount > 0)
    {
        RtlGetAce(pAcl, pAcl->AceCount - 1, (PVOID *)(&pTemp));
        pbPtr = (LPBYTE)(pTemp) + pTemp->AceSize;
    }

    // Build the ACE
    if((pAceHeader = Export(pbPtr, pbEnd - pbPtr)) != NULL)
        pAcl->AceCount++;
    return pAceHeader;
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

    // If no SID is given, create one with Everyone
    if(pSourceSid == NULL)
        pSourceSid = GetDefaultSid(AceType);

    // If we have that SID, add it to the ACE data
    if(pSourceSid != NULL)
    {
        SidLength = RtlLengthSid(pSourceSid);

        if((PtrAclData + SidLength) <= PtrAclEnd)
        {
            memmove(PtrAclData, pSourceSid, SidLength);
            pbResult = PtrAclData + SidLength;
        }
    }
    return pbResult;
}

LPBYTE ACE_HELPER::PutAceValueBinary(LPBYTE PtrAclData, LPBYTE PtrAclEnd, LPVOID lpData, size_t cbData)
{
    LPBYTE pbResult = NULL;

    // If we have that SID, add it to the ACE data
    if(lpData && cbData)
    {
        if((PtrAclData + cbData) <= PtrAclEnd)
        {
            memmove(PtrAclData, lpData, cbData);
            pbResult = PtrAclData + cbData;
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

PSID ACE_HELPER::GetDefaultSid(DWORD dwAceType, DWORD dwAceFlags)
{
    switch(dwAceType)
    {
        case SYSTEM_MANDATORY_LABEL_ACE_TYPE:       // Mandatory label ACE requires S-1-16-###
            return (PSID)(SidLabelMedium);

        case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:      // System scoped policy requires S-1-17-###
            return (PSID)(SidSystemAce17);

        case SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE:   // System process trust label requires S-1-19-###
            return (PSID)(SidSystemAce19);

        // When Flags don't contain TRUST_PROTECTED_FILTER_ACE_FLAG (0x40), the SID must be Everyone,
        //   which means the system simply filters access according to the callback condition.
        // When Flags contain TRUST_PROTECTED_FILTER_ACE_FLAG, the SID must represent a trust level
        //   (S-1-19-x-y). In this case, the system performs access filtration according to the condition
        //   only when the caller's trust is lower. In other words, a trust-protected Access Filter ACE
        //   works as a Trust Label Callback ACE would.
        case SYSTEM_ACCESS_FILTER_ACE_TYPE:
            if(dwAceFlags & TRUST_PROTECTED_FILTER_ACE_FLAG)
                return (PSID)(SidSystemAce19);
            // Go default into SidEveryone

        default:
            return (PSID)(SidEveryone);
    }
}
