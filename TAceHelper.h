/*****************************************************************************/
/* TAceHelper.h                           Copyright (c) Ladislav Zezula 2016 */
/*---------------------------------------------------------------------------*/
/* Interface for the ACE helper class                                        */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 26.03.16  1.00  Lad  The first version of TAceHelper.h                    */
/*****************************************************************************/

#ifndef __TACEHELPER_H__
#define __TACEHELPER_H__

//-----------------------------------------------------------------------------
// Definitions

// Flags for fields included
#define ACE_FIELD_HTYPE             0x00000001      // ACE_HEADER::AceType  (always included)
#define ACE_FIELD_HFLAGS            0x00000002      // ACE_HEADER::AceFlags for all ACEs except SYSTEM_ACCESS_FILTER_ACE
#define ACE_FIELD_HFLAGS2           0x00000004      // ACE_HEADER::AceFlags for SYSTEM_ACCESS_FILTER_ACE
#define ACE_FIELD_HSIZE             0x00000008      // ACE_HEADER::AceSize  (always included)
#define ACE_FIELD_ACCESS_MASK       0x00000010      // ACE::Mask
#define ACE_FIELD_ADS_ACCESS_MASK   0x00000020      // ACE::Mask for ADS ACEs
#define ACE_FIELD_MANDATORY_MASK    0x00000040      // SYSTEM_MANDATORY_LABEL_ACE::Mask
#define ACE_FIELD_GUID_FLAGS        0x00000080      // Flags for ObjectType and InheritedObjectType
#define ACE_FIELD_COMPOUND_TYPE     0x00000100      // COMPOUND_ACCESS_ALLOWED_ACE::CompoundAceType
#define ACE_FIELD_COMPOUND_RSVD     0x00000200      // COMPOUND_ACCESS_ALLOWED_ACE::Reserved
#define ACE_FIELD_OBJECT_TYPE1      0x00000400      // XXX_YYY_OBJECT_ACE::ObjectType
#define ACE_FIELD_OBJECT_TYPE2      0x00000800      // XXX_YYY_OBJECT_ACE::InheritedObjectType
#define ACE_FIELD_SID               0x00001000      // ACE::SidStart contains a (server) SID
#define ACE_FIELD_MANDATORY_SID     0x00002000      // ACE::SidStart contains a mandatory label SID
#define ACE_FIELD_POLICY_SID        0x00004000      // ACE::SidStart contains a Policy ID SID
#define ACE_FIELD_TRUST_SID         0x00008000      // ACE::SidStart contains a trust SID
#define ACE_FIELD_TRUST_SID_E       0x00010000      // ACE::SidStart contains a trust SID or Everyone
#define ACE_FIELD_CLIENT_SID        0x00020000      // ACE::SidStart contains a client SID
#define ACE_FIELD_CSA_V1            0x00040000      // Contains the CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 structure
#define ACE_FIELD_CONDITION         0x00080000      // Contains the ACE condition

#define ACE_FIELD_PRIMARY_SID_MASK (ACE_FIELD_SID|ACE_FIELD_MANDATORY_SID|ACE_FIELD_POLICY_SID|ACE_FIELD_TRUST_SID|ACE_FIELD_TRUST_SID_E)

// Multi flags that are always together
#define ACE_FIELD_HEADER            (ACE_FIELD_HTYPE|ACE_FIELD_HFLAGS|ACE_FIELD_HSIZE)

// Flags for free fields
#define ACE_HELPER_NEED_FREE_SID0   0x00000001      // The ACE_HELPER::Sid[0] needs to be freed using Sid_Free
#define ACE_HELPER_NEED_FREE_SID1   0x00000002      // The ACE_HELPER::Sid[1] needs to be freed using Sid_Free

// Unknown ACE layout (ACCESS_ALLOWED_COMPOUND_ACE)
#define ACE_LAYOUT_UNKNOWN   (0)

// Flag combinations for {Header-Mask-SidStart} ACEs
#define ACE_LAYOUT_SIMPLE     (ACE_FIELD_HEADER | ACE_FIELD_ACCESS_MASK | ACE_FIELD_SID)

//
#define ACE_LAYOUT_COMPOUND   (ACE_FIELD_HEADER | ACE_FIELD_ACCESS_MASK | ACE_FIELD_COMPOUND_TYPE | ACE_FIELD_COMPOUND_RSVD | ACE_FIELD_SID | ACE_FIELD_CLIENT_SID)

// ACE layout for {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart}
#define ACE_LAYOUT_OBJECT     (ACE_FIELD_HEADER | ACE_FIELD_ADS_ACCESS_MASK | ACE_FIELD_GUID_FLAGS | ACE_FIELD_OBJECT_TYPE1 | ACE_FIELD_OBJECT_TYPE2 | ACE_FIELD_SID)

// Flag combinations for {Header-Mask-SidStart-Condition} ACEs
#define ACE_LAYOUT_CONDITION  (ACE_FIELD_HEADER | ACE_FIELD_ACCESS_MASK | ACE_FIELD_SID | ACE_FIELD_CONDITION)

// Flag combinations for {Header-Mask-Flags-ObjectType-InheritedObjectType-SidStart-Condition} ACEs
#define ACE_LAYOUT_OBJECT_CONDITION  (ACE_FIELD_HEADER | ACE_FIELD_ADS_ACCESS_MASK | ACE_FIELD_GUID_FLAGS | ACE_FIELD_OBJECT_TYPE1 | ACE_FIELD_OBJECT_TYPE2 | ACE_FIELD_SID | ACE_FIELD_CONDITION)

// ACE Layout for SYSTEM_MANDATORY_LABEL_ACE_TYPE
#define ACE_LAYOUT_MANDATORY  (ACE_FIELD_HEADER | ACE_FIELD_MANDATORY_MASK | ACE_FIELD_MANDATORY_SID)

// ACE layout for SYSTEM_RESOURCE_ATTRIBUTE_ACE
#define ACE_LAYOUT_RESOURCE   (ACE_FIELD_HEADER | ACE_FIELD_ACCESS_MASK | ACE_FIELD_SID | ACE_FIELD_CSA_V1)

// ACE layout for SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
#define ACE_LAYOUT_POLICY_ID  (ACE_FIELD_HEADER | ACE_FIELD_ACCESS_MASK | ACE_FIELD_POLICY_SID)

// ACE layout for SYSTEM_PROCESS_TRUST_LABEL_ACE
#define ACE_LAYOUT_TRUST_ID  (ACE_FIELD_HEADER | ACE_FIELD_ACCESS_MASK | ACE_FIELD_TRUST_SID)

// ACE layout for SYSTEM_ACCESS_FILTER_ACE
#define ACE_LAYOUT_TRUST_ID_CONDITION  (ACE_FIELD_HTYPE | ACE_FIELD_HFLAGS2 | ACE_FIELD_HSIZE | ACE_FIELD_ACCESS_MASK | ACE_FIELD_TRUST_SID_E | ACE_FIELD_CONDITION)

// An invalid ACCESS_MASK
#define INVALID_ACCESS_MASK   0xFFFFFFFF

//-----------------------------------------------------------------------------
// Common structure of an ACE with GUID flags

typedef struct _ACE
{
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD Flags;
    // Followed by more fields, depending on the ACE type
} ACE, *PACE;

//-----------------------------------------------------------------------------
// External variables

extern const BYTE SidEveryone[0x0C];
extern const BYTE SidLocUsers[0x10];
extern const BYTE SidLocAdmins[0x10];
extern const BYTE SidLabelMedium[0x0C];
extern const BYTE SidSystemAce17[0x0C];
extern const BYTE SidSystemAce19[0x10];

//-----------------------------------------------------------------------------
// Interface for the ACE_HELPER class

struct ACE_HELPER
{
    // Constructors and destructors
    ACE_HELPER(DWORD dwAceType = ACCESS_ALLOWED_ACE_TYPE, PSID pSid = NULL);
    ACE_HELPER(DWORD dwAceType, ACCESS_MASK AccessMask, PSID pSid = NULL);
    ACE_HELPER(const ACE_CSA_HELPER & CsaHelper, PSID pSid = NULL);
    ~ACE_HELPER();

    void Init(DWORD dwAceType, ACCESS_MASK AccessMask, PSID pSid1, PSID pSid2);

    bool SetAceType(DWORD dwAceType);                   // Sets a new ACE type
    bool SetAce(PACE_HEADER pAceHeader);                // Stores an ACE
    PSID SetSid(LPCVOID lpSid, size_t nSidIndex);       // Stores a SID that needs to be freed
    bool SetResource(LPCVOID lpAttrRel, size_t cbAttrRel);
    bool SetResource(const ACE_CSA_HELPER & CsaHelper);
    bool SetCondition(LPCVOID lpAttrRel, size_t cbAttrRel);

    bool SetDummyResource();

    PACE_HEADER Export(LPBYTE pbBuffer, size_t cbBuffer);
    PACE_HEADER AddToAcl(PACL pAcl);

    LPBYTE PutAceValue(LPBYTE PtrAclData, LPBYTE PtrAclEnd, PVOID PtrValue, DWORD dwLayoutMask, DWORD ValueSize);
    LPBYTE PutAceValueSid(LPBYTE PtrAclData, LPBYTE PtrAclEnd, PSID pSourceSid);
    LPBYTE PutAceValueBinary(LPBYTE PtrAclData, LPBYTE PtrAclEnd, LPVOID lpData, size_t cbData);

    LPBYTE CaptureExtraStructure(LPBYTE pbPtr, LPBYTE pbEnd, size_t * pcbMoveBy = NULL);

    // Helper for creating a SID belonging to a certain ACE type
    static PSID GetDefaultSid(DWORD dwAceType = ACCESS_ALLOWED_ACE_TYPE, DWORD dwAceFlags = 0);

    // Field mask for fields that are valid
    DWORD AceLayout;                                    // See ACE_FIELD_XXX

    // Variables
    BYTE  AceType;                                      // ACE_HEADER::AceType
    BYTE  AceFlags;                                     // ACE_HEADER::AceFlags
    WORD  AceSize;                                      // ACE_HEADER::AceSize
    ACCESS_MASK Mask;                                   // Mask (Allowed Ace, Denied Ace, Audit Ace, Alarm Ace, Mandatory Label Ace)
    DWORD Flags;
    USHORT CompoundAceType;
    USHORT CompoundReserved;
    GUID ObjectType;
    GUID InheritedObjectType;
    PSID Sid[2];                                        // Pointer to the first SID (need to be freed using FreeSid)
    LPBYTE Condition;                                   // ACE condition
    size_t ConditionLength;                             // Length of the ACE condition
    LPBYTE AttrRel;                                     // Relative security attribute
    size_t AttrRelLength;                               // Length of the ACE condition
};

#endif  // __TACEHELPER_H__
