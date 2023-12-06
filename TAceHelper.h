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
#define ACE_FIELD_HFLAGS            0x00000002      // ACE_HEADER::AceFlags (always included)
#define ACE_FIELD_HSIZE             0x00000004      // ACE_HEADER::AceSize  (always included)
#define ACE_FIELD_ACCESS_MASK       0x00000008      // ACE::Mask
#define ACE_FIELD_ADS_ACCESS_MASK   0x00000010      // ACE::Mask for ADS ACEs
#define ACE_FIELD_MANDATORY_MASK    0x00000020      // SYSTEM_MANDATORY_LABEL_ACE::Mask
#define ACE_FIELD_FLAGS             0x00000040      // XXX_YYY_OBJECT_ACE::Flags
#define ACE_FIELD_CTYPE             0x00000080      // COMPOUND_ACCESS_ALLOWED_ACE::CompoundAceType
#define ACE_FIELD_CRESERVED         0x00000100      // COMPOUND_ACCESS_ALLOWED_ACE::Reserved
#define ACE_FIELD_OBJECT_TYPE1      0x00000200      // XXX_YYY_OBJECT_ACE::ObjectType
#define ACE_FIELD_OBJECT_TYPE2      0x00000400      // XXX_YYY_OBJECT_ACE::InheritedObjectType
#define ACE_FIELD_ACCESS_SID        0x00000800      // ACE::SidStart contains an access SID
#define ACE_FIELD_SERVER_SID        0x00001000      // ACE::SidStart contains a server SID
#define ACE_FIELD_CLIENT_SID        0x00002000      // ACE::SidStart contains a client SID
#define ACE_FIELD_MANDATORY_SID     0x00004000      // ACE::SidStart contains a mandatory label SID
#define ACE_FIELD_CSA_V1            0x00008000      // Contains the CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 structure
#define ACE_FIELD_CONDITION         0x00010000      // Contains the ACE condition

// Multi flags that are always together
#define ACE_FIELD_HEADER            (ACE_FIELD_HTYPE|ACE_FIELD_HFLAGS|ACE_FIELD_HSIZE)

// Flags for free fields
#define ACE_HELPER_NEED_FREE_SID0   0x00000001      // The ACE_HELPER::Sid[0] needs to be freed using Sid_Free
#define ACE_HELPER_NEED_FREE_SID1   0x00000002      // The ACE_HELPER::Sid[1] needs to be freed using Sid_Free

// Unknown ACE layout (ACCESS_ALLOWED_COMPOUND_ACE)
#define ACE_LAYOUT_UNKNOWN   (0)

// Flag combinations for {Header-Mask-SidStart} ACEs
#define ACE_LAYOUT_SIMPLE     (ACE_FIELD_HEADER | ACE_FIELD_ACCESS_MASK | ACE_FIELD_ACCESS_SID)

//
#define ACE_LAYOUT_COMPOUND   (ACE_FIELD_HEADER | ACE_FIELD_ACCESS_MASK | ACE_FIELD_CTYPE | ACE_FIELD_CRESERVED | ACE_FIELD_SERVER_SID | ACE_FIELD_CLIENT_SID)

// ACE layout for {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart}
#define ACE_LAYOUT_OBJECT     (ACE_FIELD_HEADER | ACE_FIELD_ADS_ACCESS_MASK | ACE_FIELD_FLAGS | ACE_FIELD_OBJECT_TYPE1 | ACE_FIELD_OBJECT_TYPE2 | ACE_FIELD_ACCESS_SID)

// Flag combinations for {Header-Mask-SidStart-Condition} ACEs
#define ACE_LAYOUT_CONDITION  (ACE_FIELD_HEADER | ACE_FIELD_ACCESS_MASK | ACE_FIELD_ACCESS_SID | ACE_FIELD_CONDITION)

// Flag combinations for {Header-Mask-Flags-ObjectType-InheritedObjectType-SidStart-Condition} ACEs
#define ACE_LAYOUT_OBJECT_CONDITION  (ACE_FIELD_HEADER | ACE_FIELD_ADS_ACCESS_MASK | ACE_FIELD_FLAGS | ACE_FIELD_OBJECT_TYPE1 | ACE_FIELD_OBJECT_TYPE2 | ACE_FIELD_ACCESS_SID | ACE_FIELD_CONDITION)

// ACE Layout for SYSTEM_MANDATORY_LABEL_ACE_TYPE
#define ACE_LAYOUT_MANDATORY  (ACE_FIELD_HEADER | ACE_FIELD_MANDATORY_MASK | ACE_FIELD_MANDATORY_SID)

// ACE layout for SYSTEM_RESOURCE_ATTRIBUTE_ACE
#define ACE_LAYOUT_RESOURCE   (ACE_FIELD_HEADER | ACE_FIELD_ACCESS_MASK | ACE_FIELD_ACCESS_SID | ACE_FIELD_CSA_V1)

//-----------------------------------------------------------------------------
// Interface for the ACE_HELPER class

struct ACE_HELPER
{
    // Constructors and destructors
    ACE_HELPER(DWORD dwAceType = 0, ACCESS_MASK AccessMask = GENERIC_ALL, PSID pSid = NULL);
    ~ACE_HELPER();
    void Reset();                                       // Resets everything

    bool SetAceType(DWORD dwAceType);                   // Sets a new ACE type
    bool SetAce(PACE_HEADER pAceHeader);                // Stores an ACE
    PSID SetSid(PSID pSid, size_t nSidIndex);      // Stores a SID that needs to be freed
    bool SetAttributes(LPVOID lpAttrRel, size_t cbAttrRel);
    bool SetCondition(LPVOID lpAttrRel, size_t cbAttrRel);

    PACE_HEADER Export(LPBYTE pbBuffer, size_t cbBuffer);
    PACE_HEADER AddToAcl(PACL pAcl);

    LPBYTE PutAceValue(LPBYTE PtrAclData, LPBYTE PtrAclEnd, PVOID PtrValue, DWORD dwLayoutMask, DWORD ValueSize);
    LPBYTE PutAceValueSid(LPBYTE PtrAclData, LPBYTE PtrAclEnd, PSID pSourceSid);
    LPBYTE PutAceValueBinary(LPBYTE PtrAclData, LPBYTE PtrAclEnd, LPVOID lpData, size_t cbData);

    LPBYTE CaptureExtraStructure(LPBYTE pbPtr, LPBYTE pbEnd, size_t * pcbMoveBy = NULL);

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
    DWORD FreeFlags;                                    // Free SID flags
};

#endif  // __TACEHELPER_H__
