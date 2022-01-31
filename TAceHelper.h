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
#define ACE_FIELD_HDR_TYPE          0x00000001      // ACE_HEADER::AceType (always included)
#define ACE_FIELD_HDR_FLAGS         0x00000002      // ACE_HEADER::AceFlags (always included)
#define ACE_FIELD_HDR_SIZE          0x00000004      // ACE_HEADER::AceSize (always included)
#define ACE_FIELD_ACCESS_MASK       0x00000008      // ACE::Mask
#define ACE_FIELD_ADS_ACCESS_MASK   0x00000010      // ACE::Mask for ADS ACEs
#define ACE_FIELD_MANDATORY_MASK    0x00000020      // SYSTEM_MANDATORY_LABEL_ACE::Mask
#define ACE_FIELD_FLAGS             0x00000040      // ACE::Flags
#define ACE_FIELD_OBJECT_TYPE       0x00000080      // ACE::ObjectType
#define ACE_FIELD_OBJECT_TYPE2      0x00000100      // ACE::InheritedObjectType
#define ACE_FIELD_ACCESS_SID        0x00000200      // ACE::SidStart contains an access SID
#define ACE_FIELD_MANDATORY_SID     0x00000400      // ACE::SidStart contains a mandatory label SID
#define ACE_FIELD_RCMGR_DATA        0x00000800      // Opaque data after SidStart + SidLength
#define ACE_FIELD_NEED_FREE_SID     0x80000000      // The ACE_HELPER::Sid needs to be freed using Sid_Free

// Flag combinations for {Header-Mask-SidStart} ACEs
#define ACE_LAYOUT_SIMPLE   (ACE_FIELD_HDR_TYPE | ACE_FIELD_HDR_FLAGS | ACE_FIELD_HDR_SIZE | ACE_FIELD_ACCESS_MASK | ACE_FIELD_ACCESS_SID)

// Flag combinations for {Header-Mask-SidStart-OpaqueResMgrData} ACEs
#define ACE_LAYOUT_SIMPLE2   (ACE_FIELD_HDR_TYPE | ACE_FIELD_HDR_FLAGS | ACE_FIELD_HDR_SIZE | ACE_FIELD_ACCESS_MASK | ACE_FIELD_ACCESS_SID | ACE_FIELD_RCMGR_DATA)

// Unknown ACE layout (ACCESS_ALLOWED_COMPOUND_ACE)
#define ACE_LAYOUT_UNKNOWN  (0)

// ACE layout for {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart}
#define ACE_LAYOUT_OBJECT   (ACE_FIELD_HDR_TYPE | ACE_FIELD_HDR_FLAGS | ACE_FIELD_HDR_SIZE | ACE_FIELD_ADS_ACCESS_MASK | ACE_FIELD_FLAGS | ACE_FIELD_OBJECT_TYPE | ACE_FIELD_OBJECT_TYPE2 | ACE_FIELD_ACCESS_SID)

// ACE layout for {Header-AdsMask-Flags-ObjectType-InheritedObjectType-SidStart-OpaqueResMgrData}
#define ACE_LAYOUT_OBJECT2  (ACE_FIELD_HDR_TYPE | ACE_FIELD_HDR_FLAGS | ACE_FIELD_HDR_SIZE | ACE_FIELD_ADS_ACCESS_MASK | ACE_FIELD_FLAGS | ACE_FIELD_OBJECT_TYPE | ACE_FIELD_OBJECT_TYPE2 | ACE_FIELD_ACCESS_SID | ACE_FIELD_RCMGR_DATA)

// ACE Layout for SYSTEM_MANDATORY_LABEL_ACE_TYPE
#define ACE_LAYOUT_MANDATORY (ACE_FIELD_HDR_TYPE | ACE_FIELD_HDR_FLAGS | ACE_FIELD_HDR_SIZE | ACE_FIELD_MANDATORY_MASK | ACE_FIELD_MANDATORY_SID)

//-----------------------------------------------------------------------------
// Interface for the ACE_HELPER class

struct ACE_HELPER
{
    // Constructors and destructors
    ACE_HELPER();
    ~ACE_HELPER();

    bool SetAceType(DWORD dwAceType);               // Sets a new ACE type
    bool SetAce(PACE_HEADER pAceHeader);            // Stores an ACE
    void SetAllocatedSid(PSID pSid);                // Stores a SID that needs to be freed
    bool AddToAcl(PACL pAcl);                       // Adds itself as an ACE to the ACL
    void Reset();                                   // Resets everything to 0

    LPBYTE PutAceValue(LPBYTE PtrAclData, LPBYTE PtrAclEnd, PVOID PtrValue, DWORD dwLayoutMask, DWORD ValueSize);

    // Field mask for fields that are valid
    DWORD AceLayout;                                // See ACE_FIELD_XXX

    // Variables
    DWORD AceType;                                  // ACE_HEADER::AceType
    DWORD AceFlags;                                 // ACE_HEADER::AceFlags
    DWORD AceSize;                                  // ACE_HEADER::AceSize
    ACCESS_MASK Mask;                               // Mask (Allowed Ace, Denied Ace, Audit Ace, Alarm Ace, Mandatory Label Ace)
    DWORD Flags;
    GUID ObjectType;
    GUID InheritedObjectType;
    PSID Sid;                                       // Pointer to SID (need to be freed using FreeSid)
};

#endif  // __TACEHELPER_H__
