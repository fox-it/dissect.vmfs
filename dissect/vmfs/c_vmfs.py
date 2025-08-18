from __future__ import annotations

from dissect.cstruct import cstruct

vmfs_def = """
/* === Common types === */
struct UUID {
    uint32          timeLo;
    uint32          timeHi;
    uint16          rand;
    char            macAddr[6];
};

struct SCSI_DiskId {
    uint8           type;
    uint8           len;
    uint16          lun;
    uint8           deviceType;
    uint8           scsiLevel;
    char            vendor[8];
    char            model[16];
    char            revision[4];
    char            id[44];
};

// These types normally have bitfields but we parse those in Python instead (address.py)
typedef uint32 FS3_Address;
typedef uint32 FS3_FileBlockAddr;
typedef uint32 FS3_FDAddr;

struct FS3_VolAddress {
    uint64 offset;
};

enum FS3_DescriptorType : uint32 {
    /* FS3DESC_... */
    INVALID,
    VOLUME,
    DIRECTORY,
    REGFILE,
    SYMLINK,
    SYSFILE,
    RDM,
    SENTINEL
};

enum FS3_AddrType {
    /* FS3_ADDR_... */
    INVALID             = 0x0,
    FILE_BLOCK          = 0x1,
    SMALL_FILE_BLOCK    = 0x1,                  /* File blocks, but on VMFS6 */
    SUB_BLOCK           = 0x2,
    POINTER_BLOCK       = 0x3,
    FILE_DESCRIPTOR     = 0x4,
    POINTER2_BLOCK      = 0x5,
    JOURNAL_BLOCK       = 0x6,
    LARGE_FILE_BLOCK    = 0x7,
    SENTINEL            = 0x8,
};

/* Added, don't have a better name */
enum FS3_ZeroLevelAddrType {
    INVALID             = 0x0,
    FILE_BLOCK          = 0x1,
    SUB_BLOCK           = 0x2,
    POINTER_BLOCK       = 0x3,
    POINTER2_BLOCK      = 0x5,
    POINTER_BLOCK_DOUBLE = 0x10D0,                  /* Don't have a better name */
    FILE_DESCRIPTOR_RESIDENT = 0x10D1,              /* Don't have a better name */
};

/* === System file addresses === */

#define rootDirDescAddr                 0x00000004
#define fbbDescAddr                     0x00400004
#define fdbcDescAddr                    0x00800004
#define pbcDescAddr                     0x00C00004
#define sbDescAddr                      0x01000004
#define vhDescAddr                      0x01400004
#define pb2DescAddr                     0x01800004
#define sdDirDescAddr                   0x01C00004
#define jbDescAddr                      0x02000004
#define unmapDescAddr                   0x02400004
#define dfDirDescAddr                   0x02800004

/* === Filesystem descriptor === */

#define FS3_FS_HEADER_OFFSET            0x200000
#define FS3_VMFS6_MAJOR_VERSION         24

#define VMFS_MAGIC_NUMBER               0x2fabf15e
#define VMFSL_MAGIC_NUMBER              0x2fabf15f
#define VMFS6_MAGIC_NUMBER              0x2fabf160  /* used? from symbols */
#define VMFS6L_MAGIC_NUMBER             0x2fabf161

flag FS3_Config : uint32 {
    UNKNOWN1            = 0x00000001,
    UNKNOWN2            = 0x00000002,
    DENSE_SBPC          = 0x00000004,               /* /config/VMFS3/intOpts/DenseSBPerCluster */
    MAINTENANCE         = 0x00000008,
    UNKNOWN10           = 0x00000010,               /* local VsanD? */
    UNKNOWN20           = 0x00000020,               /* default? */
    UNKNOWN40           = 0x00000040,               /* vmkfstools -C vmfs6 <dev> --createResourceOptimizedFS ? */
    UNKNOWN80           = 0x00000080,
    LOCAL               = 0x00000100,
    UNKNOWN200          = 0x00000200,               /* default? */
    SHARED              = 0x00000400,               /* vmkfstools -C vmfs6 <dev> --isVsanD */
    OSDATA              = 0x00000800,               /* vmkfstools -C vmfs6l <dev> --isSystem */
    VSAN                = 0x00001000,
    UNKNOWN2000         = 0x00002000,               /* default? */
    UNKNOWN4000         = 0x00004000,
};

struct FDS_VolInfo {
    char            id[32];
};

struct FS3_Checksum {
    uint64          value;
    uint64          checksumGen;
};

enum FS3_UnmapPriority : uint16 {
    NONE                = 0,
    LOW                 = 1,
    MEDIUM              = 2,
    HIGH                = 3,
};

enum FS3_UnmapMethod : uint8 {
    PRIORITY            = 0,
    FIXED               = 1,
};

struct FS3_Descriptor {
    uint32          magic;                          /* 0x00 */
    uint32          majorVersion;                   /* 0x04 */
    uint8           minorVersion;                   /* 0x08 */
    UUID            uuid;                           /* 0x09 */
    FS3_Config      config;                         /* 0x19 */
    char            fsLabel[128];                   /* 0x1d */
    uint32          diskBlockSize;                  /* 0x9d */
    uint64          fileBlockSize;                  /* 0xa1 */
    uint32          creationTime;                   /* 0xa9 */
    uint32          snapID;                         /* 0xad */
    FDS_VolInfo     volInfo;                        /* 0xb1 */
    uint32          fdcClusterGroupOffset;          /* 0xd1 */
    uint32          fdcClustersPerGroup;            /* 0xd5 */
    uint32          subBlockSize;                   /* 0xd9 */
    uint32          maxJournalSlotsPerTxn;          /* 0xdd */
    uint64          pb2VolAddr;                     /* 0xe1 */
    uint32          pb2FDAddr;                      /* 0xe9 */
    char            hostUuid[16];                   /* 0xed */
    uint64          gblGeneration;                  /* 0xfd */
    uint64          sddVolAddr;                     /* 0x105 */
    uint32          sddFDAddr;                      /* 0x10d */
    uint8           checksumType;                   /* 0x111 */
    FS3_UnmapPriority   unmapPriority;              /* 0x112 */
    char            pad1[4];                        /* 0x114 */
    uint64          checksumGen;                    /* 0x118 */
    FS3_Checksum    checksum;                       /* 0x120 */
    uint32          physDiskBlockSize;              /* 0x130 */
    uint32          mdAlignment;                    /* 0x134 */
    uint16          sfbToLfbShift;                  /* 0x138 */
    uint16          reserved16_1;                   /* 0x13a */
    uint16          reserved16_2;                   /* 0x13c */
    uint16          ptrBlockShift;                  /* 0x13e */
    uint16          sfbAddrBits;                    /* 0x140 */
    uint16          reserved16_3;                   /* 0x142 */
    uint32          tbzGranularity;                 /* 0x144 Also called unmapGranularity*/
    uint32          journalBlockSize;               /* 0x148 */
    uint32          leaseIntervalMs;                /* 0x14c */
    uint32          reclaimWindowMs;                /* 0x150 */
    uint64          localStampUS;                   /* 0x154 */
    char            localMountOwnerMacAddr[6];      /* 0x15c */
    FS3_UnmapMethod unmapMethod;                    /* 0x162 */
    uint32          unmapBandwidth;                 /* 0x163 */
    uint32          unmapBandwidthMin;              /* 0x167 */
    uint32          unmapBandwidthMax;              /* 0x16b */
};

/* === Resource metadata === */

enum FS3_ResourceTypeID {
    /* FS3_RESTYPE_... */
    INVALID             = 0,
    FILE_BLOCK          = 1,
    SMALL_FILE_BLOCK    = 1,
    SUB_BLOCK           = 2,
    PTR_BLOCK           = 3,
    FILE_DESC           = 4,
    PTR2_BLOCK          = 5,                        /* Don't have a better name */
    JOURNAL_BLOCK       = 6,
    LARGE_FILE_BLOCK    = 7,
    SENTINEL,
};

enum Res3PriorityType {
    /* RES3_PRIORITY_... */
    DEFAULT,
    JOURNAL             = 100000,
    MAX                 = 0x7fffffff
};

#define FS3_RFMD_SIGNATURE              0x72666D64  /* rfmd */
#define FS3_RCMD_SIGNATURE              0x72636D64  /* rcmd */

struct FS3_ResFileMetadata {
    uint32          resourcesPerCluster;            /* 0x00 */
    uint32          clustersPerGroup;               /* 0x04 */
    uint32          clusterGroupOffset;             /* 0x08 */
    uint32          resourceSize;                   /* 0x0c */
    uint32          clusterGroupSize;               /* 0x10 */
    uint32          numResourcesLo;                 /* 0x14 */
    uint32          numClusterGroups;               /* 0x18 */
    uint32          numResourcesHi;                 /* 0x1c */
    uint32          signature;                      /* 0x20 */
    uint32          version;                        /* 0x24 */
    uint32          flags;                          /* 0x28 0x02 = has parent?, 0x20 = HasUnmapBitmap */
    uint16          affinityPerCluster;             /* 0x2c */
    uint16          affinityPerResource;            /* 0x2e */
    uint32          bitsPerResource;                /* 0x30 */
    uint32          childMetaOffset;                /* 0x34 */
    uint32          parentResourcesPerCluster;      /* 0x38 */
    uint32          parentClustersPerGroup;         /* 0x3c */
    uint32          parentClusterGroupSize;         /* 0x40 */
    char            _unknown[16];                   /* 0x44 */
    uint32          convertedClusters;              /* 0x54 */
};

struct FS3_ResourceClusterMD {
    uint32          clusterNum;
    uint32          totalResources;
    uint32          freeResources;
    uint32          nextFreeIdx;
    uint8           bitmap[64];
    uint8           typeData[16];
    Res3PriorityType    priority;
};

/* TODO: This is not fully researched yet */
struct Res3_ClusterMetaVMFS6 {
    char            _pad[16];                       /* 0x00 */
    uint32          signature;                      /* 0x10 */
    uint32          priority;                       /* 0x14 */
    uint64          clusterNum;                     /* 0x18 */
    uint16          totalResources;                 /* 0x20 */
    uint16          freeResources;                  /* 0x22 */
    uint16          unk1;                           /* 0x24 */
    uint16          affinityCount;                  /* 0x26 */
    char            _unk[2328];                     /* 0x28 */
    /* List of tuple of addresses start here, referenced as overflow keys */
};

/* === Disk lock and heartbeat === */
/* TODO: This is not fully researched yet */

struct FS3_HBGen {
    uint64          gen;
};

struct FS3_LockHolder {
    FS3_VolAddress  hbAddr;
    FS3_HBGen       hbGen;
    UUID            uid;
};

struct FS3_DiskLock {
    uint32          type;                           /* 0x00 */
    FS3_VolAddress  addr;                           /* 0x04 */
    FS3_VolAddress  hbAddr;                         /* 0x0c */
    FS3_HBGen       hbGen;                          /* 0x14 */
    uint64          token;                          /* 0x1c */
    uint32          mode;                           /* 0x24 */
    UUID            owner;                          /* 0x28 */
    uint64          mtime;                          /* 0x38 */
    uint32          numHolders;                     /* 0x40 */
    FS3_LockHolder  holders[8];                     /* 0x44 */
    char            _unk[32];                       /* 0x144 */
    uint32          gblNumHolders;                  /* 0x164 */
    uint64          gblGen;                         /* 0x168 */
    uint32          gblBrk;                         /* 0x170 */
};

struct FS3_Heartbeat {
    uint32          state;                          /* 0x00 */
    FS3_VolAddress  addr;                           /* 0x04 */
    FS3_HBGen       hbGen;                          /* 0x0c */
    uint64          stamp;                          /* 0x14 */
    UUID            owner;                          /* 0x1c */
    FS3_Address     journalAddr;                    /* 0x2c */
    uint32          driveX;                         /* 0x30 drv %u.%u */
    uint8           driveY;                         /* 0x34 */
    uint8           lockImpl;                       /* 0x35 */
    char            ip[46];                         /* 0x36 */
    uint64          journalVolAddr;                 /* 0x64 */
    UUID            replayHost;                     /* 0x6c */
    char            _unk[24];                       /* 0x7c */
    uint64          replayHostHB;                   /* 0x94 */
    FS3_HBGen       replayHostHBgen;                /* 0x9c */
};

/* === FD/inode info === */

#define FS3_FDMD_SIGNATURE              0x66646D64  /* fdmd */

struct FS3_FileMetadata {
    FS3_FDAddr      descAddr;                       /* 0x00 */
    uint32          generation;                     /* 0x04 */
    uint32          linkCount;                      /* 0x08 */
    FS3_DescriptorType  type;                       /* 0x0c */
    uint32          flags;                          /* 0x10 1 = Large file allocation? */
    uint64          fileLength;                     /* 0x14 */
    uint64          blockSize;                      /* 0x1c */
    uint64          numBlocks;                      /* 0x24 */
    uint32          mtime;                          /* 0x2c */
    uint32          ctime;                          /* 0x30 */
    uint32          atime;                          /* 0x34 */
    uint32          uid;                            /* 0x38 */
    uint32          gid;                            /* 0x3c */
    uint32          mode;                           /* 0x40 */
    uint32          zeroLevelAddrType;              /* 0x44 */
    uint32          numTBZBlocksLo;                 /* 0x48 */
    uint32          numCOWBlocksLo;                 /* 0x4c */
    uint32          newSinceEpochLo;                /* 0x50 */
    uint32          numTBZBlocksHi;                 /* 0x54 */
    uint32          numCOWBlocksHi;                 /* 0x58 */
    uint32          numPointerBlocks;               /* 0x5c */
    uint32          newSinceEpochHi;                /* 0x60 */
    uint32          signature;                      /* 0x64 */
    uint32          affinityFD;                     /* 0x68 */
    uint32          tbzGranularityShift;            /* 0x6c */
    uint32          parentFD;                       /* 0x70 */
    uint32          lastSFBClusterNum;              /* 0x74 */
    uint32          _unk4;                          /* 0x78 */
    uint32          _unk5;                          /* 0x7c */
    uint32          affinityBitmap;                 /* 0x80 */
    uint8           numPreAllocBlocks;              /* 0x84 */
    uint8           _unk7;                          /* 0x85 */
    uint8           _unk8;                          /* 0x86 */
    uint8           _unk9;                          /* 0x87 */
    uint8           _unk10;                         /* 0x88 */
    uint8           blockOffsetShift;               /* 0x89 */
    uint8           numTracked;                     /* 0x8a */
    uint8           _unk12;                         /* 0x8b */
    uint32          numLFB;                         /* 0x8c */
    char            _unk13[216];                    /* 0x90 */
    uint32          lastFreeSFBC;                   /* 0x168 */
};

struct FS3_RawDiskMap {
    SCSI_DiskId     diskId;
};

/* === Directory entries === */

#define FS3_MAX_FILE_NAME_LENGTH        128
#define FS6_MAX_FILE_NAME_LENGTH        256

struct FS3_DirEntry {
    FS3_DescriptorType  type;                       /* 0x00 */
    FS3_FDAddr      descAddr;                       /* 0x04 */
    uint32          generation;                     /* 0x08 */
    char            name[FS3_MAX_FILE_NAME_LENGTH]; /* 0x0c */
};                                                  /* 0x8c */

#define FS6_DIR_HEADER_VERSION          0xF50001
#define FS6_DIR_HEADER_DEBUG_VERSION    0xFDC001
#define FS6_DIR_HEADER_BLOCK_SIZE       0x10000

#define FS6_DIR_HASH_MAX_ENTRIES        16001
#define FS6_DIR_HASH_ROOT_RESERVED      28
#define FS6_DIR_HASH_MAX_ROOT_ENTRIES   (FS6_DIR_HASH_MAX_ENTRIES - FS6_DIR_HASH_ROOT_RESERVED)

#define FS6_DIR_LINKS_PER_GROUP         12

enum FS6_DirBlockType {
    DIRENT              = 0x1,
    LINK                = 0x2,
    ALLOCATION_MAP      = 0x3,
};

struct FS6_DirEntry {
    FS3_DescriptorType  type;                       /* 0x00 */
    uint32          address;                        /* 0x04 */
    uint32          generation;                     /* 0x08 */
    uint16          hashIndex;                      /* 0x0c */
    uint16          linkHash;                       /* 0x0e */
    uint64          offset;                         /* 0x10 */
    char            name[256];                      /* 0x18 */
    uint64          _unk1;                          /* 0x118 */
};                                                  /* 0x120 */

struct FS6_DirHeader {
    uint32          version;                        /* 0x00 */
    uint32          numEntries;                     /* 0x04 */
    uint32          numAllocated;                   /* 0x08 */
    uint32          numAllocationMapBlocks;         /* 0x0c */
    uint32          allocationMapBlocks[128];       /* 0x10 */
    char            _gap0[408];                     /* 0x210 */
    uint64          checksum;                       /* 0x3A8 */
    uint64          checksumGen;                    /* 0x3B0 */
    FS6_DirEntry    selfEntry;                      /* 0x3B8 */
    FS6_DirEntry    parentEntry;                    /* 0x4D8 */
};                                                  /* 0x5F8 */

struct FS6_DirBlockHeader {
    uint16          version;                        /* 0x00 */
    uint16          type;                           /* 0x02 */
    uint16          totalSlots;                     /* 0x04 */
    uint16          freeSlots;                      /* 0x06 */
    char            bitmap[56];                     /* 0x08 */
};                                                  /* 0x40 */

struct FS6_DirLink {
    uint32          location;                       /* 0x00 */
    uint16          hash;                           /* 0x04 */
};                                                  /* 0x06 */

struct FS6_DirLinkGroup {
    uint16          hashIndex;                      /* 0x00 The hash index this is a link for */
    uint8           totalLinks;                     /* 0x02 */
    uint8           freeLinks;                      /* 0x03 */
    uint8           nextFreeIdx;                    /* 0x04 */
    uint8           pad1;                           /* 0x05 */
    FS6_DirLink     links[FS6_DIR_LINKS_PER_GROUP]; /* 0x06 */
    uint32          nextGroup;                      /* 0x4e */
    uint16          pad2;                           /* 0x52 */
};                                                  /* 0x54 */
"""

c_vmfs = cstruct().load(vmfs_def)

FS3_Config = c_vmfs.FS3_Config
FS3_AddrType = c_vmfs.FS3_AddrType
FS3_ResourceTypeID = c_vmfs.FS3_ResourceTypeID
FS3_ZeroLevelAddrType = c_vmfs.FS3_ZeroLevelAddrType
FS3_DescriptorType = c_vmfs.FS3_DescriptorType
FS6_DirBlockType = c_vmfs.FS6_DirBlockType
