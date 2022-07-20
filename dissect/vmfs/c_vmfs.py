import stat
import struct

from dissect import cstruct


vmfs_def = """
/* === System file addresses === */

#define ROOT_DIR_DESC_ADDR              0x00000004
#define FBB_DESC_ADDR                   0x00400004
#define FDBC_DESC_ADDR                  0x00800004
#define PBC_DESC_ADDR                   0x00C00004
#define SB_DESC_ADDR                    0x01000004
#define VH_DESC_ADDR                    0x01400004
#define PB2_DESC_ADDR                   0x01800004
#define SD_DIR_DESC_ADDR                0x01C00004
#define JB_DESC_ADDR                    0x02000004

/* === Address flags === */

#define ADDRESS_FLAG_COW                0x10
#define ADDRESS_FLAG_TBZ                0x20
#define ADDRESS_FLAG_TBZ_VMFS6          0x7f80

/* === LVM Info === */

#define VMFS_LVM_DEVICE_META_BASE       0x00100000
#define VMFS_LVM_DEVICE_META_MAGIC      0xC001D00D

#define VMFS5_LVM_INFO_OFFSET           0x00000200
#define VMFS_LVM_DEVICE_NAME_BASE       0x0017E000

#define VMFS_LVM_PE_BITMAP_BASE         0x00180000

#define VMFS_LVM_PE_SIZE                (256 * 1024 * 1024)

struct LVM_DiskID {
    uint8       type;                           /* 0x00 */
    uint8       len;                            /* 0x01 Length of the string in id */
    uint16      lun;                            /* 0x02 */
    uint8       devType;                        /* 0x04 */
    uint8       scsi;                           /* 0x05 */
    char        name[28];                       /* 0x06 */
    char        id[44];                         /* 0x22 */
};

struct LVM_ExtendedMeta {
    uint32      magic;                          /* 0x00 0xC001D00D */
    uint32      numPEMaps;                      /* 0x04 */
    uint64      offset;                         /* 0x08 Offset of this metadata */
};

struct LVM_DeviceMeta {
    uint32      magic;                          /* 0x00 0xC001D00D */
    uint32      majorVersion;                   /* 0x04 aka FormatVersion */
    uint32      minorVersion;                   /* 0x08 */
    LVM_DiskID  diskID;                         /* 0x0C */
    uint32      diskBlockSize;                  /* 0x5a Disk sector size */
    uint64      volumeSize;                     /* 0x5e Volume size in bytes */
    uint32      numVolumes;                     /* 0x66 Number of volumes */
    uint32      numPEs;                         /* 0x6a numPEs for VMFS5? */
                                                /*      Checked against consumedPEs of volume if VMFS6. */
    uint32      lastPEindex;                    /* 0x6e lastPEindex */
    uint32      generation;                     /* 0x72 */
    uint32      _unknown5;                      /* 0x76 */
    uint64      dataOffset;                     /* 0x7a dataOffset */
    char        deviceID[16];                   /* 0x82 devID */
    uint64      creationTime;                   /* 0x92 */
    uint64      lastModifiedTime;               /* 0x9a */
    char        lockUuid[16];                   /* 0xa2 Device locked by this UUID */
    uint64      lockTime;                       /* 0xb2 Locked at this time */
    char        _unknown6[4];                   /* 0xba */
    uint32      numPEMaps;                      /* 0xbe numPEMaps, # PEMaps */
    uint64      extDeviceMetaOffset;            /* 0xc2 extDeviceMetaOffset */
    uint32      volumeInfoOffset;               /* 0xca VMFS6 only, relative offset to volume info and device name */
                                                /*      This is likely a "size" of something, but don't know what */
    uint32      _unknown9;                      /* 0xce VMFS6 += 0x180000, VMFS5 0x180200, related to bitmaps? */
    uint32      numPEsVMFS6;                    /* 0xd2 numPEs for VMFS6? */
                                                /*      numPEs of volume checked against this if VMFS6 */
};

struct LVM_VolumeInfo {
    uint64_t    size;                           /* 0x00 Volume size in bytes */
    uint64_t    _unknown1;                      /* 0x08 */
    uint32_t    state;                          /* 0x10 Some flag, snapshot? */
    char        uuidString[64];                 /* 0x14 UUID as string */
    char        uuid[16];                       /* 0x54 UUID as bytes */
    uint32_t    _unknown2;                      /* 0x64 Related to UUID, always 1 */
    uint64_t    creationTime;                   /* 0x68 Time of creation */
    uint32_t    volumeID;                       /* 0x70 Volume index */
    uint32_t    numPEs;                         /* 0x74 Number of physical extents */
    uint64_t    firstPE;                        /* 0x78 First physical extent */
    uint64_t    lastPE;                         /* 0x80 Last physical extent */
    uint64_t    lastModifiedTime;               /* 0x88 Time of last metadata update */
    uint32_t    numDevs;                        /* 0x90 */
    char        _unknown3[124];                 /* 0x94 */
    uint32_t    consumedPEs;                    /* 0x110 Consumed physical extents? */
};

/* === Filesystem descriptor === */

#define VMFS_FS3_BASE                   0x00200000
#define VMFS_FS3_MAGIC                  0x2fabf15e
#define VMFSL_FS3_MAGIC                 0x2fabf15f

// Temporary until more info is available
#define VMFS_HB_BASE                    0x00300000
#define VMFS5_HB_ENTRY_SIZE             0x200
#define VMFS5_HB_REGION_SIZE            0x100000
#define VMFS6_HB_ENTRY_SIZE             0x1000

#define VMFS5_MD_ALIGNMENT              0x200

flag FS_CONFIG : uint32 {
    MAINTENANCE = 0x00000008,
    SYSTEM = 0x00000800
};

struct FDS_VolInfo {
    char            id[32];
};

struct FS3_Checksum {
    uint64          value;
    uint64          checksumGen;
};

struct FS3_Descriptor {
    uint32      magic;                          /* 0x00 */
    uint32      majorVersion;                   /* 0x04 */
    uint8       minorVersion;                   /* 0x08 */
    char        uuid[16];                       /* 0x09 */
    FS_CONFIG   config;                         /* 0x19 */
    char        fsLabel[128];                   /* 0x1d */
    uint32      diskBlockSize;                  /* 0x9d */
    uint64      fileBlockSize;                  /* 0xa1 */
    uint32      creationTime;                   /* 0xa9 */
    uint32      snapID;                         /* 0xad */
    FDS_VolInfo volInfo;                        /* 0xb1 */
    uint32      fdcClusterGroupOffset;          /* 0xd1 */
    uint32      fdcClustersPerGroup;            /* 0xd5 */
    uint32      subBlockSize;                   /* 0xd9 */
    uint32      maxJournalSlotsPerTxn;          /* 0xdd */
    uint64      pb2VolAddr;                     /* 0xe1 */
    uint32      pb2FDAddr;                      /* 0xe9 */
    char        hostUuid[16];                   /* 0xed */
    uint64      gblGeneration;                  /* 0xfd */
    uint64      sddVolAddr;                     /* 0x105 */
    uint32      sddFDAddr;                      /* 0x10d */
    uint8       checksumType;                   /* 0x111 */
    uint16      unmapPriority;                  /* 0x112 */
    char        pad1[4];                        /* 0x114 */
    uint64      checksumGen;                    /* 0x118 */
    FS3_Checksum checksum;                      /* 0x120 */
    uint32      physDiskBlockSize;              /* 0x130 */
    uint32      mdAlignment;                    /* 0x134 */
    uint16      sfbToLfbShift;                  /* 0x138 */
    uint16      reserved16_1;                   /* 0x13a */
    uint16      reserved16_2;                   /* 0x13c */
    uint16      ptrBlockShift;                  /* 0x13e */
    uint16      sfbAddrBits;                    /* 0x140 */
    uint16      reserved16_3;                   /* 0x142 */
    uint32      tbzGranularity;                 /* 0x144 */
    uint32      journalBlockSize;               /* 0x148 */
    uint32      leaseIntervalMs;                /* 0x14c */
    uint32      reclaimWindowMs;                /* 0x150 */
    uint64      localStampUS;                   /* 0x154 */
    char        localMountOwnerMacAddr[6];      /* 0x15c */
};

/* === Heartbeat === */

#define HEARTBEAT_FREE                  0xABCDEF01
#define HEARTBEAT_IN_USE                0xABCDEF02

struct FS3_Heartbeat {
    uint32      state;                          /* 0x00 */
    uint64      address;                        /* 0x04 */
    uint64      hbGeneration;                   /* 0x0c */
    uint64      stampUS;                        /* 0x14 */
    char        owner[16];                      /* 0x1c */
    uint32      journalAddress;                 /* 0x2c */
    uint32      driveX;                         /* 0x30 drv %u.%u */
    uint8       driveY;                         /* 0x34 */
    uint8       lockImpl;                       /* 0x35 */
    char        ip[46];                         /* 0x36 */
    uint64      journalVolumeAddress;           /* 0x64 */
    char        replayHostUUID[16];             /* 0x6c */
    char        _unk[24];                       /* 0x7c */
    uint64      replayHostHB;                   /* 0x94 */
    uint64      replayHostHBgen;                /* 0x9c */
};

/* === Resource metadata === */

enum ResourceType {
    NONE = 0,
    FB = 1,             /* (Small) File Block */
    SB = 2,             /* Sub-Block */
    PB = 3,             /* Pointer Block */
    FD = 4,             /* File Descriptor */
    PB2 = 5,            /* Pointer Block 2 */
    JB = 6,             /* Journal Block */
    LFB = 7,            /* Large File Block */
};

#define VMFS_RESOURCE_META_SIGNATURE    0x72666D64  // dmcr

struct Res3_Metadata {
    uint32      resourcePerCluster;
    uint32      clustersPerClusterGroup;
    uint32      firstClusterGroupOffset;
    uint32      resourceSize;
    uint32      clusterGroupSize;
    uint32      numResourcesLo;
    uint32      numClusterGroups;
    uint32      numResourcesHi;
    uint32      signature;
    uint32      version;
    uint32      flags;
    uint16      affinityPerResourceCluster;
    uint16      affinityPerResource;
    uint32      bitsPerResource;
    uint32      childMetaOffset;
    uint32      parentResourcesPerCluster;
    uint32      parentClustersPerClusterGroup;
    uint32      parentClusterGroupSize;
};

struct Res3_ClusterMetaVMFS5 {
    uint32      clusterNum;
    uint32      totalResources;
    uint32      freeResources;
    uint32      nextFreeIdx;
};

#define VMFS6_CLUSTER_META_SIGNATURE    0x72636D64  // dmcr

struct Res3_ClusterMetaVMFS6 {
    char        _pad[16];                       /* 0x00 */
    uint32      signature;                      /* 0x10 */
    uint32      priority;                       /* 0x14 */
    uint64      clusterNum;                     /* 0x18 */
    uint16      totalResources;                 /* 0x20 */
    uint16      freeResources;                  /* 0x22 */
    uint16      unk1;                           /* 0x24 */
    uint16      affinityCount;                  /* 0x26 */
    char        _unk[2328];                     /* 0x28 */
    /* List of tuple of addresses start here, referenced as overflow keys */
};

/* === Disk lock info === */

#define VMFS5_LOCK_SIZE                 0x200

struct FS3_DiskLockInfo {
    uint32      type;
    uint64      offset;
    uint64      hbAddress;
    uint64      hbGeneration;
    uint64      generation;
    uint32      mode;
    char        ownerUuid[16];
    uint64      modificationTime;
    uint32      numHolders;
    char        _unk0[288];
    uint32      gblNumHolders;
    uint64      gblGeneration;
    uint32      gblBrk;
};

/* === FD/inode info === */

enum FileType {
    Directory = 0x2,
    Regular = 0x3,
    Symlink = 0x4,
    System = 0x5,
    RDM = 0x6,
};

struct FS3_FileDescriptor {
    uint32      address;                        /* 0x00 */
    uint32      generation;                     /* 0x04 */
    uint32      numLinks;                       /* 0x08 */
    uint32      type;                           /* 0x0c */
    uint32      flags;                          /* 0x10 */
    uint64      length;                         /* 0x14 */
    uint64      blockSize;                      /* 0x1c */
    uint64      numBlocks;                      /* 0x24 */
    uint32      modificationTime;               /* 0x2c */
    uint32      creationTime;                   /* 0x30 */
    uint32      accessTime;                     /* 0x34 */
    uint32      uid;                            /* 0x38 */
    uint32      gid;                            /* 0x3c */
    uint32      mode;                           /* 0x40 */
    uint32      zla;                            /* 0x44 */
    uint32      tbzLo;                          /* 0x48 */
    uint32      cowLo;                          /* 0x4c */
    uint32      newSinceEpochLo;                /* 0x50 */
    uint32      tbzHi;                          /* 0x54 */
    uint32      cowHi;                          /* 0x58 */
    uint32      numPointerBlocks;               /* 0x5c */
    uint32      newSinceEpochHi;                /* 0x60 */
    uint32      _unk1;                          /* 0x64 */
    uint32      affinityFD;                     /* 0x68 */
    uint32      tbzGranularityShift;            /* 0x6c */
    uint32      parentFD;                       /* 0x70 */
    uint32      lastSFBClusterNum;              /* 0x74 */
    uint32      _unk4;                          /* 0x78 */
    uint32      _unk5;                          /* 0x7c */
    uint32      _unk6;                          /* 0x80 */
    uint8       numPreAllocBlocks;              /* 0x84 */
    uint8       _unk7;                          /* 0x85 */
    uint8       _unk8;                          /* 0x86 */
    uint8       _unk9;                          /* 0x87 */
    uint8       _unk10;                         /* 0x88 */
    uint8       blockOffsetShift;               /* 0x89 */
    uint8       numTracked;                     /* 0x8a */
    uint8       _unk12;                         /* 0x8b */
    uint32      numLFB;                         /* 0x8c */
    char        _unk13[216];                    /* 0x90 */
    uint32      lastFreeSFBC;                   /* 0x168 */
    // char        _unk14[148];                    /* 0x16c */
};

// Temporary until more info is available
#define VMFS5_ZLA_BASE                  4301    // 0x10d1

/* === Directory entries === */

#define VMFS5_DIR_ENTRY_SIZE            0x8c

struct FS3_DirEntry {
    uint32      type;
    uint32      address;
    uint32      generation;
    char        name[128];
};

#define VMFS6_DIR_FS_VERSION            0xF50001
#define VMFS6_DIR_FDC_VERSION           0xFDC001
#define VMFS6_DIR_BLOCK_BASE            0x10000

#define VMFS6_DIR_ENTRY_SIZE            0x120

struct FS6_DirEntry {
    uint32      type;
    uint32      address;
    uint32      generation;
    uint32      hash;
    uint64      offset;
    char        name[256];
    uint64      _unk1;
};

struct FS6_DirHeader {
  uint32        version;
  uint32        numEntries;
  uint32        numAllocated;
  uint32        _unk1;
  uint64        _unk2;
  char          _gap0[912];
  uint64        _unk4;
  uint64        _unk5;
  FS6_DirEntry  selfEntry;
  FS6_DirEntry  parentEntry;
};
"""

c_vmfs = cstruct.cstruct()
c_vmfs.load(vmfs_def)

ADDRESS_TYPE_MASK = 7
ResourceType = c_vmfs.ResourceType
FileType = c_vmfs.FileType


def bsf(value, size=32):
    """Count the number of zero bits in an integer of a given size."""
    for i in range(size):
        if value & (1 << i):
            return i


def type_to_mode(type_):
    if type_ == FileType.Directory:
        return stat.S_IFDIR
    elif type_ == FileType.Symlink:
        return stat.S_IFLNK
    return stat.S_IFREG


def vmfs_uuid(buf):
    uuid1, uuid2, uuid3, uuid4 = struct.unpack("<IIH6s", buf)
    return f"{uuid1:08x}-{uuid2:08x}-{uuid3:04x}-{uuid4.hex()}"
