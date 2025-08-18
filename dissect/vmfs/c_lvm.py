from __future__ import annotations

from dissect.cstruct import cstruct

lvm_def = """
typedef uint8 Bool;

#define DISK_BLOCK_SIZE_512B            512
#define FS_PLIST_DEF_MAX_PARTITIONS     32

#define LVM_MAGIC_NUMBER                0xC001D00D
#define LVM_INITIAL_MAJOR_VERSION       3
#define LVM_MAJOR_VERSION_ESX60         6
#define LVM_MAJOR_VERSION_ESX50         5

#define LVM_IS_LVM6(majorVersion)       ((majorVersion == LVM_MAJOR_VERSION_ESX60) ? TRUE : FALSE)

#define LVM_DEV_HEADER_OFFSET           0x00100000
#define LVM_MD_ALIGNMENT_DEFAULT        (1 << 12)

#define LVM_MAX_VOLUME_LABEL_LENGTH     64

#define LVM_SIZEOF_LVM_DEVMETA_LVM5     DISK_BLOCK_SIZE_512B
#define LVM_SIZEOF_LVM_DEVMETA_LVM6(mdAlignment)    (mdAlignment)
#define LVM_SIZEOF_LVM_DEVMETA(majorVersion,mdAlignment) (LVM_IS_LVM6(majorVersion) ? LVM_SIZEOF_LVM_DEVMETA_LVM6(mdAlignment) : LVM_SIZEOF_LVM_DEVMETA_LVM5)

#define LVM_SIZEOF_EXTVOLMETA           256
#define LVM_SIZEOF_VTENTRY              512
#define LVM_SIZEOF_PTENTRY              128
#define LVM_SIZEOF_SDTENTRY             256

#define LVM_MAX_VOLUMES_PER_DEV_LVM5    512
#define LVM_MAX_VOLUMES_PER_DEV_LVM6    1
#define LVM_MAX_VOLUMES_PER_DEV(majorVersion) (LVM_IS_LVM6(majorVersion) ? LVM_MAX_VOLUMES_PER_DEV_LVM6 : LVM_MAX_VOLUMES_PER_DEV_LVM5)

#define LVM_UNUSED_MD_SECTORS_LVM5      (1024 - (LVM_MAX_VOLUMES_PER_DEV_LVM5))
#define LVM_UNUSED_MD_SECTORS_LVM6      (1024 - (LVM_MAX_VOLUMES_PER_DEV_LVM6))

#define LVM_UNUSED_MD_SIZE_LVM5         LVM_UNUSED_MD_SECTORS_LVM5 * DISK_BLOCK_SIZE_512B
#define LVM_UNUSED_MD_SIZE_LVM6         LVM_UNUSED_MD_SECTORS_LVM6 * DISK_BLOCK_SIZE_512B

#define LVM_RESERVED_SIZE_LVM5          (LVM_UNUSED_MD_SIZE_LVM5 - LVM_SIZEOF_SDTENTRY * FS_PLIST_DEF_MAX_PARTITIONS)
#define LVM_RESERVED_SIZE_LVM6          (LVM_UNUSED_MD_SIZE_LVM6 - LVM_SIZEOF_SDTENTRY * FS_PLIST_DEF_MAX_PARTITIONS)
#define LVM_RESERVED_SIZE(majorVersion) (LVM_IS_LVM6(majorVersion) ? LVM_RESERVED_SIZE_LVM6 : LVM_RESERVED_SIZE_LVM5)

#define LVM_PES_PER_BITMAP              8192
#define LVM_PE_BITMAP_SIZE_LVM5         (LVM_PES_PER_BITMAP / 8)
#define LVM_PE_BITMAP_SIZE_LVM6(mdAlignment)    (MAX(mdAlignment, LVM_PE_BITMAP_SIZE_LVM5))
#define LVM_PE_BITMAP_SIZE(majorVersion,mdAlignment)    (LVM_IS_LVM6(majorVersion) ? LVM_PE_BITMAP_SIZE_LVM6(mdAlignment) : LVM_PE_BITMAP_SIZE_LVM5)

enum LVM_VolState {
    LVM_INVALID,
    LVM_NORMAL,
    LVM_RESIG_PENDING,
    LVM_RESIG_DONE,
    LVM_SENTINEL
};

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

struct LVM_DevMetadata {
    uint32          magic;                              /* 0x00 0xC001D00D */
    uint32          majorVersion;                       /* 0x04 */
    uint32          minorVersion;                       /* 0x08 */
    SCSI_DiskId     diskID;                             /* 0x0C */
    uint32          diskBlockSize;                      /* 0x5a */
    uint64          totalBytes;                         /* 0x5e */
    uint32          numVolumes;                         /* 0x66 */
    uint32          numPEs;                             /* 0x6a */
    uint32          lastPEIndex;                        /* 0x6e */
    uint64          generation;                         /* 0x72 */
    uint64          dataOffset;                         /* 0x7A */
    UUID            devID;                              /* 0x82 */
    uint64          initTimeUS;                         /* 0x92 */
    uint64          modTimeUS;                          /* 0x9A */
    UUID            lockedBy;                           /* 0xA2 */
    uint64          lockedWhenUS;                       /* 0xB2 */
    uint32          _unknown0;                          /* 0xBA */
    uint32          numPEMaps;                          /* 0xBE */
    uint64          extDevMetadataOffset;               /* 0xC2 */
    uint32          mdAlignment;                        /* 0xCA Not sure if this is a good name, but it's used similarly */
    uint32          numPEs6;                            /* 0xCE */
    uint32          flags;                              /* 0xD2 1 == VMFSL */
};                                                      /* 0xD6 sizeof(LVM_DevMetadata) */

struct LVM_ExtDevMetadata {
    uint32          magic;                              /* 0x00 0xC001D00D */
    uint32          numPEMaps;                          /* 0x04 */
    uint64          dataOffset;                         /* 0x08 */
    uint64          nextOffset;                         /* 0x10 Offset to the next LVM_ExtDevMetadata */
};                                                      /* 0x18 sizeof(LVM_ExtDevMetadata) */

struct LVM_VolID {
    UUID            uuid;                               /* 0x00 UUID of the volume */
    uint32          snapID;                             /* 0x10 Snapshot ID of the volume */
};                                                      /* 0x14 sizeof(LVM_VolID) */

struct LVM_VolMetadata {
    uint64          logicalSize;                        /* 0x00 Logical size of the volume in bytes */
    uint64          generation;                         /* 0x08 Generation number of the volume */
    LVM_VolState    state;                              /* 0x10 State of the volume */
    char            name[LVM_MAX_VOLUME_LABEL_LENGTH];  /* 0x14 Name of the volume */
    LVM_VolID       lvID;                               /* 0x54 Logical volume ID */
    uint64          creationTimeUS;                     /* 0x64 Creation time of the volume in microseconds */
};                                                      /* 0x70 sizeof(LVM_VolMetadata) */

struct LVM_ExtVolMetadata {
    uint32          numDevs;                            /* 0x00 Number of devices in the volume */
    char            pad[124];                           /* 0x04 */
    uint32          consumedPEs;                        /* 0x80 Consumed physical extents */
};                                                      /* 0x84 sizeof(LVM_ExtVolMetadata) */

struct LVM_VolDescriptor {
    LVM_VolMetadata volMeta;                            /* 0x00 */
    uint32          volumeID;                           /* 0x70 Volume index */
    uint32          numPEs;                             /* 0x74 Number of physical extents */
    uint64          firstPE;                            /* 0x78 First physical extent */
    uint64          lastPE;                             /* 0x80 Last physical extent */
    uint64          modTimeUS;                          /* 0x88 Last modification time in microseconds */
    LVM_ExtVolMetadata  extVolMeta;                     /* 0x90 Extended volume metadata */
    char            pad[236];                           /* 0x114 */
};                                                      /* 0x200 sizeof(LVM_VolDescriptor) */

struct LVM_VolTableEntry {
    LVM_VolDescriptor   volDesc;                        /* 0x00 */
};                                                      /* 0x200 sizeof(LVM_VolTableEntry) */

struct LVM_PEDescriptor {
    uint32          peID;                               /* 0x00 Physical extent ID */
    uint32          volumeID;                           /* 0x04 Volume ID this PE belongs to */
    uint64          pOffset;                            /* 0x08 Physical offset of this PE in the device */
    uint64          lOffset;                            /* 0x10 Logical offset of this PE in the volume */
    uint64          length;                             /* 0x18 Length of this PE in bytes */
    uint32          version;                            /* 0x20 Version of this PE */
};                                                      /* 0x24 sizeof(LVM_PEDescriptor) */

struct LVM_PETableEntry {
    Bool            used;                               /* 0x00 Whether this PE is used */
    LVM_PEDescriptor    peDesc;                         /* 0x01 Physical extent descriptor */
};                                                      /* 0x25 sizeof(LVM_PETableEntry) */

struct LVM_SDTableEntry {
    char            deviceName[256];                    /* 0x00 Name of the device */
};                                                      /* 0x100 sizeof(LVM_SDTableEntry) */
"""  # noqa: E501

c_lvm = cstruct().load(lvm_def)
