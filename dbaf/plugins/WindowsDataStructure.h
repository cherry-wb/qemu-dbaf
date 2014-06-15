#ifndef _WINDOWS_DATAASTRUCTURE_H_
#define _WINDOWS_DATAASTRUCTURE_H_

#include <inttypes.h>
#include <map>
#include <string>
namespace dbaf {
namespace windows {

static const uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D;      // MZ
static const uint32_t IMAGE_NT_SIGNATURE = 0x00004550;  // PE00

typedef struct IMAGE_DOS_HEADER {      // DOS .EXE header
    uint16_t   e_magic;                     // Magic number
    uint16_t   e_cblp;                      // Bytes on last page of file
    uint16_t   e_cp;                        // Pages in file
    uint16_t   e_crlc;                      // Relocations
    uint16_t   e_cparhdr;                   // Size of header in paragraphs
    uint16_t   e_minalloc;                  // Minimum extra paragraphs needed
    uint16_t   e_maxalloc;                  // Maximum extra paragraphs needed
    uint16_t   e_ss;                        // Initial (relative) SS value
    uint16_t   e_sp;                        // Initial SP value
    uint16_t   e_csum;                      // Checksum
    uint16_t   e_ip;                        // Initial IP value
    uint16_t   e_cs;                        // Initial (relative) CS value
    uint16_t   e_lfarlc;                    // File address of relocation table
    uint16_t   e_ovno;                      // Overlay number
    uint16_t   e_res[4];                    // Reserved uint16_ts
    uint16_t   e_oemid;                     // OEM identifier (for e_oeminfo)
    uint16_t   e_oeminfo;                   // OEM information; e_oemid specific
    uint16_t   e_res2[10];                  // Reserved uint16_ts
    int32_t    e_lfanew;                    // File address of new exe header
  }__attribute__ ((packed)) IMAGE_DOS_HEADER;

typedef struct IMAGE_FILE_HEADER {	//20 bytes
    uint16_t    Machine;
    uint16_t    NumberOfSections;
    uint32_t   TimeDateStamp;
    uint32_t   PointerToSymbolTable;
    uint32_t   NumberOfSymbols;
    uint16_t    SizeOfOptionalHeader;
    uint16_t    Characteristics;
} __attribute__ ((packed)) IMAGE_FILE_HEADER;

#define IMAGE_SIZEOF_FILE_HEADER             20


//
// Directory format.
//
typedef struct IMAGE_DATA_DIRECTORY {
    uint32_t   VirtualAddress;
    uint32_t   Size;
} __attribute__ ((packed)) IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

//
// Optional header format.
//

typedef struct IMAGE_OPTIONAL_HEADER {			//96 + ... bytes
    //
    // Standard fields.
    //

    uint16_t    Magic;
    uint8_t    MajorLinkerVersion;
    uint8_t    MinorLinkerVersion;
    uint32_t   SizeOfCode;
    uint32_t   SizeOfInitializedData;
    uint32_t   SizeOfUninitializedData;
    uint32_t   AddressOfEntryPoint;			//+16 bytes
    uint32_t   BaseOfCode;
    uint32_t   BaseOfData;

    //
    // NT additional fields.
    //

    uint32_t   ImageBase;
    uint32_t   SectionAlignment;
    uint32_t   FileAlignment;
    uint16_t    MajorOperatingSystemVersion;
    uint16_t    MinorOperatingSystemVersion;
    uint16_t    MajorImageVersion;
    uint16_t    MinorImageVersion;
    uint16_t    MajorSubsystemVersion;
    uint16_t    MinorSubsystemVersion;
    uint32_t   Win32VersionValue;
    uint32_t   SizeOfImage;
    uint32_t   SizeOfHeaders;
    uint32_t   CheckSum;
    uint16_t    Subsystem;
    uint16_t    DllCharacteristics;
    uint32_t   SizeOfStackReserve;
    uint32_t   SizeOfStackCommit;
    uint32_t   SizeOfHeapReserve;
    uint32_t   SizeOfHeapCommit;
    uint32_t   LoaderFlags;
    uint32_t   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} __attribute__ ((packed)) IMAGE_OPTIONAL_HEADER;


typedef struct IMAGE_NT_HEADERS {				//
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} __attribute__ ((packed)) IMAGE_NT_HEADERS;

typedef struct IMAGE_ROM_OPTIONAL_HEADER {
    uint16_t   Magic;
    uint8_t   MajorLinkerVersion;
    uint8_t   MinorLinkerVersion;
    uint32_t  SizeOfCode;
    uint32_t  SizeOfInitializedData;
    uint32_t  SizeOfUninitializedData;
    uint32_t  AddressOfEntryPoint;
    uint32_t  BaseOfCode;
    uint32_t  BaseOfData;
    uint32_t  BaseOfBss;
    uint32_t  GprMask;
    uint32_t  CprMask[4];
    uint32_t  GpValue;
} __attribute__ ((packed)) IMAGE_ROM_OPTIONAL_HEADER;


#define IMAGE_SIZEOF_ROM_OPTIONAL_HEADER      56
#define IMAGE_SIZEOF_STD_OPTIONAL_HEADER      28
#define IMAGE_SIZEOF_NT_OPTIONAL32_HEADER    224
#define IMAGE_SIZEOF_NT_OPTIONAL64_HEADER    240

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC       0x107


#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct IMAGE_SECTION_HEADER {
    uint8_t    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            uint32_t   PhysicalAddress;
            uint32_t   VirtualSize;
    } Misc;
    uint32_t   VirtualAddress;
    uint32_t   SizeOfRawData;
    uint32_t   PointerToRawData;
    uint32_t   PointerToRelocations;
    uint32_t   PointerToLinenumbers;
    uint16_t    NumberOfRelocations;
    uint16_t    NumberOfLinenumbers;
    uint32_t   Characteristics;
}  __attribute__ ((packed)) IMAGE_SECTION_HEADER;

static const uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;
static const uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
static const uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;

#define IMAGE_SIZEOF_SECTION_HEADER          40

// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor


//
// DLL support.
//

//
// Export Format
//

typedef struct IMAGE_EXPORT_DIRECTORY {
    uint32_t   Characteristics;
    uint32_t   TimeDateStamp;
    uint16_t    MajorVersion;
    uint16_t    MinorVersion;
    uint32_t   Name;
    uint32_t   Base;
    uint32_t   NumberOfFunctions;
    uint32_t   NumberOfNames;
    uint32_t   AddressOfFunctions;     // RVA from base of image
    uint32_t   AddressOfNames;         // RVA from base of image
    uint32_t   AddressOfNameOrdinals;  // RVA from base of image
} __attribute__ ((packed)) IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

//
// Import Format
//

typedef struct IMAGE_IMPORT_BY_NAME {
    uint16_t    Hint;
    uint8_t    Name[1];
} __attribute__ ((packed)) IMAGE_IMPORT_BY_NAME;

#ifndef IMAGE_ORDINAL_FLAG
#define IMAGE_ORDINAL_FLAG  0x80000000
#endif

typedef struct IMAGE_THUNK_DATA {
    union {
        uint32_t ForwarderString; //PBYTE
        uint32_t Function; //Puint32_t
        uint32_t Ordinal;
        uint32_t AddressOfData; //IMAGE_IMPORT_BY_NAME  *
    } u1;
} __attribute__ ((packed)) IMAGE_THUNK_DATA, *PIMAGE_THUNK_DATA, IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

typedef IMAGE_THUNK_DATA * PIMAGE_THUNK_DATA;

typedef struct IMAGE_IMPORT_DESCRIPTOR {
    union {
        uint32_t   Characteristics;            // 0 for terminating null import descriptor
        uint32_t   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    };
    uint32_t   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    uint32_t   ForwarderChain;                 // -1 if no forwarders
    uint32_t   Name;
    uint32_t   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} __attribute__ ((packed))IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;


//
// Based relocation format.
//

typedef struct IMAGE_BASE_RELOCATION {
    uint32_t   VirtualAddress;
    uint32_t   SizeOfBlock;
//  uint16_t    TypeOffset[1];
} __attribute__ ((packed)) IMAGE_BASE_RELOCATION;

typedef IMAGE_BASE_RELOCATION * PIMAGE_BASE_RELOCATION;

#define IMAGE_SIZEOF_BASE_RELOCATION         8

//
// Based relocation types.
//

#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MIPS_JMPADDR          5
#define IMAGE_REL_BASED_SECTION               6
#define IMAGE_REL_BASED_REL32                 7

#define IMAGE_REL_BASED_MIPS_JMPADDR16        9
#define IMAGE_REL_BASED_IA64_IMM64            9
#define IMAGE_REL_BASED_DIR64                 10
#define IMAGE_REL_BASED_HIGH3ADJ              11

typedef struct IMAGE_RELOC_TYPE
{
    unsigned offset:12;
    unsigned type:4;


}__attribute__((packed))IMAGE_RELOC_TYPE;


typedef struct _UNICODE_STRING32 {
  uint16_t Length;
  uint16_t MaximumLength;
  uint32_t  Buffer;
}UNICODE_STRING32, *PUNICODE_STRING32;

typedef struct _BINARY_DATA32 {
  uint16_t Length;
  uint32_t Buffer;
} __attribute__((packed)) BINARY_DATA32, *PBINARY_DATA32;

typedef struct _LIST_ENTRY32 {
    uint32_t Flink;
    uint32_t Blink;
}LIST_ENTRY32, *PLIST_ENTRY32;

#define CONTAINING_RECORD32(address, type, field) ((uint32_t)( \
                                                  (uint32_t)(address) - \
                                                  (uint32_t)(uint64_t)(&((type *)0)->field)))

typedef int32_t NTSTATUS; //MUST BE SIGNED

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NT_INFORMATION(Status) ((ULONG)(Status) >> 30 == 1)
#define NT_WARNING(Status) ((ULONG)(Status) >> 30 == 2)
#define NT_ERROR(Status) ((ULONG)(Status) >> 30 == 3)

typedef struct _MODULE_ENTRY32
{
    LIST_ENTRY32 le_mod;
    uint32_t  unknown[4];
    uint32_t  base;
    uint32_t  driver_start;
    uint32_t  unk1;
    UNICODE_STRING32 driver_Path;
    UNICODE_STRING32 driver_Name;
}   __attribute__((packed)) MODULE_ENTRY32, *PMODULE_ENTRY32;

typedef struct _DRIVER_OBJECT32
{
  uint16_t Type;
  uint16_t Size;

  uint32_t DeviceObject; //PVOID
  uint32_t Flags;

  uint32_t DriverStart; //PVOID
  uint32_t DriverSize; //PVOID
  uint32_t DriverSection; //PVOID
  UNICODE_STRING32 DriverName;

  PUNICODE_STRING32 HardwareDatabase;
  uint32_t FastIoDispatch;
  uint32_t DriverInit;
  uint32_t DriverStartIo;
  uint32_t DriverUnload;
  uint32_t MajorFunction[28];
} __attribute__((packed)) DRIVER_OBJECT32, *PDRIVER_OBJECT32;

extern const char * s_irpMjArray [];

//KPCR is at fs:1c
//This is only valid for XP (no ASLR)
//#define KPCR_ADDRESS  0xFFDFF000

//Offset of the pointer to KPCR relative to the fs register
//#define KPCR_FS_OFFSET 0x1c

//Offset of the DBGKD_GET_VERSION32 data structure in the KPCR
//#define KPCR_KDVERSION32_OFFSET 0x34

//Offset of the KPRCB in the KPCR
//#define KPCR_KPRCB_OFFSET 0x120
//#define KPCR_KPRCB_PTR_OFFSET 0x20


//Offset of the current thread in the FS register
#define FS_CURRENT_THREAD_OFFSET 0x124

//Offset of the pointer to the EPROCESS in the ETHREAD structure
#define ETHREAD_PROCESS_OFFSET_VISTA 0x48
#define ETHREAD_PROCESS_OFFSET_XP 0x44
#define ETHREAD_PROCESS_OFFSET_WIN7 0x50

#define EPROCESS_ACTIVE_PROCESS_LINK_XP 0x88


//#define KD_VERSION_BLOCK (KPCR_ADDRESS + 0x34)
#define PS_LOADED_MODULE_LIST_OFFSET 0x70 //Inside the kd version block

#define BUILD_WINXP     2600
#define BUILD_LONGHORN  5048


//#define KPRCB_OFFSET 0xFFDFF120
#define IRQL_OFFSET 0xFFDFF124
//#define PEB_OFFSET 0x7FFDF000
typedef uint32_t KAFFINITY;

typedef struct _DBGKD_GET_VERSION32 {
    uint16_t    MajorVersion;   // 0xF == Free, 0xC == Checked
    uint16_t    MinorVersion;
    uint16_t    ProtocolVersion;
    uint16_t    Flags;          // DBGKD_VERS_FLAG_XXX
    uint32_t    KernBase;
    uint32_t    PsLoadedModuleList;
    uint16_t    MachineType;
    uint16_t    ThCallbackStack;
    uint16_t    NextCallback;
    uint16_t    FramePointer;
    uint32_t    KiCallUserMode;
    uint32_t    KeUserCallbackDispatcher;
    uint32_t    BreakpointWithStatus;
    uint32_t    Reserved4;
} __attribute__((packed)) DBGKD_GET_VERSION32, *PDBGKD_GET_VERSION32;

typedef struct _DBGKD_GET_VERSION64
{
     uint16_t MajorVersion;
     uint16_t MinorVersion;
     uint8_t ProtocolVersion;
     uint8_t KdSecondaryVersion;
     uint16_t Flags;
     uint16_t MachineType;
     uint8_t MaxPacketType;
     uint8_t MaxStateChange;
     uint8_t MaxManipulate;
     uint8_t Simulation;
     uint16_t Unused[1];
     uint64_t KernBase;
     uint64_t PsLoadedModuleList;
     uint64_t DebuggerDataList;
} __attribute__((packed)) DBGKD_GET_VERSION64, *PDBGKD_GET_VERSION64;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
     LIST_ENTRY32 InLoadOrderLinks;
     LIST_ENTRY32 InMemoryOrderLinks;
     LIST_ENTRY32 InInitializationOrderLinks;
     uint32_t DllBase;
     uint32_t EntryPoint;
     uint32_t SizeOfImage;
     UNICODE_STRING32 FullDllName;
     UNICODE_STRING32 BaseDllName;
     uint32_t Flags;
     uint16_t LoadCount;
     uint16_t TlsIndex;
     union
     {
          LIST_ENTRY32 HashLinks;
          struct
          {
               uint32_t SectionPointer;
               uint32_t CheckSum;
          };
     };
     union
     {
          uint32_t TimeDateStamp;
          uint32_t LoadedImports;
     };
     uint32_t EntryPointActivationContext;
     uint32_t PatchInformation;
}  __attribute__((packed)) LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;


typedef struct _PEB_LDR_DATA32
{
  uint32_t Length;
  uint32_t Initialized;
  uint32_t SsHandle;
  LIST_ENTRY32 InLoadOrderModuleList;
  LIST_ENTRY32 InMemoryOrderModuleList;
  uint32_t EntryInProgress;
}  __attribute__((packed))PEB_LDR_DATA32;

typedef struct _PEB32 {
  uint8_t Unk1[0x8];
  uint32_t ImageBaseAddress;
  uint32_t Ldr; /* PEB_LDR_DATA */
} __attribute__((packed))PEB32;


typedef struct _KPROCESS32_XP {
  uint8_t Unk1[0x18];
  uint32_t DirectoryTableBase;
  uint8_t Unk2[0x50];
} __attribute__((packed))KPROCESS32_XP;

typedef struct _EPROCESS32_XP {
  KPROCESS32_XP Pcb;
  uint32_t ProcessLock;
  uint64_t CreateTime;
  uint64_t ExitTime;
  uint32_t RundownProtect;
  uint32_t UniqueProcessId;
  LIST_ENTRY32 ActiveProcessLinks;
  uint8_t Unk2[0xE4];
  uint8_t ImageFileName[16]; //offset 0x174
  uint32_t Unk3[11];
  uint32_t Peb;
} __attribute__((packed)) EPROCESS32_XP;
typedef struct _KPROCESS32_WIN7 {
  uint8_t Unk1[0x10];
  LIST_ENTRY32 ProfileListHead;
  uint32_t DirectoryTableBase;//offset 18
  uint8_t Unk2[0x7c];//1c
  //98
} __attribute__((packed))KPROCESS32_WIN7;
typedef struct _EPROCESS32_WIN7 {
  KPROCESS32_WIN7 Pcb;
  uint64_t ProcessLock;//offset 98
  uint64_t CreateTime; //a0
  uint64_t ExitTime;	//a8
  uint32_t RundownProtect;//b0
  uint32_t UniqueProcessId;//b4
  LIST_ENTRY32 ActiveProcessLinks;//b8
  uint8_t Unk2[0xac];//c0
  uint8_t ImageFileName[16]; //offset 16c
  uint32_t Unk3[11];
  uint32_t Peb;
} __attribute__((packed)) EPROCESS32_WIN7;
typedef struct _KPROCESS32_VISTA {
  uint8_t Unk1[0x10];
  LIST_ENTRY32 ProfileListHead;
  uint32_t DirectoryTableBase;
  uint8_t Unk2[0x64];
} __attribute__((packed))KPROCESS32_VISTA;

typedef struct _EPROCESS32_VISTA {
  KPROCESS32_VISTA Pcb;
  uint64_t ProcessLock;
  uint64_t CreateTime;
  uint64_t ExitTime;
  uint32_t RundownProtect;
  uint32_t UniqueProcessId;
  LIST_ENTRY32 ActiveProcessLinks;
  uint8_t Unk2[0xa4];
  uint8_t ImageFileName[16]; //offset 14c
  uint32_t Unk3[11];
  uint32_t Peb;
} __attribute__((packed)) EPROCESS32_VISTA;

typedef struct _KAPC_STATE32 {
  LIST_ENTRY32 ApcListHead[2];
  uint32_t Process;  /* Ptr to (E)KPROCESS */
  uint8_t KernelApcInProgress;
  uint8_t KernelApcPending;
  uint8_t UserApcPending;
} __attribute__((packed))KAPC_STATE32;

typedef struct _KTHREAD32
{
    uint8_t Unk1[0x18];
    uint32_t InitialStack;
    uint32_t StackLimit;
    uint8_t Unk2[0x14];
    KAPC_STATE32 ApcState;

    uint8_t Unk3[0x164];

    LIST_ENTRY32 ThreadListEntry;

} __attribute__((packed))KTHREAD32;

/*
+0x000 Header           : _DISPATCHER_HEADER
   +0x010 MutantListHead   : _LIST_ENTRY
   +0x018 InitialStack     : Ptr32 Void
   +0x01c StackLimit       : Ptr32 Void
   +0x020 Teb              : Ptr32 Void
   +0x024 TlsArray         : Ptr32 Void
   +0x028 KernelStack      : Ptr32 Void
   +0x02c DebugActive      : UChar
   +0x02d State            : UChar
   +0x02e Alerted          : [2] UChar
   +0x030 Iopl             : UChar
   +0x031 NpxState         : UChar
   +0x032 Saturation       : Char
   +0x033 Priority         : Char
   +0x034 ApcState         : _KAPC_STATE
   +0x04c ContextSwitches  : Uint4B
   +0x050 IdleSwapBlock    : UChar
   +0x051 Spare0           : [3] UChar
   +0x054 WaitStatus       : Int4B
   +0x058 WaitIrql         : UChar
   +0x059 WaitMode         : Char
   +0x05a WaitNext         : UChar
   +0x05b WaitReason       : UChar

   +0x05c WaitBlockList    : Ptr32 _KWAIT_BLOCK
   +0x060 WaitListEntry    : _LIST_ENTRY
   +0x060 SwapListEntry    : _SINGLE_LIST_ENTRY
   +0x068 WaitTime         : Uint4B
   +0x06c BasePriority     : Char
   +0x06d DecrementCount   : UChar
   +0x06e PriorityDecrement : Char
   +0x06f Quantum          : Char
   +0x070 WaitBlock        : [4] _KWAIT_BLOCK
   +0x0d0 LegoData         : Ptr32 Void
   +0x0d4 KernelApcDisable : Uint4B
   +0x0d8 UserAffinity     : Uint4B
   +0x0dc SystemAffinityActive : UChar
   +0x0dd PowerState       : UChar
   +0x0de NpxIrql          : UChar
   +0x0df InitialNode      : UChar
   +0x0e0 ServiceTable     : Ptr32 Void
   +0x0e4 Queue            : Ptr32 _KQUEUE
   +0x0e8 ApcQueueLock     : Uint4B
   +0x0f0 Timer            : _KTIMER
   +0x118 QueueListEntry   : _LIST_ENTRY
   +0x120 SoftAffinity     : Uint4B
   +0x124 Affinity         : Uint4B
   +0x128 Preempted        : UChar
   +0x129 ProcessReadyQueue : UChar
   +0x12a KernelStackResident : UChar
   +0x12b NextProcessor    : UChar
   +0x12c CallbackStack    : Ptr32 Void
   +0x130 Win32Thread      : Ptr32 Void
   +0x134 TrapFrame        : Ptr32 _KTRAP_FRAME
   +0x138 ApcStatePointer  : [2] Ptr32 _KAPC_STATE
   +0x140 PreviousMode     : Char
   +0x141 EnableStackSwap  : UChar
   +0x142 LargeStack       : UChar
   +0x143 ResourceIndex    : UChar
   +0x144 KernelTime       : Uint4B
   +0x148 UserTime         : Uint4B
   +0x14c SavedApcState    : _KAPC_STATE
   +0x164 Alertable        : UChar
   +0x165 ApcStateIndex    : UChar
   +0x166 ApcQueueable     : UChar
   +0x167 AutoAlignment    : UChar
   +0x168 StackBase        : Ptr32 Void
   +0x16c SuspendApc       : _KAPC
   +0x19c SuspendSemaphore : _KSEMAPHORE
   +0x1b0 ThreadListEntry  : _LIST_ENTRY
   +0x1b8 FreezeCount      : Char
   +0x1b9 SuspendCount     : Char
   +0x1ba IdealProcessor   : UChar
   +0x1bb DisableBoost     : UChar
*/

typedef struct _NT_TIB32
{
     uint32_t ExceptionList;  //PEXCEPTION_REGISTRATION_RECORD
     uint32_t StackBase;   //PVOID
     uint32_t StackLimit; //PVOID
     uint32_t SubSystemTib; //PVOID
     union
     {
          uint32_t FiberData; //PVOID
          uint32_t Version; //ULONG
     };
     uint32_t ArbitraryUserPointer;
     uint32_t Self; //PNT_TIB
}__attribute__((packed)) NT_TIB32;


struct DESCRIPTOR32
{
     uint16_t Pad;
     uint16_t Limit;
     uint32_t Base;
}__attribute__((packed));

struct KSPECIAL_REGISTERS32
{
     uint32_t Cr0;
     uint32_t Cr2;
     uint32_t Cr3;
     uint32_t Cr4;
     uint32_t KernelDr0;
     uint32_t KernelDr1;
     uint32_t KernelDr2;
     uint32_t KernelDr3;
     uint32_t KernelDr6;
     uint32_t KernelDr7;
     DESCRIPTOR32 Gdtr;
     DESCRIPTOR32 Idtr;
     uint16_t Tr;
     uint16_t Ldtr;
     uint32_t Reserved[6];
}__attribute__((packed));


typedef enum _INTERFACE_TYPE {
    InterfaceTypeUndefined = -1,
    Internal,
    Isa,
    Eisa,
    MicroChannel,
    TurboChannel,
    PCIBus,
    VMEBus,
    NuBus,
    PCMCIABus,
    CBus,
    MPIBus,
    MPSABus,
    ProcessorInternal,
    InternalPowerBus,
    PNPISABus,
    PNPBus,
    MaximumInterfaceType
}INTERFACE_TYPE, *PINTERFACE_TYPE;

struct FLOATING_SAVE_AREA
{
     uint32_t ControlWord;
     uint32_t StatusWord;
     uint32_t TagWord;
     uint32_t ErrorOffset;
     uint32_t ErrorSelector;
     uint32_t DataOffset;
     uint32_t DataSelector;
     uint8_t  RegisterArea[80];
     uint32_t Cr0NpxState;
}__attribute__((packed));


struct CONTEXT32
{
     uint32_t ContextFlags;
     uint32_t Dr0;
     uint32_t Dr1;
     uint32_t Dr2;
     uint32_t Dr3;
     uint32_t Dr6;
     uint32_t Dr7;
     FLOATING_SAVE_AREA FloatSave;
     uint32_t SegGs;
     uint32_t SegFs;
     uint32_t SegEs;
     uint32_t SegDs;
     uint32_t Edi;
     uint32_t Esi;
     uint32_t Ebx;
     uint32_t Edx;
     uint32_t Ecx;
     uint32_t Eax;
     uint32_t Ebp;
     uint32_t Eip;
     uint32_t SegCs;
     uint32_t EFlags;
     uint32_t Esp;
     uint32_t SegSs;
     uint8_t ExtendedRegisters[512];
}__attribute__((packed));

#define CONTEXT_i386    0x00010000
#define CONTEXT_i486    0x00010000

#define CONTEXT_CONTROL         (CONTEXT_i386 | 0x00000001L)
#define CONTEXT_INTEGER         (CONTEXT_i386 | 0x00000002L)
#define CONTEXT_SEGMENTS        (CONTEXT_i386 | 0x00000004L)
#define CONTEXT_FLOATING_POINT  (CONTEXT_i386 | 0x00000008L)
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_i386 | 0x00000010L)
#define CONTEXT_EXTENDED_REGISTERS  (CONTEXT_i386 | 0x00000020L)

#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)


#define EXCEPTION_MAXIMUM_PARAMETERS 15

#define EXCEPTION_NONCONTINUABLE   0x0001
#define EXCEPTION_UNWINDING        0x0002
#define EXCEPTION_EXIT_UNWIND      0x0004
#define EXCEPTION_STACK_INVALID    0x0008
#define EXCEPTION_NESTED_CALL      0x0010
#define EXCEPTION_TARGET_UNWIND    0x0020
#define EXCEPTION_COLLIDED_UNWIND  0x0040
#define EXCEPTION_UNWIND           0x0066

#define STATUS_BREAKPOINT 0x80000003

struct EXCEPTION_RECORD32 {
    uint32_t ExceptionCode;
    uint32_t ExceptionFlags;
    uint32_t ExceptionRecord; //struct _EXCEPTION_RECORD
    uint32_t ExceptionAddress; //PVOID
    uint32_t NumberParameters;
    uint32_t ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
}__attribute__((packed));

struct KPROCESSOR_STATE32
{
     CONTEXT32 ContextFrame;
     KSPECIAL_REGISTERS32 SpecialRegisters;
}__attribute__((packed));


static const uint32_t KPRCB32_DPC_STACK_OFFSET = 0x868;
struct KPRCB32 {
    uint16_t MinorVersion;
    uint16_t MajorVersion;
    uint32_t CurrentThread;
    uint32_t NextThread;
    uint32_t IdleThread;
    uint8_t Number;
    uint8_t WakeIdle;
    uint16_t BuildType;
    uint32_t SetMember;
    uint32_t  RestartBlock;

    KPROCESSOR_STATE32 ProcessorState;

} __attribute__((packed));

// Page frame number
typedef uint32_t PFN_NUMBER;

struct PHYSICAL_MEMORY_RUN {
    PFN_NUMBER BasePage;
    PFN_NUMBER PageCount;
}__attribute__((packed));

struct PHYSICAL_MEMORY_DESCRIPTOR {
    uint32_t NumberOfRuns;
    PFN_NUMBER NumberOfPages;
    PHYSICAL_MEMORY_RUN Run[1];
}__attribute__((packed));

static const uint32_t STATUS_SUCCESS = 0;
static const uint32_t STATUS_PENDING = 0x00000103;
static const uint32_t STATUS_BUFFER_TOO_SMALL = 0xC0000023;
static const uint32_t STATUS_UNKNOWN_REVISION = 0xC0000058;
static const uint32_t STATUS_INVALID_SECURITY_DESCR = 0xC0000079;
static const uint32_t STATUS_BAD_DESCRIPTOR_FORMAT = 0xC00000E7;

typedef uint32_t PACL32;
typedef uint32_t PSID32;
typedef uint16_t SECURITY_DESCRIPTOR_CONTROL;
typedef uint32_t PDEVICE_OBJECT32;
typedef uint8_t KPROCESSOR_MODE;
typedef uint8_t BOOLEAN;
typedef uint8_t UCHAR;
typedef int8_t CCHAR;
typedef uint16_t USHORT;
typedef uint16_t CSHORT;
typedef uint32_t ULONG;
typedef int32_t LONG;
typedef uint32_t UINT;
typedef uint32_t HANDLE;

typedef ULONG SECURITY_INFORMATION;
typedef uint32_t LCID;

#define POINTER_ALIGNMENT

enum DEVICE_RELATION_TYPE {
    BusRelations,
    EjectionRelations,
    PowerRelations,
    RemovalRelations,
    TargetDeviceRelation,
    SingleBusRelations
};

enum BUS_QUERY_ID_TYPE{
    BusQueryDeviceID = 0,
    BusQueryHardwareIDs = 1,
    BusQueryCompatibleIDs = 2,
    BusQueryInstanceID = 3,
    BusQueryDeviceSerialNumber = 4
};

enum DEVICE_TEXT_TYPE {
    DeviceTextDescription = 0,
    DeviceTextLocationInformation = 1
};

enum DEVICE_USAGE_NOTIFICATION_TYPE {
    DeviceUsageTypeUndefined,
    DeviceUsageTypePaging,
    DeviceUsageTypeHibernation,
    DeviceUsageTypeDumpFile
};

enum SYSTEM_POWER_STATE {
    PowerSystemUnspecified = 0,
    PowerSystemWorking     = 1,
    PowerSystemSleeping1   = 2,
    PowerSystemSleeping2   = 3,
    PowerSystemSleeping3   = 4,
    PowerSystemHibernate   = 5,
    PowerSystemShutdown    = 6,
    PowerSystemMaximum     = 7
};

enum POWER_STATE_TYPE {
    SystemPowerState = 0,
    DevicePowerState
};

enum DEVICE_POWER_STATE {
    PowerDeviceUnspecified = 0,
    PowerDeviceD0,
    PowerDeviceD1,
    PowerDeviceD2,
    PowerDeviceD3,
    PowerDeviceMaximum
};

enum POWER_ACTION{
    PowerActionNone = 0,
    PowerActionReserved,
    PowerActionSleep,
    PowerActionHibernate,
    PowerActionShutdown,
    PowerActionShutdownReset,
    PowerActionShutdownOff,
    PowerActionWarmEject
};

union POWER_STATE {
    SYSTEM_POWER_STATE SystemState;
    DEVICE_POWER_STATE DeviceState;
};

enum FILE_INFORMATION_CLASS {
    FileDirectoryInformation         = 1,
    FileFullDirectoryInformation,   // 2
    FileBothDirectoryInformation,   // 3
    FileBasicInformation,           // 4
    FileStandardInformation,        // 5
    FileInternalInformation,        // 6
    FileEaInformation,              // 7
    FileAccessInformation,          // 8
    FileNameInformation,            // 9
    FileRenameInformation,          // 10
    FileLinkInformation,            // 11
    FileNamesInformation,           // 12
    FileDispositionInformation,     // 13
    FilePositionInformation,        // 14
    FileFullEaInformation,          // 15
    FileModeInformation,            // 16
    FileAlignmentInformation,       // 17
    FileAllInformation,             // 18
    FileAllocationInformation,      // 19
    FileEndOfFileInformation,       // 20
    FileAlternateNameInformation,   // 21
    FileStreamInformation,          // 22
    FilePipeInformation,            // 23
    FilePipeLocalInformation,       // 24
    FilePipeRemoteInformation,      // 25
    FileMailslotQueryInformation,   // 26
    FileMailslotSetInformation,     // 27
    FileCompressionInformation,     // 28
    FileObjectIdInformation,        // 29
    FileCompletionInformation,      // 30
    FileMoveClusterInformation,     // 31
    FileQuotaInformation,           // 32
    FileReparsePointInformation,    // 33
    FileNetworkOpenInformation,     // 34
    FileAttributeTagInformation,    // 35
    FileTrackingInformation,        // 36
    FileIdBothDirectoryInformation, // 37
    FileIdFullDirectoryInformation, // 38
    FileValidDataLengthInformation, // 39
    FileShortNameInformation,       // 40
    FileMaximumInformation
};

enum FS_INFORMATION_CLASS {
    FileFsVolumeInformation       = 1,
    FileFsLabelInformation,      // 2
    FileFsSizeInformation,       // 3
    FileFsDeviceInformation,     // 4
    FileFsAttributeInformation,  // 5
    FileFsControlInformation,    // 6
    FileFsFullSizeInformation,   // 7
    FileFsObjectIdInformation,   // 8
    FileFsDriverPathInformation, // 9
    FileFsMaximumInformation
};

struct SECURITY_DESCRIPTOR32 {
    uint8_t Revision;
    uint8_t Sbz1;
    SECURITY_DESCRIPTOR_CONTROL Control;
    PSID32 Owner;
    PSID32 Group;
    PACL32 Sacl;
    PACL32 Dacl;
}__attribute__((packed));



typedef struct _FILE_OBJECT *PFILE_OBJECT;

struct IO_STACK_LOCATION {
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    UCHAR Flags;
    UCHAR Control;

    union {
        struct {
            uint32_t SecurityContext;
            ULONG Options;
            USHORT POINTER_ALIGNMENT FileAttributes;
            USHORT ShareAccess;
            ULONG POINTER_ALIGNMENT EaLength;
        } Create;

        struct {
            ULONG Length;
            ULONG POINTER_ALIGNMENT Key;
            uint64_t ByteOffset;
        } Read;

        struct {
            ULONG Length;
            ULONG POINTER_ALIGNMENT Key;
            uint64_t ByteOffset;
        } Write;

        struct {
            ULONG Length;
            FILE_INFORMATION_CLASS POINTER_ALIGNMENT FileInformationClass;
        } QueryFile;

        struct {
            ULONG Length;
            FILE_INFORMATION_CLASS POINTER_ALIGNMENT FileInformationClass;
            uint32_t FileObject;
            union {
                struct {
                    BOOLEAN ReplaceIfExists;
                    BOOLEAN AdvanceOnly;
                };
                ULONG ClusterCount;
                HANDLE DeleteHandle;
            };
        } SetFile;

        struct {
            ULONG Length;
            FS_INFORMATION_CLASS POINTER_ALIGNMENT FsInformationClass;
        } QueryVolume;


        struct {
            ULONG OutputBufferLength;
            ULONG POINTER_ALIGNMENT InputBufferLength;
            ULONG POINTER_ALIGNMENT IoControlCode;
            uint32_t Type3InputBuffer;
        } DeviceIoControl;


        struct {
            SECURITY_INFORMATION SecurityInformation;
            ULONG POINTER_ALIGNMENT Length;
        } QuerySecurity;


        struct {
            SECURITY_INFORMATION SecurityInformation;
            uint32_t SecurityDescriptor;
        } SetSecurity;


        struct {
            uint32_t Vpb;
            uint32_t DeviceObject;
        } MountVolume;


        struct {
            uint32_t Vpb;
            uint32_t DeviceObject;
        } VerifyVolume;

        struct {
            uint32_t Srb;
        } Scsi;

        struct {
            DEVICE_RELATION_TYPE Type;
        } QueryDeviceRelations;

        struct {
            uint32_t InterfaceType;
            USHORT Size;
            USHORT Version;
            uint32_t Interface;
            uint32_t InterfaceSpecificData;
        } QueryInterface;

        struct {
            uint32_t Capabilities;
        } DeviceCapabilities;

        struct {
            uint32_t IoResourceRequirementList;
        } FilterResourceRequirements;

        struct {
            ULONG WhichSpace;
            uint32_t Buffer;
            ULONG Offset;
            ULONG POINTER_ALIGNMENT Length;
        } ReadWriteConfig;

        struct {
            BOOLEAN Lock;
        } SetLock;

        struct {
            BUS_QUERY_ID_TYPE IdType;
        } QueryId;

        struct {
            DEVICE_TEXT_TYPE DeviceTextType;
            LCID POINTER_ALIGNMENT LocaleId;
        } QueryDeviceText;

        struct {
            BOOLEAN InPath;
            BOOLEAN Reserved[3];
            DEVICE_USAGE_NOTIFICATION_TYPE POINTER_ALIGNMENT Type;
        } UsageNotification;

        struct {
            SYSTEM_POWER_STATE PowerState;
        } WaitWake;

        struct {
            uint32_t PowerSequence;
        } PowerSequence;

        struct {
            ULONG SystemContext;
            POWER_STATE_TYPE POINTER_ALIGNMENT Type;
            POWER_STATE POINTER_ALIGNMENT State;
            POWER_ACTION POINTER_ALIGNMENT ShutdownType;
        } Power;

        struct {
            uint32_t AllocatedResources;
            uint32_t AllocatedResourcesTranslated;
        } StartDevice;

        struct {
            uint32_t ProviderId;
            uint32_t DataPath;
            ULONG BufferSize;
            uint32_t Buffer;
        } WMI;

        struct {
            uint32_t Argument1;
            uint32_t Argument2;
            uint32_t Argument3;
            uint32_t Argument4;
        } Others;

    } Parameters;

    uint32_t DeviceObject;

    uint32_t FileObject; //FILE_OBJECT

    uint32_t CompletionRoutine;

    uint32_t Context;

}__attribute__((packed));

struct KAPC32 {
    uint16_t Type;
    uint16_t Size;
    uint32_t Spare0;
    uint32_t Thread;
    LIST_ENTRY32 ApcListEntry;
    uint32_t KernelRoutine;
    uint32_t RundownRoutine;
    uint32_t NormalRoutine;
    uint32_t NormalContext;

    uint32_t SystemArgument1;
    uint32_t SystemArgument2;
    uint8_t ApcStateIndex;
    KPROCESSOR_MODE ApcMode;
    BOOLEAN Inserted;
};

struct KDEVICE_QUEUE_ENTRY32 {
    LIST_ENTRY32 DeviceListEntry;
    uint32_t SortKey;
    BOOLEAN Inserted;
};

struct IO_STATUS_BLOCK32 {
    union {
        uint32_t Status;
        uint32_t Pointer;
    };

    uint32_t Information;
};

struct IRP {
    uint16_t Type;
    uint16_t Size;
    uint32_t MdlAddress;
    uint32_t Flags;

    union {
        uint32_t MasterIrp;
        int32_t IrpCount;
        uint32_t SystemBuffer;
    } AssociatedIrp;

    LIST_ENTRY32 ThreadListEntry;
    IO_STATUS_BLOCK32 IoStatus;
    int8_t RequestorMode;
    uint8_t PendingReturned;
    int8_t StackCount;
    int8_t CurrentLocation;
    uint8_t Cancel;
    uint8_t CancelIrql;
    int8_t ApcEnvironment;
    uint8_t AllocationFlags;

    uint32_t UserIosb;
    uint32_t UserEvent;
    union {
        struct {
            uint32_t UserApcRoutine;
            uint32_t UserApcContext;
        } AsynchronousParameters;
        uint64_t AllocationSize;
    } Overlay;

    uint32_t CancelRoutine;
    uint32_t UserBuffer;

    union {
        struct {
            union {
                KDEVICE_QUEUE_ENTRY32 DeviceQueueEntry;
                struct {
                    uint32_t DriverContext[4];
                } ;
            } ;

            uint32_t Thread;
            uint32_t AuxiliaryBuffer;

            struct {
                LIST_ENTRY32 ListEntry;
                union {
                    uint32_t CurrentStackLocation; //struct IO_STACK_LOCATION *
                    uint32_t PacketType;
                };
            };
            uint32_t OriginalFileObject;
        } Overlay;

        KAPC32 Apc;
        uint32_t CompletionKey;

    } Tail;

};

static const uint32_t  IRP_MJ_CREATE                     = 0x00;
static const uint32_t  IRP_MJ_CREATE_NAMED_PIPE          = 0x01;
static const uint32_t  IRP_MJ_CLOSE                      = 0x02;
static const uint32_t  IRP_MJ_READ                       = 0x03;
static const uint32_t  IRP_MJ_WRITE                      = 0x04;
static const uint32_t  IRP_MJ_QUERY_INFORMATION          = 0x05;
static const uint32_t  IRP_MJ_SET_INFORMATION            = 0x06;
static const uint32_t  IRP_MJ_QUERY_EA                   = 0x07;
static const uint32_t  IRP_MJ_SET_EA                     = 0x08;
static const uint32_t  IRP_MJ_FLUSH_BUFFERS              = 0x09;
static const uint32_t  IRP_MJ_QUERY_VOLUME_INFORMATION   = 0x0a;
static const uint32_t  IRP_MJ_SET_VOLUME_INFORMATION     = 0x0b;
static const uint32_t  IRP_MJ_DIRECTORY_CONTROL          = 0x0c;
static const uint32_t  IRP_MJ_FILE_SYSTEM_CONTROL        = 0x0d;
static const uint32_t  IRP_MJ_DEVICE_CONTROL             = 0x0e;
static const uint32_t  IRP_MJ_INTERNAL_DEVICE_CONTROL    = 0x0f;
static const uint32_t  IRP_MJ_SCSI                       = 0x0f;
static const uint32_t  IRP_MJ_SHUTDOWN                   = 0x10;
static const uint32_t  IRP_MJ_LOCK_CONTROL               = 0x11;
static const uint32_t  IRP_MJ_CLEANUP                    = 0x12;
static const uint32_t  IRP_MJ_CREATE_MAILSLOT            = 0x13;
static const uint32_t  IRP_MJ_QUERY_SECURITY             = 0x14;
static const uint32_t  IRP_MJ_SET_SECURITY               = 0x15;
static const uint32_t  IRP_MJ_POWER                      = 0x16;
static const uint32_t  IRP_MJ_SYSTEM_CONTROL             = 0x17;
static const uint32_t  IRP_MJ_DEVICE_CHANGE              = 0x18;
static const uint32_t  IRP_MJ_QUERY_QUOTA                = 0x19;
static const uint32_t  IRP_MJ_SET_QUOTA                  = 0x1a;
static const uint32_t  IRP_MJ_PNP                        = 0x1b;
static const uint32_t  IRP_MJ_PNP_POWER                  = 0x1b;
static const uint32_t  IRP_MJ_MAXIMUM_FUNCTION           = 0x1b;

} //namespace windows
} //namespace dbaf
/*
 * 取相对地址时请注意内核模块对应的文件
 ntoskrnl.exe ---Uniprocessor单处理器，不支持PAE（QEMU中默认是使用的这一个）
 ntkrnlpa.exe ---Uniprocessor单处理器，支持PAE（VMWare中默认是使用的这一个）
 ntkrnlmp.exe ---Multiprocessor多处理器，不支持PAE
 ntkrpamp.exe ---Mulitiprocessor多处理器，支持PAE
 */
/**
 * 其实KeVersionBlock指向的是_DBGKD_GET_VERSION64结构体，
 * 这个结构体的大小只有0x28，这个结构信息还可以通过 IG_GET_KERNEL_VERSION的IOCTL操作来得到
 * 紧跟在后面的是KDDEBUGGER_DATA64（不同版本的系统结构不一样，但是新加入的成员都是放在结构体的后面）
 * 系统中很多未导出的重要变量都在此结构体中比如PsLoadedModuleList，PsActiveProcessHead，
 * PspCidTable，ObpRootDirectoryObject，ObpTypeObjectType，KiProcessorBlock等
typedef struct _DBGKD_GET_VERSION64 {
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    UCHAR   ProtocolVersion;
    UCHAR   KdSecondaryVersion; // Cannot be 'A' for compat with dump header
    USHORT  Flags;
    USHORT  MachineType;
    UCHAR   MaxPacketType;
    UCHAR   MaxStateChange;
    UCHAR   MaxManipulate;
    UCHAR   Simulation;
    USHORT  Unused[1];
    ULONG64 KernBase;
    ULONG64 PsLoadedModuleList;
    ULONG64 DebuggerDataList;
} DBGKD_GET_VERSION64, *PDBGKD_GET_VERSION64;

typedef struct _DBGKD_DEBUG_DATA_HEADER64 {
    LIST_ENTRY64 List;
    ULONG           OwnerTag;
    ULONG           Size;
} DBGKD_DEBUG_DATA_HEADER64, *PDBGKD_DEBUG_DATA_HEADER64;

typedef struct _KDDEBUGGER_DATA64 {
    DBGKD_DEBUG_DATA_HEADER64 Header;
    ULONG64   KernBase;
    ULONG64   BreakpointWithStatus;       // address of breakpoint
    ULONG64   SavedContext;
    USHORT  ThCallbackStack;            // offset in thread data
    USHORT  NextCallback;               // saved pointer to next callback frame
    USHORT  FramePointer;               // saved frame pointer
    USHORT  PaeEnabled:1;
    ULONG64   KiCallUserMode;             // kernel routine
    ULONG64   KeUserCallbackDispatcher;   // address in ntdll
    ULONG64   PsLoadedModuleList;        // our target
    ULONG64   PsActiveProcessHead;       // our target
    ULONG64   PspCidTable;
    ULONG64   ExpSystemResourcesList;
    ULONG64   ExpPagedPoolDescriptor;
    ULONG64   ExpNumberOfPagedPools;
    ULONG64   KeTimeIncrement;
    ULONG64   KeBugCheckCallbackListHead;
    ULONG64   KiBugcheckData;
    ULONG64   IopErrorLogListHead;
    ULONG64   ObpRootDirectoryObject;
    ULONG64   ObpTypeObjectType;
    ULONG64   MmSystemCacheStart;
    ULONG64   MmSystemCacheEnd;
    ULONG64   MmSystemCacheWs;
    ULONG64   MmPfnDatabase;
    ULONG64   MmSystemPtesStart;
    ULONG64   MmSystemPtesEnd;
    ULONG64   MmSubsectionBase;
    ULONG64   MmNumberOfPagingFiles;
    ULONG64   MmLowestPhysicalPage;
    ULONG64   MmHighestPhysicalPage;
    ULONG64   MmNumberOfPhysicalPages;
    ULONG64   MmMaximumNonPagedPoolInBytes;
    ULONG64   MmNonPagedSystemStart;
    ULONG64   MmNonPagedPoolStart;
    ULONG64   MmNonPagedPoolEnd;
    ULONG64   MmPagedPoolStart;
    ULONG64   MmPagedPoolEnd;
    ULONG64   MmPagedPoolInformation;
    ULONG64   MmPageSize;
    ULONG64   MmSizeOfPagedPoolInBytes;
    ULONG64   MmTotalCommitLimit;
    ULONG64   MmTotalCommittedPages;
    ULONG64   MmSharedCommit;
    ULONG64   MmDriverCommit;
    ULONG64   MmProcessCommit;
    ULONG64   MmPagedPoolCommit;
    ULONG64   MmExtendedCommit;
    ULONG64   MmZeroedPageListHead;
    ULONG64   MmFreePageListHead;
    ULONG64   MmStandbyPageListHead;
    ULONG64   MmModifiedPageListHead;
    ULONG64   MmModifiedNoWritePageListHead;
    ULONG64   MmAvailablePages;
    ULONG64   MmResidentAvailablePages;
    ULONG64   PoolTrackTable;
    ULONG64   NonPagedPoolDescriptor;
    ULONG64   MmHighestUserAddress;
    ULONG64   MmSystemRangeStart;
    ULONG64   MmUserProbeAddress;
    ULONG64   KdPrintCircularBuffer;
    ULONG64   KdPrintCircularBufferEnd;
    ULONG64   KdPrintWritePointer;
    ULONG64   KdPrintRolloverCount;
    ULONG64   MmLoadedUserImageList;
    // NT 5.1 Addition
    ULONG64   NtBuildLab;
    ULONG64   KiNormalSystemCall;
    // NT 5.0 hotfix addition
    ULONG64   KiProcessorBlock;
    ULONG64   MmUnloadedDrivers;
    ULONG64   MmLastUnloadedDriver;
    ULONG64   MmTriageActionTaken;
    ULONG64   MmSpecialPoolTag;
    ULONG64   KernelVerifier;
    ULONG64   MmVerifierData;
    ULONG64   MmAllocatedNonPagedPool;
    ULONG64   MmPeakCommitment;
    ULONG64   MmTotalCommitLimitMaximum;
    ULONG64   CmNtCSDVersion;
    // NT 5.1 Addition
    ULONG64   MmPhysicalMemoryBlock;
    ULONG64   MmSessionBase;
    ULONG64   MmSessionSize;
    ULONG64   MmSystemParentTablePage;
    // Server 2003 addition
    ULONG64   MmVirtualTranslationBase;
    USHORT    OffsetKThreadNextProcessor;
    USHORT    OffsetKThreadTeb;
    USHORT    OffsetKThreadKernelStack;
    USHORT    OffsetKThreadInitialStack;
    USHORT    OffsetKThreadApcProcess;
    USHORT    OffsetKThreadState;
    USHORT    OffsetKThreadBStore;
    USHORT    OffsetKThreadBStoreLimit;
    USHORT    SizeEProcess;
    USHORT    OffsetEprocessPeb;
    USHORT    OffsetEprocessParentCID;
    USHORT    OffsetEprocessDirectoryTableBase;
    USHORT    SizePrcb;
    USHORT    OffsetPrcbDpcRoutine;
    USHORT    OffsetPrcbCurrentThread;
    USHORT    OffsetPrcbMhz;
    USHORT    OffsetPrcbCpuType;
    USHORT    OffsetPrcbVendorString;
    USHORT    OffsetPrcbProcStateContext;
    USHORT    OffsetPrcbNumber;
    USHORT    SizeEThread;
    ULONG64   KdPrintCircularBufferPtr;
    ULONG64   KdPrintBufferSize;
    ULONG64   KeLoaderBlock;
    USHORT    SizePcr;
    USHORT    OffsetPcrSelfPcr;
    USHORT    OffsetPcrCurrentPrcb;
    USHORT    OffsetPcrContainedPrcb;
    USHORT    OffsetPcrInitialBStore;
    USHORT    OffsetPcrBStoreLimit;
    USHORT    OffsetPcrInitialStack;
    USHORT    OffsetPcrStackLimit;
    USHORT    OffsetPrcbPcrPage;
    USHORT    OffsetPrcbProcStateSpecialReg;
    USHORT    GdtR0Code;
    USHORT    GdtR0Data;
    USHORT    GdtR0Pcr;
    USHORT    GdtR3Code;
    USHORT    GdtR3Data;
    USHORT    GdtR3Teb;
    USHORT    GdtLdt;
    USHORT    GdtTss;
    USHORT    Gdt64R3CmCode;
    USHORT    Gdt64R3CmTeb;
    ULONG64   IopNumTriageDumpDataBlocks;
    ULONG64   IopTriageDumpDataBlocks;
    // Longhorn addition
    ULONG64   VfCrashDataBlock;
    ULONG64   MmBadPagesDetected;
    ULONG64   MmZeroedPageSingleBitErrorsDetected;
    // Windows 7 addition
    ULONG64   EtwpDebuggerData;
    USHORT    OffsetPrcbContext;
} KDDEBUGGER_DATA64, *PKDDEBUGGER_DATA64;

由于其紧紧跟在KdVersionBlock后面，因此可以直接通过便宜量获取相关数据，比如内核加载基地址。
PKDDEBUGGER_DATA64 KdDebuggerData64;
KdDebuggerData64=(PKDDEBUGGER_DATA64)((ULONG_PTR)KdVersionBlock+sizeof(DBGKD_GET_VERSION64));
DbgPrint("KernelBase=0x%08x\n",(PDBGKD_GET_VERSION64)KdVersionBlock->KernBase);
DbgPrint("KernelBase=0x%08x\n",KdDebuggerData64->KernBase);

 */
/**
 * XP SP3
kd> dt _IMAGE_NT_HEADERS
ntdll!_IMAGE_NT_HEADERS
   +0x000 Signature        : Uint4B
   +0x004 FileHeader       : _IMAGE_FILE_HEADER
   +0x018 OptionalHeader   : _IMAGE_OPTIONAL_HEADER

kd>  dt _DBGKD_GET_VERSION64
nt!_DBGKD_GET_VERSION64
   +0x000 MajorVersion     : Uint2B
   +0x002 MinorVersion     : Uint2B
   +0x004 ProtocolVersion  : Uint2B
   +0x006 Flags            : Uint2B
   +0x008 MachineType      : Uint2B
   +0x00a MaxPacketType    : UChar
   +0x00b MaxStateChange   : UChar
   +0x00c MaxManipulate    : UChar
   +0x00d Simulation       : UChar
   +0x00e Unused           : [1] Uint2B
   +0x010 KernBase         : Uint8B
   +0x018 PsLoadedModuleList : Uint8B
   +0x020 DebuggerDataList : Uint8B

kd> dt _kpcr
nt!_KPCR
   +0x000 NtTib            : _NT_TIB
   +0x01c SelfPcr          : Ptr32 _KPCR
   +0x020 Prcb             : Ptr32 _KPRCB
   +0x024 Irql             : UChar
   +0x028 IRR              : Uint4B
   +0x02c IrrActive        : Uint4B
   +0x030 IDR              : Uint4B
   +0x034 KdVersionBlock   : Ptr32 Void
   +0x038 IDT              : Ptr32 _KIDTENTRY
   +0x03c GDT              : Ptr32 _KGDTENTRY
   +0x040 TSS              : Ptr32 _KTSS
   +0x044 MajorVersion     : Uint2B
   +0x046 MinorVersion     : Uint2B
   +0x048 SetMember        : Uint4B
   +0x04c StallScaleFactor : Uint4B
   +0x050 DebugActive      : UChar
   +0x051 Number           : UChar
   +0x052 Spare0           : UChar
   +0x053 SecondLevelCacheAssociativity : UChar
   +0x054 VdmAlert         : Uint4B
   +0x058 KernelReserved   : [14] Uint4B
   +0x090 SecondLevelCacheSize : Uint4B
   +0x094 HalReserved      : [16] Uint4B
   +0x0d4 InterruptMode    : Uint4B
   +0x0d8 Spare1           : UChar
   +0x0dc KernelReserved2  : [17] Uint4B
   +0x120 PrcbData         : _KPRCB

kd> dt _KPRCB
ntdll!_KPRCB
   +0x000 MinorVersion     : Uint2B
   +0x002 MajorVersion     : Uint2B
   +0x004 CurrentThread    : Ptr32 _KTHREAD
   +0x008 NextThread       : Ptr32 _KTHREAD
   +0x00c IdleThread       : Ptr32 _KTHREAD
   +0x010 Number           : Char
   +0x011 Reserved         : Char
   +0x012 BuildType        : Uint2B
   +0x014 SetMember        : Uint4B
   +0x018 CpuType          : Char
   +0x019 CpuID            : Char
   +0x01a CpuStep          : Uint2B
   +0x01c ProcessorState   : _KPROCESSOR_STATE
   +0x33c KernelReserved   : [16] Uint4B
   +0x37c HalReserved      : [16] Uint4B
   +0x3bc PrcbPad0         : [92] UChar
   +0x418 LockQueue        : [16] _KSPIN_LOCK_QUEUE
   +0x498 PrcbPad1         : [8] UChar
   +0x4a0 NpxThread        : Ptr32 _KTHREAD
   +0x4a4 InterruptCount   : Uint4B
   +0x4a8 KernelTime       : Uint4B
   +0x4ac UserTime         : Uint4B
   +0x4b0 DpcTime          : Uint4B
   +0x4b4 DebugDpcTime     : Uint4B
   +0x4b8 InterruptTime    : Uint4B
   +0x4bc AdjustDpcThreshold : Uint4B
   +0x4c0 PageColor        : Uint4B
   +0x4c4 SkipTick         : Uint4B
   +0x4c8 MultiThreadSetBusy : UChar
   +0x4c9 Spare2           : [3] UChar
   +0x4cc ParentNode       : Ptr32 _KNODE
   +0x4d0 MultiThreadProcessorSet : Uint4B
   +0x4d4 MultiThreadSetMaster : Ptr32 _KPRCB
   +0x4d8 ThreadStartCount : [2] Uint4B
   +0x4e0 CcFastReadNoWait : Uint4B
   +0x4e4 CcFastReadWait   : Uint4B
   +0x4e8 CcFastReadNotPossible : Uint4B
   +0x4ec CcCopyReadNoWait : Uint4B
   +0x4f0 CcCopyReadWait   : Uint4B
   +0x4f4 CcCopyReadNoWaitMiss : Uint4B
   +0x4f8 KeAlignmentFixupCount : Uint4B
   +0x4fc KeContextSwitches : Uint4B
   +0x500 KeDcacheFlushCount : Uint4B
   +0x504 KeExceptionDispatchCount : Uint4B
   +0x508 KeFirstLevelTbFills : Uint4B
   +0x50c KeFloatingEmulationCount : Uint4B
   +0x510 KeIcacheFlushCount : Uint4B
   +0x514 KeSecondLevelTbFills : Uint4B
   +0x518 KeSystemCalls    : Uint4B
   +0x51c SpareCounter0    : [1] Uint4B
   +0x520 PPLookasideList  : [16] _PP_LOOKASIDE_LIST
   +0x5a0 PPNPagedLookasideList : [32] _PP_LOOKASIDE_LIST
   +0x6a0 PPPagedLookasideList : [32] _PP_LOOKASIDE_LIST
   +0x7a0 PacketBarrier    : Uint4B
   +0x7a4 ReverseStall     : Uint4B
   +0x7a8 IpiFrame         : Ptr32 Void
   +0x7ac PrcbPad2         : [52] UChar
   +0x7e0 CurrentPacket    : [3] Ptr32 Void
   +0x7ec TargetSet        : Uint4B
   +0x7f0 WorkerRoutine    : Ptr32     void
   +0x7f4 IpiFrozen        : Uint4B
   +0x7f8 PrcbPad3         : [40] UChar
   +0x820 RequestSummary   : Uint4B
   +0x824 SignalDone       : Ptr32 _KPRCB
   +0x828 PrcbPad4         : [56] UChar
   +0x860 DpcListHead      : _LIST_ENTRY
   +0x868 DpcStack         : Ptr32 Void
   +0x86c DpcCount         : Uint4B
   +0x870 DpcQueueDepth    : Uint4B
   +0x874 DpcRoutineActive : Uint4B
   +0x878 DpcInterruptRequested : Uint4B
   +0x87c DpcLastCount     : Uint4B
   +0x880 DpcRequestRate   : Uint4B
   +0x884 MaximumDpcQueueDepth : Uint4B
   +0x888 MinimumDpcRate   : Uint4B
   +0x88c QuantumEnd       : Uint4B
   +0x890 PrcbPad5         : [16] UChar
   +0x8a0 DpcLock          : Uint4B
   +0x8a4 PrcbPad6         : [28] UChar
   +0x8c0 CallDpc          : _KDPC
   +0x8e0 ChainedInterruptList : Ptr32 Void
   +0x8e4 LookasideIrpFloat : Int4B
   +0x8e8 SpareFields0     : [6] Uint4B
   +0x900 VendorString     : [13] UChar
   +0x90d InitialApicId    : UChar
   +0x90e LogicalProcessorsPerPhysicalProcessor : UChar
   +0x910 MHz              : Uint4B
   +0x914 FeatureBits      : Uint4B
   +0x918 UpdateSignature  : _LARGE_INTEGER
   +0x920 NpxSaveArea      : _FX_SAVE_AREA
   +0xb30 PowerState       : _PROCESSOR_POWER_STATE


内核态
获取数据：
kd> dd fs:[0]
0030:00000000  f8b04e04 f8b05df0 f8b03000 00000000
0030:00000010  00000000 00000000 00000000 ffdff000
0030:00000020  ffdff120 00000000 00000000 00000000
0030:00000030  ffffffff 80546b38 8003f400 8003f000
0030:00000040  80042000 00010001 00000001 00000a22
0030:00000050  00000000 00000000 00000000 00000000
0030:00000060  00000000 00000000 00000000 00000000
0030:00000070  00000000 00000000 00000000 00000000
kd> !pcr
KPCR for Processor 0 at ffdff000:
    Major 1 Minor 1
	NtTib.ExceptionList: f8b04e04
	    NtTib.StackBase: f8b05df0
	   NtTib.StackLimit: f8b03000
	 NtTib.SubSystemTib: 00000000
	      NtTib.Version: 00000000
	  NtTib.UserPointer: 00000000
	      NtTib.SelfTib: 00000000

	            SelfPcr: ffdff000
	               Prcb: ffdff120
	               Irql: 00000000
	                IRR: 00000000
	                IDR: ffffffff
	      InterruptMode: 00000000
	                IDT: 8003f400
	                GDT: 8003f000
	                TSS: 80042000

	      CurrentThread: 821b6020
	         NextThread: 00000000
	         IdleThread: 805537c0

	          DpcQueue:
kd> dt nt!_KPCR ffdff000
   +0x000 NtTib            : _NT_TIB
   +0x01c SelfPcr          : 0xffdff000 _KPCR
   +0x020 Prcb             : 0xffdff120 _KPRCB
   +0x024 Irql             : 0 ''
   +0x028 IRR              : 0
   +0x02c IrrActive        : 0
   +0x030 IDR              : 0xffffffff
   +0x034 KdVersionBlock   : 0x80546b38
   +0x038 IDT              : 0x8003f400 _KIDTENTRY
   +0x03c GDT              : 0x8003f000 _KGDTENTRY
   +0x040 TSS              : 0x80042000 _KTSS
   +0x044 MajorVersion     : 1
   +0x046 MinorVersion     : 1
   +0x048 SetMember        : 1
   +0x04c StallScaleFactor : 0xa22
   +0x050 DebugActive      : 0 ''
   +0x051 Number           : 0 ''
   +0x052 Spare0           : 0 ''
   +0x053 SecondLevelCacheAssociativity : 0 ''
   +0x054 VdmAlert         : 0
   +0x058 KernelReserved   : [14] 0
   +0x090 SecondLevelCacheSize : 0
   +0x094 HalReserved      : [16] 0x200
   +0x0d4 InterruptMode    : 0
   +0x0d8 Spare1           : 0 ''
   +0x0dc KernelReserved2  : [17] 0
   +0x120 PrcbData         : _KPRCB
kd> dt nt!_KPRCB ffdff120
   +0x000 MinorVersion     : 1
   +0x002 MajorVersion     : 1
   +0x004 CurrentThread    : 0x821b6020 _KTHREAD
   +0x008 NextThread       : (null)
   +0x00c IdleThread       : 0x805537c0 _KTHREAD
   +0x010 Number           : 0 ''
   +0x011 Reserved         : 0 ''
   +0x012 BuildType        : 2
   +0x014 SetMember        : 1
   +0x018 CpuType          : 6 ''
   +0x019 CpuID            : 1 ''
   +0x01a CpuStep          : 0x3a09
   +0x01c ProcessorState   : _KPROCESSOR_STATE
   +0x33c KernelReserved   : [16] 0
   +0x37c HalReserved      : [16] 0
   +0x3bc PrcbPad0         : [92]  ""
   +0x418 LockQueue        : [16] _KSPIN_LOCK_QUEUE
   +0x498 PrcbPad1         : [8]  ""
   +0x4a0 NpxThread        : 0x821b6020 _KTHREAD
   +0x4a4 InterruptCount   : 0x318
   +0x4a8 KernelTime       : 0xcd
   +0x4ac UserTime         : 0
   +0x4b0 DpcTime          : 2
   +0x4b4 DebugDpcTime     : 0
   +0x4b8 InterruptTime    : 6
   +0x4bc AdjustDpcThreshold : 0x13
   +0x4c0 PageColor        : 0
   +0x4c4 SkipTick         : 0
   +0x4c8 MultiThreadSetBusy : 0 ''
   +0x4c9 Spare2           : [3]  ""
   +0x4cc ParentNode       : 0x80553e80 _KNODE
   +0x4d0 MultiThreadProcessorSet : 1
   +0x4d4 MultiThreadSetMaster : (null)
   +0x4d8 ThreadStartCount : [2] 0
   +0x4e0 CcFastReadNoWait : 0
   +0x4e4 CcFastReadWait   : 0
   +0x4e8 CcFastReadNotPossible : 0
   +0x4ec CcCopyReadNoWait : 0
   +0x4f0 CcCopyReadWait   : 0
   +0x4f4 CcCopyReadNoWaitMiss : 0
   +0x4f8 KeAlignmentFixupCount : 0
   +0x4fc KeContextSwitches : 0x2a68
   +0x500 KeDcacheFlushCount : 0
   +0x504 KeExceptionDispatchCount : 0x3d
   +0x508 KeFirstLevelTbFills : 0
   +0x50c KeFloatingEmulationCount : 0
   +0x510 KeIcacheFlushCount : 0
   +0x514 KeSecondLevelTbFills : 0
   +0x518 KeSystemCalls    : 0x18edb
   +0x51c SpareCounter0    : [1] 0
   +0x520 PPLookasideList  : [16] _PP_LOOKASIDE_LIST
   +0x5a0 PPNPagedLookasideList : [32] _PP_LOOKASIDE_LIST
   +0x6a0 PPPagedLookasideList : [32] _PP_LOOKASIDE_LIST
   +0x7a0 PacketBarrier    : 0
   +0x7a4 ReverseStall     : 0
   +0x7a8 IpiFrame         : (null)
   +0x7ac PrcbPad2         : [52]  ""
   +0x7e0 CurrentPacket    : [3] (null)
   +0x7ec TargetSet        : 0
   +0x7f0 WorkerRoutine    : (null)
   +0x7f4 IpiFrozen        : 0
   +0x7f8 PrcbPad3         : [40]  ""
   +0x820 RequestSummary   : 0
   +0x824 SignalDone       : (null)
   +0x828 PrcbPad4         : [56]  ""
   +0x860 DpcListHead      : _LIST_ENTRY [ 0xffdff980 - 0xffdff980 ]
   +0x868 DpcStack         : 0xf8ace000
   +0x86c DpcCount         : 0x9b1
   +0x870 DpcQueueDepth    : 0
   +0x874 DpcRoutineActive : 0
   +0x878 DpcInterruptRequested : 0
   +0x87c DpcLastCount     : 0x9b1
   +0x880 DpcRequestRate   : 1
   +0x884 MaximumDpcQueueDepth : 1
   +0x888 MinimumDpcRate   : 3
   +0x88c QuantumEnd       : 0
   +0x890 PrcbPad5         : [16]  ""
   +0x8a0 DpcLock          : 0
   +0x8a4 PrcbPad6         : [28]  ""
   +0x8c0 CallDpc          : _KDPC
   +0x8e0 ChainedInterruptList : (null)
   +0x8e4 LookasideIrpFloat : 1536
   +0x8e8 SpareFields0     : [6] 0
   +0x900 VendorString     : [13]  "GenuineIntel"
   +0x90d InitialApicId    : 0 ''
   +0x90e LogicalProcessorsPerPhysicalProcessor : 0x1 ''
   +0x910 MHz              : 0xa22
   +0x914 FeatureBits      : 0x20033fff
   +0x918 UpdateSignature  : _LARGE_INTEGER 0x15`00000000
   +0x920 NpxSaveArea      : _FX_SAVE_AREA
   +0xb30 PowerState       : _PROCESSOR_POWER_STATE

kd> dt nt!_DBGKD_GET_VERSION64 0x80546b38
   +0x000 MajorVersion     : 0xf
   +0x002 MinorVersion     : 0xa28
   +0x004 ProtocolVersion  : 6
   +0x006 Flags            : 2
   +0x008 MachineType      : 0x14c
   +0x00a MaxPacketType    : 0xc ''
   +0x00b MaxStateChange   : 0x3 ''
   +0x00c MaxManipulate    : 0x2d '-'
   +0x00d Simulation       : 0 ''
   +0x00e Unused           : [1] 0
   +0x010 KernBase         : 0xffffffff`804d8000
   +0x018 PsLoadedModuleList : 0xffffffff`80555040
   +0x020 DebuggerDataList : 0xffffffff`80678ff4

kd> dd 0x80546b38 +0x20 (_KDDEBUGGER_DATA64)
80546b58  80678ff4 ffffffff 80678ff4 80678ff4
80546b68  00000000 00000000 4742444b 00000290
80546b78  804d8000 00000000 80528bec 00000000
80546b88  00000000 00000000 0008012c 00010018
80546b98  8050069c 00000000 00000000 00000000
80546ba8  80555040(PsLoadedModuleList) 00000000 8055b1d8(PsActiveProcessHead) 00000000
80546bb8  8055b2e0 00000000 8055d708 00000000
80546bc8  8055c5a0 00000000 8054bb2c 00000000
kd> dd 0x80546b38 +0x78  //  PsActiveProcessHead
80546bb0  8055b1d8 00000000 8055b2e0 00000000
80546bc0  8055d708 00000000 8055c5a0 00000000
80546bd0  8054bb2c 00000000 80553f9c 00000000
80546be0  80554078 00000000 805549c0 00000000
80546bf0  80552940 00000000 8055a7f8 00000000
80546c00  8055a7f0 00000000 8054b210 00000000
80546c10  805597e8 00000000 80559800 00000000
80546c20  805599e8 00000000 80554c68 00000000

 */
/*
 * win7 sp1
kd> dt _DBGKD_GET_VERSION64
nt!_DBGKD_GET_VERSION64
   +0x000 MajorVersion     : Uint2B
   +0x002 MinorVersion     : Uint2B
   +0x004 ProtocolVersion  : UChar
   +0x005 KdSecondaryVersion : UChar
   +0x006 Flags            : Uint2B
   +0x008 MachineType      : Uint2B
   +0x00a MaxPacketType    : UChar
   +0x00b MaxStateChange   : UChar
   +0x00c MaxManipulate    : UChar
   +0x00d Simulation       : UChar
   +0x00e Unused           : [1] Uint2B
   +0x010 KernBase         : Uint8B
   +0x018 PsLoadedModuleList : Uint8B
   +0x020 DebuggerDataList : Uint8B

kd> dt _kpcr
nt!_KPCR
   +0x000 NtTib            : _NT_TIB
   +0x000 Used_ExceptionList : Ptr32 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Used_StackBase   : Ptr32 Void
   +0x008 Spare2           : Ptr32 Void
   +0x00c TssCopy          : Ptr32 Void
   +0x010 ContextSwitches  : Uint4B
   +0x014 SetMemberCopy    : Uint4B
   +0x018 Used_Self        : Ptr32 Void
   +0x01c SelfPcr          : Ptr32 _KPCR
   +0x020 Prcb             : Ptr32 _KPRCB
   +0x024 Irql             : UChar
   +0x028 IRR              : Uint4B
   +0x02c IrrActive        : Uint4B
   +0x030 IDR              : Uint4B
   +0x034 KdVersionBlock   : Ptr32 Void
   +0x038 IDT              : Ptr32 _KIDTENTRY
   +0x03c GDT              : Ptr32 _KGDTENTRY
   +0x040 TSS              : Ptr32 _KTSS
   +0x044 MajorVersion     : Uint2B
   +0x046 MinorVersion     : Uint2B
   +0x048 SetMember        : Uint4B
   +0x04c StallScaleFactor : Uint4B
   +0x050 SpareUnused      : UChar
   +0x051 Number           : UChar
   +0x052 Spare0           : UChar
   +0x053 SecondLevelCacheAssociativity : UChar
   +0x054 VdmAlert         : Uint4B
   +0x058 KernelReserved   : [14] Uint4B
   +0x090 SecondLevelCacheSize : Uint4B
   +0x094 HalReserved      : [16] Uint4B
   +0x0d4 InterruptMode    : Uint4B
   +0x0d8 Spare1           : UChar
   +0x0dc KernelReserved2  : [17] Uint4B
   +0x120 PrcbData         : _KPRCB

kd> dt nt!_KPRCB
   +0x000 MinorVersion     : Uint2B
   +0x002 MajorVersion     : Uint2B
   +0x004 CurrentThread    : Ptr32 _KTHREAD
   +0x008 NextThread       : Ptr32 _KTHREAD
   +0x00c IdleThread       : Ptr32 _KTHREAD
   +0x010 LegacyNumber     : UChar
   +0x011 NestingLevel     : UChar
   +0x012 BuildType        : Uint2B
   +0x014 CpuType          : Char
   +0x015 CpuID            : Char
   +0x016 CpuStep          : Uint2B
   +0x016 CpuStepping      : UChar
   +0x017 CpuModel         : UChar
   +0x018 ProcessorState   : _KPROCESSOR_STATE
   +0x338 KernelReserved   : [16] Uint4B
   +0x378 HalReserved      : [16] Uint4B
   +0x3b8 CFlushSize       : Uint4B
   +0x3bc CoresPerPhysicalProcessor : UChar
   +0x3bd LogicalProcessorsPerCore : UChar
   +0x3be PrcbPad0         : [2] UChar
   +0x3c0 MHz              : Uint4B
   +0x3c4 CpuVendor        : UChar
   +0x3c5 GroupIndex       : UChar
   +0x3c6 Group            : Uint2B
   +0x3c8 GroupSetMember   : Uint4B
   +0x3cc Number           : Uint4B
   +0x3d0 PrcbPad1         : [72] UChar
   +0x418 LockQueue        : [17] _KSPIN_LOCK_QUEUE
   +0x4a0 NpxThread        : Ptr32 _KTHREAD
   +0x4a4 InterruptCount   : Uint4B
   +0x4a8 KernelTime       : Uint4B
   +0x4ac UserTime         : Uint4B
   +0x4b0 DpcTime          : Uint4B
   +0x4b4 DpcTimeCount     : Uint4B
   +0x4b8 InterruptTime    : Uint4B
   +0x4bc AdjustDpcThreshold : Uint4B
   +0x4c0 PageColor        : Uint4B
   +0x4c4 DebuggerSavedIRQL : UChar
   +0x4c5 NodeColor        : UChar
   +0x4c6 PrcbPad20        : [2] UChar
   +0x4c8 NodeShiftedColor : Uint4B
   +0x4cc ParentNode       : Ptr32 _KNODE
   +0x4d0 SecondaryColorMask : Uint4B
   +0x4d4 DpcTimeLimit     : Uint4B
   +0x4d8 PrcbPad21        : [2] Uint4B
   +0x4e0 CcFastReadNoWait : Uint4B
   +0x4e4 CcFastReadWait   : Uint4B
   +0x4e8 CcFastReadNotPossible : Uint4B
   +0x4ec CcCopyReadNoWait : Uint4B
   +0x4f0 CcCopyReadWait   : Uint4B
   +0x4f4 CcCopyReadNoWaitMiss : Uint4B
   +0x4f8 MmSpinLockOrdering : Int4B
   +0x4fc IoReadOperationCount : Int4B
   +0x500 IoWriteOperationCount : Int4B
   +0x504 IoOtherOperationCount : Int4B
   +0x508 IoReadTransferCount : _LARGE_INTEGER
   +0x510 IoWriteTransferCount : _LARGE_INTEGER
   +0x518 IoOtherTransferCount : _LARGE_INTEGER
   +0x520 CcFastMdlReadNoWait : Uint4B
   +0x524 CcFastMdlReadWait : Uint4B
   +0x528 CcFastMdlReadNotPossible : Uint4B
   +0x52c CcMapDataNoWait  : Uint4B
   +0x530 CcMapDataWait    : Uint4B
   +0x534 CcPinMappedDataCount : Uint4B
   +0x538 CcPinReadNoWait  : Uint4B
   +0x53c CcPinReadWait    : Uint4B
   +0x540 CcMdlReadNoWait  : Uint4B
   +0x544 CcMdlReadWait    : Uint4B
   +0x548 CcLazyWriteHotSpots : Uint4B
   +0x54c CcLazyWriteIos   : Uint4B
   +0x550 CcLazyWritePages : Uint4B
   +0x554 CcDataFlushes    : Uint4B
   +0x558 CcDataPages      : Uint4B
   +0x55c CcLostDelayedWrites : Uint4B
   +0x560 CcFastReadResourceMiss : Uint4B
   +0x564 CcCopyReadWaitMiss : Uint4B
   +0x568 CcFastMdlReadResourceMiss : Uint4B
   +0x56c CcMapDataNoWaitMiss : Uint4B
   +0x570 CcMapDataWaitMiss : Uint4B
   +0x574 CcPinReadNoWaitMiss : Uint4B
   +0x578 CcPinReadWaitMiss : Uint4B
   +0x57c CcMdlReadNoWaitMiss : Uint4B
   +0x580 CcMdlReadWaitMiss : Uint4B
   +0x584 CcReadAheadIos   : Uint4B
   +0x588 KeAlignmentFixupCount : Uint4B
   +0x58c KeExceptionDispatchCount : Uint4B
   +0x590 KeSystemCalls    : Uint4B
   +0x594 AvailableTime    : Uint4B
   +0x598 PrcbPad22        : [2] Uint4B
   +0x5a0 PPLookasideList  : [16] _PP_LOOKASIDE_LIST
   +0x620 PPNPagedLookasideList : [32] _GENERAL_LOOKASIDE_POOL
   +0xf20 PPPagedLookasideList : [32] _GENERAL_LOOKASIDE_POOL
   +0x1820 PacketBarrier    : Uint4B
   +0x1824 ReverseStall     : Int4B
   +0x1828 IpiFrame         : Ptr32 Void
   +0x182c PrcbPad3         : [52] UChar
   +0x1860 CurrentPacket    : [3] Ptr32 Void
   +0x186c TargetSet        : Uint4B
   +0x1870 WorkerRoutine    : Ptr32     void
   +0x1874 IpiFrozen        : Uint4B
   +0x1878 PrcbPad4         : [40] UChar
   +0x18a0 RequestSummary   : Uint4B
   +0x18a4 SignalDone       : Ptr32 _KPRCB
   +0x18a8 PrcbPad50        : [56] UChar
   +0x18e0 DpcData          : [2] _KDPC_DATA
   +0x1908 DpcStack         : Ptr32 Void
   +0x190c MaximumDpcQueueDepth : Int4B
   +0x1910 DpcRequestRate   : Uint4B
   +0x1914 MinimumDpcRate   : Uint4B
   +0x1918 DpcLastCount     : Uint4B
   +0x191c PrcbLock         : Uint4B
   +0x1920 DpcGate          : _KGATE
   +0x1930 ThreadDpcEnable  : UChar
   +0x1931 QuantumEnd       : UChar
   +0x1932 DpcRoutineActive : UChar
   +0x1933 IdleSchedule     : UChar
   +0x1934 DpcRequestSummary : Int4B
   +0x1934 DpcRequestSlot   : [2] Int2B
   +0x1934 NormalDpcState   : Int2B
   +0x1936 DpcThreadActive  : Pos 0, 1 Bit
   +0x1936 ThreadDpcState   : Int2B
   +0x1938 TimerHand        : Uint4B
   +0x193c LastTick         : Uint4B
   +0x1940 MasterOffset     : Int4B
   +0x1944 PrcbPad41        : [2] Uint4B
   +0x194c PeriodicCount    : Uint4B
   +0x1950 PeriodicBias     : Uint4B
   +0x1958 TickOffset       : Uint8B
   +0x1960 TimerTable       : _KTIMER_TABLE
   +0x31a0 CallDpc          : _KDPC
   +0x31c0 ClockKeepAlive   : Int4B
   +0x31c4 ClockCheckSlot   : UChar
   +0x31c5 ClockPollCycle   : UChar
   +0x31c6 PrcbPad6         : [2] UChar
   +0x31c8 DpcWatchdogPeriod : Int4B
   +0x31cc DpcWatchdogCount : Int4B
   +0x31d0 ThreadWatchdogPeriod : Int4B
   +0x31d4 ThreadWatchdogCount : Int4B
   +0x31d8 KeSpinLockOrdering : Int4B
   +0x31dc PrcbPad70        : [1] Uint4B
   +0x31e0 WaitListHead     : _LIST_ENTRY
   +0x31e8 WaitLock         : Uint4B
   +0x31ec ReadySummary     : Uint4B
   +0x31f0 QueueIndex       : Uint4B
   +0x31f4 DeferredReadyListHead : _SINGLE_LIST_ENTRY
   +0x31f8 StartCycles      : Uint8B
   +0x3200 CycleTime        : Uint8B
   +0x3208 HighCycleTime    : Uint4B
   +0x320c PrcbPad71        : Uint4B
   +0x3210 PrcbPad72        : [2] Uint8B
   +0x3220 DispatcherReadyListHead : [32] _LIST_ENTRY
   +0x3320 ChainedInterruptList : Ptr32 Void
   +0x3324 LookasideIrpFloat : Int4B
   +0x3328 MmPageFaultCount : Int4B
   +0x332c MmCopyOnWriteCount : Int4B
   +0x3330 MmTransitionCount : Int4B
   +0x3334 MmCacheTransitionCount : Int4B
   +0x3338 MmDemandZeroCount : Int4B
   +0x333c MmPageReadCount  : Int4B
   +0x3340 MmPageReadIoCount : Int4B
   +0x3344 MmCacheReadCount : Int4B
   +0x3348 MmCacheIoCount   : Int4B
   +0x334c MmDirtyPagesWriteCount : Int4B
   +0x3350 MmDirtyWriteIoCount : Int4B
   +0x3354 MmMappedPagesWriteCount : Int4B
   +0x3358 MmMappedWriteIoCount : Int4B
   +0x335c CachedCommit     : Uint4B
   +0x3360 CachedResidentAvailable : Uint4B
   +0x3364 HyperPte         : Ptr32 Void
   +0x3368 PrcbPad8         : [4] UChar
   +0x336c VendorString     : [13] UChar
   +0x3379 InitialApicId    : UChar
   +0x337a LogicalProcessorsPerPhysicalProcessor : UChar
   +0x337b PrcbPad9         : [5] UChar
   +0x3380 FeatureBits      : Uint4B
   +0x3388 UpdateSignature  : _LARGE_INTEGER
   +0x3390 IsrTime          : Uint8B
   +0x3398 RuntimeAccumulation : Uint8B
   +0x33a0 PowerState       : _PROCESSOR_POWER_STATE
   +0x3468 DpcWatchdogDpc   : _KDPC
   +0x3488 DpcWatchdogTimer : _KTIMER
   +0x34b0 WheaInfo         : Ptr32 Void
   +0x34b4 EtwSupport       : Ptr32 Void
   +0x34b8 InterruptObjectPool : _SLIST_HEADER
   +0x34c0 HypercallPageList : _SLIST_HEADER
   +0x34c8 HypercallPageVirtual : Ptr32 Void
   +0x34cc VirtualApicAssist : Ptr32 Void
   +0x34d0 StatisticsPage   : Ptr32 Uint8B
   +0x34d4 RateControl      : Ptr32 Void
   +0x34d8 Cache            : [5] _CACHE_DESCRIPTOR
   +0x3514 CacheCount       : Uint4B
   +0x3518 CacheProcessorMask : [5] Uint4B
   +0x352c PackageProcessorSet : _KAFFINITY_EX
   +0x3538 PrcbPad91        : [1] Uint4B
   +0x353c CoreProcessorSet : Uint4B
   +0x3540 TimerExpirationDpc : _KDPC
   +0x3560 SpinLockAcquireCount : Uint4B
   +0x3564 SpinLockContentionCount : Uint4B
   +0x3568 SpinLockSpinCount : Uint4B
   +0x356c IpiSendRequestBroadcastCount : Uint4B
   +0x3570 IpiSendRequestRoutineCount : Uint4B
   +0x3574 IpiSendSoftwareInterruptCount : Uint4B
   +0x3578 ExInitializeResourceCount : Uint4B
   +0x357c ExReInitializeResourceCount : Uint4B
   +0x3580 ExDeleteResourceCount : Uint4B
   +0x3584 ExecutiveResourceAcquiresCount : Uint4B
   +0x3588 ExecutiveResourceContentionsCount : Uint4B
   +0x358c ExecutiveResourceReleaseExclusiveCount : Uint4B
   +0x3590 ExecutiveResourceReleaseSharedCount : Uint4B
   +0x3594 ExecutiveResourceConvertsCount : Uint4B
   +0x3598 ExAcqResExclusiveAttempts : Uint4B
   +0x359c ExAcqResExclusiveAcquiresExclusive : Uint4B
   +0x35a0 ExAcqResExclusiveAcquiresExclusiveRecursive : Uint4B
   +0x35a4 ExAcqResExclusiveWaits : Uint4B
   +0x35a8 ExAcqResExclusiveNotAcquires : Uint4B
   +0x35ac ExAcqResSharedAttempts : Uint4B
   +0x35b0 ExAcqResSharedAcquiresExclusive : Uint4B
   +0x35b4 ExAcqResSharedAcquiresShared : Uint4B
   +0x35b8 ExAcqResSharedAcquiresSharedRecursive : Uint4B
   +0x35bc ExAcqResSharedWaits : Uint4B
   +0x35c0 ExAcqResSharedNotAcquires : Uint4B
   +0x35c4 ExAcqResSharedStarveExclusiveAttempts : Uint4B
   +0x35c8 ExAcqResSharedStarveExclusiveAcquiresExclusive : Uint4B
   +0x35cc ExAcqResSharedStarveExclusiveAcquiresShared : Uint4B
   +0x35d0 ExAcqResSharedStarveExclusiveAcquiresSharedRecursive : Uint4B
   +0x35d4 ExAcqResSharedStarveExclusiveWaits : Uint4B
   +0x35d8 ExAcqResSharedStarveExclusiveNotAcquires : Uint4B
   +0x35dc ExAcqResSharedWaitForExclusiveAttempts : Uint4B
   +0x35e0 ExAcqResSharedWaitForExclusiveAcquiresExclusive : Uint4B
   +0x35e4 ExAcqResSharedWaitForExclusiveAcquiresShared : Uint4B
   +0x35e8 ExAcqResSharedWaitForExclusiveAcquiresSharedRecursive : Uint4B
   +0x35ec ExAcqResSharedWaitForExclusiveWaits : Uint4B
   +0x35f0 ExAcqResSharedWaitForExclusiveNotAcquires : Uint4B
   +0x35f4 ExSetResOwnerPointerExclusive : Uint4B
   +0x35f8 ExSetResOwnerPointerSharedNew : Uint4B
   +0x35fc ExSetResOwnerPointerSharedOld : Uint4B
   +0x3600 ExTryToAcqExclusiveAttempts : Uint4B
   +0x3604 ExTryToAcqExclusiveAcquires : Uint4B
   +0x3608 ExBoostExclusiveOwner : Uint4B
   +0x360c ExBoostSharedOwners : Uint4B
   +0x3610 ExEtwSynchTrackingNotificationsCount : Uint4B
   +0x3614 ExEtwSynchTrackingNotificationsAccountedCount : Uint4B
   +0x3618 Context          : Ptr32 _CONTEXT
   +0x361c ContextFlags     : Uint4B
   +0x3620 ExtendedState    : Ptr32 _XSAVE_AREA

用户态
用户态
0:000> dd fs:[0]
003b:00000000  0012fb40 00130000 0012e000 00000000
003b:00000010  00001e00 00000000 7ffdf000 00000000
003b:00000020  00000f64 000006b4 00000000 7ffdf02c
003b:00000030  7ffd9000 00000000 00000000 00000000
003b:00000040  00000000 00000000 00000000 00000000
003b:00000050  00000000 00000000 00000000 00000000
003b:00000060  00000000 00000000 00000000 00000000
003b:00000070  00000000 00000000 00000000 00000000
0:000> dt ntdll!_NT_TIB
   +0x000 ExceptionList    : Ptr32 _EXCEPTION_REGISTRATION_RECORD
   +0x004 StackBase        : Ptr32 Void
   +0x008 StackLimit       : Ptr32 Void
   +0x00c SubSystemTib     : Ptr32 Void
   +0x010 FiberData        : Ptr32 Void
   +0x010 Version          : Uint4B
   +0x014 ArbitraryUserPointer : Ptr32 Void
   +0x018 Self             : Ptr32 _NT_TIB
0:000> dd fs:[0] + 18h
003b:00000018  7ffdf000 00000000 00000f64 000006b4
003b:00000028  00000000 7ffdf02c 7ffd9000 00000000
003b:00000038  00000000 00000000 00000000 00000000
003b:00000048  00000000 00000000 00000000 00000000
003b:00000058  00000000 00000000 00000000 00000000
003b:00000068  00000000 00000000 00000000 00000000
003b:00000078  00000000 00000000 00000000 00000000
003b:00000088  00000000 00000000 00000000 00000000
0:000> dt ntdll!_NT_TIB 7ffdf000
   +0x000 ExceptionList    : 0x0012fb40 _EXCEPTION_REGISTRATION_RECORD
   +0x004 StackBase        : 0x00130000
   +0x008 StackLimit       : 0x0012e000
   +0x00c SubSystemTib     : (null)
   +0x010 FiberData        : 0x00001e00
   +0x010 Version          : 0x1e00
   +0x014 ArbitraryUserPointer : (null)
   +0x018 Self             : 0x7ffdf000 _NT_TIB

内核态
获取数据：
kd> dd fs:[0]
0030:00000000  83f3401c 00000000 00000000 801e4000
0030:00000010  00000000 00000001 00000000 83f37c00
0030:00000020  83f37d20 0000001f 00000000 00000000
0030:00000030  ffffffff 83f36c00 80b95400 80b95000
0030:00000040  801e4000 00010001 00000001 00000a22
0030:00000050  00000000 00000000 00000000 00000000
0030:00000060  00000000 00000000 00000000 00000000
0030:00000070  00000000 00000000 00000000 00000000
kd> !pcr
KPCR for Processor 0 at 83f37c00:
    Major 1 Minor 1
	NtTib.ExceptionList: 83f3401c
	    NtTib.StackBase: 00000000
	   NtTib.StackLimit: 00000000
	 NtTib.SubSystemTib: 801e4000
	      NtTib.Version: 00000000
	  NtTib.UserPointer: 00000001
	      NtTib.SelfTib: 00000000

	            SelfPcr: 83f37c00
	               Prcb: 83f37d20
	               Irql: 0000001f
	                IRR: 00000000
	                IDR: ffffffff
	      InterruptMode: 00000000
	                IDT: 80b95400
	                GDT: 80b95000
	                TSS: 801e4000

	      CurrentThread: 83f41380
	         NextThread: 00000000
	         IdleThread: 83f41380

	          DpcQueue:
kd> dt nt!_KPCR 83f37c00
   +0x000 NtTib            : _NT_TIB
   +0x000 Used_ExceptionList : 0x83f3401c _EXCEPTION_REGISTRATION_RECORD
   +0x004 Used_StackBase   : (null)
   +0x008 Spare2           : (null)
   +0x00c TssCopy          : 0x801e4000
   +0x010 ContextSwitches  : 0
   +0x014 SetMemberCopy    : 1
   +0x018 Used_Self        : (null)
   +0x01c SelfPcr          : 0x83f37c00 _KPCR
   +0x020 Prcb             : 0x83f37d20 _KPRCB
   +0x024 Irql             : 0x1f ''
   +0x028 IRR              : 0
   +0x02c IrrActive        : 0
   +0x030 IDR              : 0xffffffff
   +0x034 KdVersionBlock   : 0x83f36c00
   +0x038 IDT              : 0x80b95400 _KIDTENTRY
   +0x03c GDT              : 0x80b95000 _KGDTENTRY
   +0x040 TSS              : 0x801e4000 _KTSS
   +0x044 MajorVersion     : 1
   +0x046 MinorVersion     : 1
   +0x048 SetMember        : 1
   +0x04c StallScaleFactor : 0xa22
   +0x050 SpareUnused      : 0 ''
   +0x051 Number           : 0 ''
   +0x052 Spare0           : 0 ''
   +0x053 SecondLevelCacheAssociativity : 0 ''
   +0x054 VdmAlert         : 0
   +0x058 KernelReserved   : [14] 0
   +0x090 SecondLevelCacheSize : 0
   +0x094 HalReserved      : [16] 0
   +0x0d4 InterruptMode    : 0
   +0x0d8 Spare1           : 0 ''
   +0x0dc KernelReserved2  : [17] 0
   +0x120 PrcbData         : _KPRCB
kd> dt nt!_KPRCB 0x83f37d20
   +0x000 MinorVersion     : 1
   +0x002 MajorVersion     : 1
   +0x004 CurrentThread    : 0x83f41380 _KTHREAD
   +0x008 NextThread       : (null)
   +0x00c IdleThread       : 0x83f41380 _KTHREAD
   +0x010 LegacyNumber     : 0 ''
   +0x011 NestingLevel     : 0 ''
   +0x012 BuildType        : 0
   +0x014 CpuType          : 6 ''
   +0x015 CpuID            : 1 ''
   +0x016 CpuStep          : 0x3a09
   +0x016 CpuStepping      : 0x9 ''
   +0x017 CpuModel         : 0x3a ':'
   +0x018 ProcessorState   : _KPROCESSOR_STATE
   +0x338 KernelReserved   : [16] 0
   +0x378 HalReserved      : [16] 0
   +0x3b8 CFlushSize       : 0x40
   +0x3bc CoresPerPhysicalProcessor : 0x1 ''
   +0x3bd LogicalProcessorsPerCore : 0x1 ''
   +0x3be PrcbPad0         : [2]  ""
   +0x3c0 MHz              : 0xa22
   +0x3c4 CpuVendor        : 0x1 ''
   +0x3c5 GroupIndex       : 0 ''
   +0x3c6 Group            : 0
   +0x3c8 GroupSetMember   : 1
   +0x3cc Number           : 0
   +0x3d0 PrcbPad1         : [72]  ""
   +0x418 LockQueue        : [17] _KSPIN_LOCK_QUEUE
   +0x4a0 NpxThread        : (null)
   +0x4a4 InterruptCount   : 0
   +0x4a8 KernelTime       : 0
   +0x4ac UserTime         : 0
   +0x4b0 DpcTime          : 0
   +0x4b4 DpcTimeCount     : 0
   +0x4b8 InterruptTime    : 0
   +0x4bc AdjustDpcThreshold : 0x14
   +0x4c0 PageColor        : 0xf5
   +0x4c4 DebuggerSavedIRQL : 0x1 ''
   +0x4c5 NodeColor        : 0 ''
   +0x4c6 PrcbPad20        : [2]  ""
   +0x4c8 NodeShiftedColor : 0
   +0x4cc ParentNode       : 0x83f41300 _KNODE
   +0x4d0 SecondaryColorMask : 0x3f
   +0x4d4 DpcTimeLimit     : 0
   +0x4d8 PrcbPad21        : [2] 0
   +0x4e0 CcFastReadNoWait : 0
   +0x4e4 CcFastReadWait   : 0
   +0x4e8 CcFastReadNotPossible : 0
   +0x4ec CcCopyReadNoWait : 0
   +0x4f0 CcCopyReadWait   : 0
   +0x4f4 CcCopyReadNoWaitMiss : 0
   +0x4f8 MmSpinLockOrdering : 0
   +0x4fc IoReadOperationCount : 0
   +0x500 IoWriteOperationCount : 0
   +0x504 IoOtherOperationCount : 0
   +0x508 IoReadTransferCount : _LARGE_INTEGER 0x0
   +0x510 IoWriteTransferCount : _LARGE_INTEGER 0x0
   +0x518 IoOtherTransferCount : _LARGE_INTEGER 0x0
   +0x520 CcFastMdlReadNoWait : 0
   +0x524 CcFastMdlReadWait : 0
   +0x528 CcFastMdlReadNotPossible : 0
   +0x52c CcMapDataNoWait  : 0
   +0x530 CcMapDataWait    : 0
   +0x534 CcPinMappedDataCount : 0
   +0x538 CcPinReadNoWait  : 0
   +0x53c CcPinReadWait    : 0
   +0x540 CcMdlReadNoWait  : 0
   +0x544 CcMdlReadWait    : 0
   +0x548 CcLazyWriteHotSpots : 0
   +0x54c CcLazyWriteIos   : 0
   +0x550 CcLazyWritePages : 0
   +0x554 CcDataFlushes    : 0
   +0x558 CcDataPages      : 0
   +0x55c CcLostDelayedWrites : 0
   +0x560 CcFastReadResourceMiss : 0
   +0x564 CcCopyReadWaitMiss : 0
   +0x568 CcFastMdlReadResourceMiss : 0
   +0x56c CcMapDataNoWaitMiss : 0
   +0x570 CcMapDataWaitMiss : 0
   +0x574 CcPinReadNoWaitMiss : 0
   +0x578 CcPinReadWaitMiss : 0
   +0x57c CcMdlReadNoWaitMiss : 0
   +0x580 CcMdlReadWaitMiss : 0
   +0x584 CcReadAheadIos   : 0
   +0x588 KeAlignmentFixupCount : 0
   +0x58c KeExceptionDispatchCount : 0x9a
   +0x590 KeSystemCalls    : 3
   +0x594 AvailableTime    : 0
   +0x598 PrcbPad22        : [2] 0
   +0x5a0 PPLookasideList  : [16] _PP_LOOKASIDE_LIST
   +0x620 PPNPagedLookasideList : [32] _GENERAL_LOOKASIDE_POOL
   +0xf20 PPPagedLookasideList : [32] _GENERAL_LOOKASIDE_POOL
   +0x1820 PacketBarrier    : 0
   +0x1824 ReverseStall     : 0
   +0x1828 IpiFrame         : (null)
   +0x182c PrcbPad3         : [52]  ""
   +0x1860 CurrentPacket    : [3] (null)
   +0x186c TargetSet        : 0
   +0x1870 WorkerRoutine    : (null)
   +0x1874 IpiFrozen        : 0
   +0x1878 PrcbPad4         : [40]  ""
   +0x18a0 RequestSummary   : 0
   +0x18a4 SignalDone       : (null)
   +0x18a8 PrcbPad50        : [56]  ""
   +0x18e0 DpcData          : [2] _KDPC_DATA
   +0x1908 DpcStack         : 0x83f32000
   +0x190c MaximumDpcQueueDepth : 4
   +0x1910 DpcRequestRate   : 0
   +0x1914 MinimumDpcRate   : 3
   +0x1918 DpcLastCount     : 0
   +0x191c PrcbLock         : 0
   +0x1920 DpcGate          : _KGATE
   +0x1930 ThreadDpcEnable  : 0 ''
   +0x1931 QuantumEnd       : 0 ''
   +0x1932 DpcRoutineActive : 0 ''
   +0x1933 IdleSchedule     : 0 ''
   +0x1934 DpcRequestSummary : 0
   +0x1934 DpcRequestSlot   : [2] 0
   +0x1934 NormalDpcState   : 0
   +0x1936 DpcThreadActive  : 0y0
   +0x1936 ThreadDpcState   : 0
   +0x1938 TimerHand        : 0
   +0x193c LastTick         : 0
   +0x1940 MasterOffset     : 156001
   +0x1944 PrcbPad41        : [2] 0
   +0x194c PeriodicCount    : 0
   +0x1950 PeriodicBias     : 0
   +0x1958 TickOffset       : 0
   +0x1960 TimerTable       : _KTIMER_TABLE
   +0x31a0 CallDpc          : _KDPC
   +0x31c0 ClockKeepAlive   : 1
   +0x31c4 ClockCheckSlot   : 0 ''
   +0x31c5 ClockPollCycle   : 0x64 'd'
   +0x31c6 PrcbPad6         : [2]  ""
   +0x31c8 DpcWatchdogPeriod : 0
   +0x31cc DpcWatchdogCount : 0
   +0x31d0 ThreadWatchdogPeriod : 0
   +0x31d4 ThreadWatchdogCount : 0
   +0x31d8 KeSpinLockOrdering : 0
   +0x31dc PrcbPad70        : [1] 0
   +0x31e0 WaitListHead     : _LIST_ENTRY [ 0x83f3af00 - 0x83f3af00 ]
   +0x31e8 WaitLock         : 0
   +0x31ec ReadySummary     : 0
   +0x31f0 QueueIndex       : 1
   +0x31f4 DeferredReadyListHead : _SINGLE_LIST_ENTRY
   +0x31f8 StartCycles      : 0x13`5acca499
   +0x3200 CycleTime        : 0x14`a50eff6b
   +0x3208 HighCycleTime    : 0x14
   +0x320c PrcbPad71        : 0
   +0x3210 PrcbPad72        : [2] 0
   +0x3220 DispatcherReadyListHead : [32] _LIST_ENTRY [ 0x83f3af40 - 0x83f3af40 ]
   +0x3320 ChainedInterruptList : (null)
   +0x3324 LookasideIrpFloat : 0
   +0x3328 MmPageFaultCount : 3
   +0x332c MmCopyOnWriteCount : 0
   +0x3330 MmTransitionCount : 0
   +0x3334 MmCacheTransitionCount : 0
   +0x3338 MmDemandZeroCount : 3
   +0x333c MmPageReadCount  : 0
   +0x3340 MmPageReadIoCount : 0
   +0x3344 MmCacheReadCount : 0
   +0x3348 MmCacheIoCount   : 0
   +0x334c MmDirtyPagesWriteCount : 0
   +0x3350 MmDirtyWriteIoCount : 0
   +0x3354 MmMappedPagesWriteCount : 0
   +0x3358 MmMappedWriteIoCount : 0
   +0x335c CachedCommit     : 0x100
   +0x3360 CachedResidentAvailable : 0x67
   +0x3364 HyperPte         : 0x8060000c
   +0x3368 PrcbPad8         : [4]  ""
   +0x336c VendorString     : [13]  "GenuineIntel"
   +0x3379 InitialApicId    : 0 ''
   +0x337a LogicalProcessorsPerPhysicalProcessor : 0x1 ''
   +0x337b PrcbPad9         : [5]  ""
   +0x3380 FeatureBits      : 0xa0cf3fff
   +0x3388 UpdateSignature  : _LARGE_INTEGER 0x15`00000000
   +0x3390 IsrTime          : 0
   +0x3398 RuntimeAccumulation : 0
   +0x33a0 PowerState       : _PROCESSOR_POWER_STATE
   +0x3468 DpcWatchdogDpc   : _KDPC
   +0x3488 DpcWatchdogTimer : _KTIMER
   +0x34b0 WheaInfo         : (null)
   +0x34b4 EtwSupport       : (null)
   +0x34b8 InterruptObjectPool : _SLIST_HEADER
   +0x34c0 HypercallPageList : _SLIST_HEADER
   +0x34c8 HypercallPageVirtual : (null)
   +0x34cc VirtualApicAssist : (null)
   +0x34d0 StatisticsPage   : (null)
   +0x34d4 RateControl      : (null)
   +0x34d8 Cache            : [5] _CACHE_DESCRIPTOR
   +0x3514 CacheCount       : 4
   +0x3518 CacheProcessorMask : [5] 1
   +0x352c PackageProcessorSet : _KAFFINITY_EX
   +0x3538 PrcbPad91        : [1] 0
   +0x353c CoreProcessorSet : 1
   +0x3540 TimerExpirationDpc : _KDPC
   +0x3560 SpinLockAcquireCount : 0x79616
   +0x3564 SpinLockContentionCount : 1
   +0x3568 SpinLockSpinCount : 0
   +0x356c IpiSendRequestBroadcastCount : 0
   +0x3570 IpiSendRequestRoutineCount : 0
   +0x3574 IpiSendSoftwareInterruptCount : 0
   +0x3578 ExInitializeResourceCount : 4
   +0x357c ExReInitializeResourceCount : 0
   +0x3580 ExDeleteResourceCount : 0
   +0x3584 ExecutiveResourceAcquiresCount : 1
   +0x3588 ExecutiveResourceContentionsCount : 0
   +0x358c ExecutiveResourceReleaseExclusiveCount : 1
   +0x3590 ExecutiveResourceReleaseSharedCount : 0
   +0x3594 ExecutiveResourceConvertsCount : 0
   +0x3598 ExAcqResExclusiveAttempts : 1
   +0x359c ExAcqResExclusiveAcquiresExclusive : 1
   +0x35a0 ExAcqResExclusiveAcquiresExclusiveRecursive : 0
   +0x35a4 ExAcqResExclusiveWaits : 0
   +0x35a8 ExAcqResExclusiveNotAcquires : 0
   +0x35ac ExAcqResSharedAttempts : 0
   +0x35b0 ExAcqResSharedAcquiresExclusive : 0
   +0x35b4 ExAcqResSharedAcquiresShared : 0
   +0x35b8 ExAcqResSharedAcquiresSharedRecursive : 0
   +0x35bc ExAcqResSharedWaits : 0
   +0x35c0 ExAcqResSharedNotAcquires : 0
   +0x35c4 ExAcqResSharedStarveExclusiveAttempts : 0
   +0x35c8 ExAcqResSharedStarveExclusiveAcquiresExclusive : 0
   +0x35cc ExAcqResSharedStarveExclusiveAcquiresShared : 0
   +0x35d0 ExAcqResSharedStarveExclusiveAcquiresSharedRecursive : 0
   +0x35d4 ExAcqResSharedStarveExclusiveWaits : 0
   +0x35d8 ExAcqResSharedStarveExclusiveNotAcquires : 0
   +0x35dc ExAcqResSharedWaitForExclusiveAttempts : 0
   +0x35e0 ExAcqResSharedWaitForExclusiveAcquiresExclusive : 0
   +0x35e4 ExAcqResSharedWaitForExclusiveAcquiresShared : 0
   +0x35e8 ExAcqResSharedWaitForExclusiveAcquiresSharedRecursive : 0
   +0x35ec ExAcqResSharedWaitForExclusiveWaits : 0
   +0x35f0 ExAcqResSharedWaitForExclusiveNotAcquires : 0
   +0x35f4 ExSetResOwnerPointerExclusive : 0
   +0x35f8 ExSetResOwnerPointerSharedNew : 0
   +0x35fc ExSetResOwnerPointerSharedOld : 0
   +0x3600 ExTryToAcqExclusiveAttempts : 0
   +0x3604 ExTryToAcqExclusiveAcquires : 0
   +0x3608 ExBoostExclusiveOwner : 0
   +0x360c ExBoostSharedOwners : 0
   +0x3610 ExEtwSynchTrackingNotificationsCount : 0
   +0x3614 ExEtwSynchTrackingNotificationsAccountedCount : 0
   +0x3618 Context          : 0x83f37d38 _CONTEXT
   +0x361c ContextFlags     : 0x10017
   +0x3620 ExtendedState    : (null)
kd> dt nt!_DBGKD_GET_VERSION64 0x83f36c00
   +0x000 MajorVersion     : 0xf
   +0x002 MinorVersion     : 0x1db1
   +0x004 ProtocolVersion  : 0x6 ''
   +0x005 KdSecondaryVersion : 0 ''
   +0x006 Flags            : 3
   +0x008 MachineType      : 0x14c
   +0x00a MaxPacketType    : 0xc ''
   +0x00b MaxStateChange   : 0x3 ''
   +0x00c MaxManipulate    : 0x2f '/'
   +0x00d Simulation       : 0 ''
   +0x00e Unused           : [1] 0
   +0x010 KernBase         : 0xffffffff`83e0d000
   +0x018 PsLoadedModuleList : 0xffffffff`83f564d0
   +0x020 DebuggerDataList : 0xffffffff`8417efec
kd> dd 0x83f36c00+0x20 (_KDDEBUGGER_DATA64)
83f36c20  8417efec ffffffff 8417efec 8417efec
83f36c30  00000000 00000000 4742444b 00000340
83f36c40  83e0d000 00000000 83e877b8 00000000
83f36c50  00000000 00000000 00080130 00010018
83f36c60  83e8bc28 00000000 00000000 00000000
83f36c70  83f564d0(PsLoadedModuleList) 00000000 83f4eba8(PsActiveProcessHead) 00000000
83f36c80  83f4ebc4 00000000 83f48498 00000000
83f36c90  83f76018 00000000 83f76014 00000000
kd> dd 0x83f36c00+0x78
83f36c78  83f4eba8 00000000 83f4ebc4 00000000
83f36c88  83f48498 00000000 83f76018 00000000
83f36c98  83f76014 00000000 83f769d0 00000000
83f36ca8  83f717a0 00000000 83f6e680 00000000
83f36cb8  83f743e0 00000000 83f4f748 00000000
83f36cc8  83f4f754 00000000 00000000 00000000
83f36cd8  00000000 00000000 83f77100 00000000
83f36ce8  83f76834 00000000 00000000 00000000
*/
#endif
