#ifndef _WINDOWS_PLUGIN_H_

#define _WINDOWS_PLUGIN_H_

#include <dbaf/Plugin.h>
#include <dbaf/plugins/CorePlugin.h>
#include <dbaf/plugins/OSMonitor.h>
#include <dbaf/plugins/WindowsDataStructure.h>
#include <inttypes.h>
#include <set>
#include <map>

#define MAX_NAME_LENGTH 128
#define MAX_UNICODE_LENGTH 2*MAX_NAME_LENGTH

#ifdef __x86_64__
#define BYTE uint8_t
#define WORD uint16_t
#define DWORD uint32_t
#define LONG uint32_t
#else
#define BYTE     unsigned char
#define WORD     unsigned short
#define DWORD    unsigned int
#define LONG     unsigned int
#endif

#define NAMESIZE 16
#define MAX_MODULE_COUNT 500

#define IMAGE_SIZEOF_SHORT_NAME 8
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES   16
#define IMAGE_NT_SIGNATURE 0x00004550

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
#define IMAGE_DIRECTORY_ENTRY_TLS 9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#define IMAGE_DIRECTORY_ENTRY_IAT 12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_DOS_HEADER
{
     WORD e_magic;
     WORD e_cblp;
     WORD e_cp;
     WORD e_crlc;
     WORD e_cparhdr;
     WORD e_minalloc;
     WORD e_maxalloc;
     WORD e_ss;
     WORD e_sp;
     WORD e_csum;
     WORD e_ip;
     WORD e_cs;
     WORD e_lfarlc;
     WORD e_ovno;
     WORD e_res[4];
     WORD e_oemid;
     WORD e_oeminfo;
     WORD e_res2[10];
     LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;


typedef struct _IMAGE_NT_HEADERS {
  DWORD                 Signature;
  IMAGE_FILE_HEADER     FileHeader;
  IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
	DWORD Characteristics;
	DWORD TimeDateStamp;
	WORD MajorVersion;
	WORD MinorVersion;
	DWORD Name;
	DWORD Base;
	DWORD NumberOfFunctions;
	DWORD NumberOfNames;
	DWORD AddressOfFunctions;     // RVA from base of image
	DWORD AddressOfNames;     // RVA from base of image
	DWORD AddressOfNameOrdinals;  // RVA from base of image
}IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef enum {
	WINXP_SP2 = 0, WINXP_SP3, WIN7_SP0, WIN7_SP1
} GUEST_OS;

typedef enum{
	WType = 2, Directory = 3, SymbolicLink, Token, Job, Process, Thread, UserApcReserve, IoCompletionReserve, DebugObject,
	Event, EventPair, Mutant, Callback, Semaphore, Timer, Profile, KeyedEvent, WindowStation, Desktop, TpWorkerFactory,
	Adapter, Controller, Device, Driver,IoCompletion, File, TmTm, TmTx, TmRm, TmEn, Section, Session, Key, ALPCPort, PowerRequest,
	WmiGuid, EtwRegistration, EtwConsumer, FilterConnectionPort, FilterCommunicationPort, PcwObject
}W7TYPE_TABLE;

struct api_entry{
	char name[64];
	uint32_t base;
	QLIST_ENTRY (api_entry) loadedlist_entry;
};

struct pe_entry{
	char name[64];
	char fullname[128];
	//uint32_t function_num;
	uint32_t base;
	uint32_t size;
	QLIST_HEAD (apilist_head, api_entry) apilist_head;
	QLIST_ENTRY (pe_entry) loadedlist_entry;
};

struct process_entry {
	char name[NAMESIZE];
	uint32_t EPROC_base_addr; //Base address of the EPROCESS structure _Most imp_
	uint32_t ppid; //Parent process id
	//uint32_t time_created[2]; //Time created
	uint32_t number_of_threads; //Number of active threads
	uint32_t number_of_handles;
	uint32_t table_code;
	uint32_t process_id;
	uint32_t cr3;
	QLIST_HEAD (modlist_head, pe_entry) modlist_head;
	QLIST_ENTRY (process_entry) loadedlist_entry;
};

struct tcb {
	uint32_t _EAX;
	uint32_t _EBX;
	uint32_t _ECX;
	uint32_t _EDX;
};

struct thread_entry {
	//struct process_entry *owning_process;
	uint32_t thread_id;
	uint32_t owning_process_id;
	uint32_t ETHREAD_base_addr; //_Most imp_
	struct tcb* tcb;
	//uint32_t time_created[2];
	QLIST_ENTRY (thread_entry) loadedlist_entry;
};

struct service_entry {
	char name[64];
	uint32_t base;
	uint32_t size;
	QLIST_ENTRY (service_entry) loadedlist_entry;
};

struct file_entry {

	char type[32];
	char filename[64];
	uint32_t file_object_base;
	//uint32_t num_ptr;
	//uint32_t num_hnd;
	QLIST_ENTRY (file_entry) loadedlist_entry;
};
/*
win7 sp1  ring 3
0:000> dt _NT_TIB
ntdll!_NT_TIB
   +0x000 ExceptionList    : Ptr32 _EXCEPTION_REGISTRATION_RECORD
   +0x004 StackBase        : Ptr32 Void
   +0x008 StackLimit       : Ptr32 Void
   +0x00c SubSystemTib     : Ptr32 Void
   +0x010 FiberData        : Ptr32 Void
   +0x010 Version          : Uint4B
   +0x014 ArbitraryUserPointer : Ptr32 Void
   +0x018 Self             : Ptr32 _NT_TIB
  dt _TEB
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x01c EnvironmentPointer : Ptr32 Void
   +0x020 ClientId         : _CLIENT_ID
   +0x028 ActiveRpcHandle  : Ptr32 Void
   +0x02c ThreadLocalStoragePointer : Ptr32 Void
   +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
   +0x034 LastErrorValue   : Uint4B
   +0x038 CountOfOwnedCriticalSections : Uint4B
   +0x03c CsrClientThread  : Ptr32 Void
   +0x040 Win32ThreadInfo  : Ptr32 Void
   +0x044 User32Reserved   : [26] Uint4B
   +0x0ac UserReserved     : [5] Uint4B
   +0x0c0 WOW32Reserved    : Ptr32 Void
   +0x0c4 CurrentLocale    : Uint4B
   +0x0c8 FpSoftwareStatusRegister : Uint4B
   +0x0cc SystemReserved1  : [54] Ptr32 Void
   +0x1a4 ExceptionCode    : Int4B
   +0x1a8 ActivationContextStackPointer : Ptr32 _ACTIVATION_CONTEXT_STACK
   +0x1ac SpareBytes       : [36] UChar
   +0x1d0 TxFsContext      : Uint4B
   +0x1d4 GdiTebBatch      : _GDI_TEB_BATCH
   +0x6b4 RealClientId     : _CLIENT_ID
   +0x6bc GdiCachedProcessHandle : Ptr32 Void
   +0x6c0 GdiClientPID     : Uint4B
   +0x6c4 GdiClientTID     : Uint4B
   +0x6c8 GdiThreadLocalInfo : Ptr32 Void
   +0x6cc Win32ClientInfo  : [62] Uint4B
   +0x7c4 glDispatchTable  : [233] Ptr32 Void
   +0xb68 glReserved1      : [29] Uint4B
   +0xbdc glReserved2      : Ptr32 Void
   +0xbe0 glSectionInfo    : Ptr32 Void
   +0xbe4 glSection        : Ptr32 Void
   +0xbe8 glTable          : Ptr32 Void
   +0xbec glCurrentRC      : Ptr32 Void
   +0xbf0 glContext        : Ptr32 Void
   +0xbf4 LastStatusValue  : Uint4B
   +0xbf8 StaticUnicodeString : _UNICODE_STRING
   +0xc00 StaticUnicodeBuffer : [261] Wchar
   +0xe0c DeallocationStack : Ptr32 Void
   +0xe10 TlsSlots         : [64] Ptr32 Void
   +0xf10 TlsLinks         : _LIST_ENTRY
   +0xf18 Vdm              : Ptr32 Void
   +0xf1c ReservedForNtRpc : Ptr32 Void
   +0xf20 DbgSsReserved    : [2] Ptr32 Void
   +0xf28 HardErrorMode    : Uint4B
   +0xf2c Instrumentation  : [9] Ptr32 Void
   +0xf50 ActivityId       : _GUID
   +0xf60 SubProcessTag    : Ptr32 Void
   +0xf64 EtwLocalData     : Ptr32 Void
   +0xf68 EtwTraceData     : Ptr32 Void
   +0xf6c WinSockData      : Ptr32 Void
   +0xf70 GdiBatchCount    : Uint4B
   +0xf74 CurrentIdealProcessor : _PROCESSOR_NUMBER
   +0xf74 IdealProcessorValue : Uint4B
   +0xf74 ReservedPad0     : UChar
   +0xf75 ReservedPad1     : UChar
   +0xf76 ReservedPad2     : UChar
   +0xf77 IdealProcessor   : UChar
   +0xf78 GuaranteedStackBytes : Uint4B
   +0xf7c ReservedForPerf  : Ptr32 Void
   +0xf80 ReservedForOle   : Ptr32 Void
   +0xf84 WaitingOnLoaderLock : Uint4B
   +0xf88 SavedPriorityState : Ptr32 Void
   +0xf8c SoftPatchPtr1    : Uint4B
   +0xf90 ThreadPoolData   : Ptr32 Void
   +0xf94 TlsExpansionSlots : Ptr32 Ptr32 Void
   +0xf98 MuiGeneration    : Uint4B
   +0xf9c IsImpersonating  : Uint4B
   +0xfa0 NlsCache         : Ptr32 Void
   +0xfa4 pShimData        : Ptr32 Void
   +0xfa8 HeapVirtualAffinity : Uint4B
   +0xfac CurrentTransactionHandle : Ptr32 Void
   +0xfb0 ActiveFrame      : Ptr32 _TEB_ACTIVE_FRAME
   +0xfb4 FlsData          : Ptr32 Void
   +0xfb8 PreferredLanguages : Ptr32 Void
   +0xfbc UserPrefLanguages : Ptr32 Void
   +0xfc0 MergedPrefLanguages : Ptr32 Void
   +0xfc4 MuiImpersonation : Uint4B
   +0xfc8 CrossTebFlags    : Uint2B
   +0xfc8 SpareCrossTebBits : Pos 0, 16 Bits
   +0xfca SameTebFlags     : Uint2B
   +0xfca SafeThunkCall    : Pos 0, 1 Bit
   +0xfca InDebugPrint     : Pos 1, 1 Bit
   +0xfca HasFiberData     : Pos 2, 1 Bit
   +0xfca SkipThreadAttach : Pos 3, 1 Bit
   +0xfca WerInShipAssertCode : Pos 4, 1 Bit
   +0xfca RanProcessInit   : Pos 5, 1 Bit
   +0xfca ClonedThread     : Pos 6, 1 Bit
   +0xfca SuppressDebugMsg : Pos 7, 1 Bit
   +0xfca DisableUserStackWalk : Pos 8, 1 Bit
   +0xfca RtlExceptionAttached : Pos 9, 1 Bit
   +0xfca InitialThread    : Pos 10, 1 Bit
   +0xfca SpareSameTebBits : Pos 11, 5 Bits
   +0xfcc TxnScopeEnterCallback : Ptr32 Void
   +0xfd0 TxnScopeExitCallback : Ptr32 Void
   +0xfd4 TxnScopeContext  : Ptr32 Void
   +0xfd8 LockCount        : Uint4B
   +0xfdc SpareUlong0      : Uint4B
   +0xfe0 ResourceRetValue : Ptr32 Void
0:000> dt _PEB
ntdll!_PEB
   +0x000 InheritedAddressSpace : UChar
   +0x001 ReadImageFileExecOptions : UChar
   +0x002 BeingDebugged    : UChar
   +0x003 BitField         : UChar
   +0x003 ImageUsesLargePages : Pos 0, 1 Bit
   +0x003 IsProtectedProcess : Pos 1, 1 Bit
   +0x003 IsLegacyProcess  : Pos 2, 1 Bit
   +0x003 IsImageDynamicallyRelocated : Pos 3, 1 Bit
   +0x003 SkipPatchingUser32Forwarders : Pos 4, 1 Bit
   +0x003 SpareBits        : Pos 5, 3 Bits
   +0x004 Mutant           : Ptr32 Void
   +0x008 ImageBaseAddress : Ptr32 Void
   +0x00c Ldr              : Ptr32 _PEB_LDR_DATA
   +0x010 ProcessParameters : Ptr32 _RTL_USER_PROCESS_PARAMETERS
   +0x014 SubSystemData    : Ptr32 Void
   +0x018 ProcessHeap      : Ptr32 Void
   +0x01c FastPebLock      : Ptr32 _RTL_CRITICAL_SECTION
   +0x020 AtlThunkSListPtr : Ptr32 Void
   +0x024 IFEOKey          : Ptr32 Void
   +0x028 CrossProcessFlags : Uint4B
   +0x028 ProcessInJob     : Pos 0, 1 Bit
   +0x028 ProcessInitializing : Pos 1, 1 Bit
   +0x028 ProcessUsingVEH  : Pos 2, 1 Bit
   +0x028 ProcessUsingVCH  : Pos 3, 1 Bit
   +0x028 ProcessUsingFTH  : Pos 4, 1 Bit
   +0x028 ReservedBits0    : Pos 5, 27 Bits
   +0x02c KernelCallbackTable : Ptr32 Void
   +0x02c UserSharedInfoPtr : Ptr32 Void
   +0x030 SystemReserved   : [1] Uint4B
   +0x034 AtlThunkSListPtr32 : Uint4B
   +0x038 ApiSetMap        : Ptr32 Void
   +0x03c TlsExpansionCounter : Uint4B
   +0x040 TlsBitmap        : Ptr32 Void
   +0x044 TlsBitmapBits    : [2] Uint4B
   +0x04c ReadOnlySharedMemoryBase : Ptr32 Void
   +0x050 HotpatchInformation : Ptr32 Void
   +0x054 ReadOnlyStaticServerData : Ptr32 Ptr32 Void
   +0x058 AnsiCodePageData : Ptr32 Void
   +0x05c OemCodePageData  : Ptr32 Void
   +0x060 UnicodeCaseTableData : Ptr32 Void
   +0x064 NumberOfProcessors : Uint4B
   +0x068 NtGlobalFlag     : Uint4B
   +0x070 CriticalSectionTimeout : _LARGE_INTEGER
   +0x078 HeapSegmentReserve : Uint4B
   +0x07c HeapSegmentCommit : Uint4B
   +0x080 HeapDeCommitTotalFreeThreshold : Uint4B
   +0x084 HeapDeCommitFreeBlockThreshold : Uint4B
   +0x088 NumberOfHeaps    : Uint4B
   +0x08c MaximumNumberOfHeaps : Uint4B
   +0x090 ProcessHeaps     : Ptr32 Ptr32 Void
   +0x094 GdiSharedHandleTable : Ptr32 Void
   +0x098 ProcessStarterHelper : Ptr32 Void
   +0x09c GdiDCAttributeList : Uint4B
   +0x0a0 LoaderLock       : Ptr32 _RTL_CRITICAL_SECTION
   +0x0a4 OSMajorVersion   : Uint4B
   +0x0a8 OSMinorVersion   : Uint4B
   +0x0ac OSBuildNumber    : Uint2B
   +0x0ae OSCSDVersion     : Uint2B
   +0x0b0 OSPlatformId     : Uint4B
   +0x0b4 ImageSubsystem   : Uint4B
   +0x0b8 ImageSubsystemMajorVersion : Uint4B
   +0x0bc ImageSubsystemMinorVersion : Uint4B
   +0x0c0 ActiveProcessAffinityMask : Uint4B
   +0x0c4 GdiHandleBuffer  : [34] Uint4B
   +0x14c PostProcessInitRoutine : Ptr32     void
   +0x150 TlsExpansionBitmap : Ptr32 Void
   +0x154 TlsExpansionBitmapBits : [32] Uint4B
   +0x1d4 SessionId        : Uint4B
   +0x1d8 AppCompatFlags   : _ULARGE_INTEGER
   +0x1e0 AppCompatFlagsUser : _ULARGE_INTEGER
   +0x1e8 pShimData        : Ptr32 Void
   +0x1ec AppCompatInfo    : Ptr32 Void
   +0x1f0 CSDVersion       : _UNICODE_STRING
   +0x1f8 ActivationContextData : Ptr32 _ACTIVATION_CONTEXT_DATA
   +0x1fc ProcessAssemblyStorageMap : Ptr32 _ASSEMBLY_STORAGE_MAP
   +0x200 SystemDefaultActivationContextData : Ptr32 _ACTIVATION_CONTEXT_DATA
   +0x204 SystemAssemblyStorageMap : Ptr32 _ASSEMBLY_STORAGE_MAP
   +0x208 MinimumStackCommit : Uint4B
   +0x20c FlsCallback      : Ptr32 _FLS_CALLBACK_INFO
   +0x210 FlsListHead      : _LIST_ENTRY
   +0x218 FlsBitmap        : Ptr32 Void
   +0x21c FlsBitmapBits    : [4] Uint4B
   +0x22c FlsHighIndex     : Uint4B
   +0x230 WerRegistrationData : Ptr32 Void
   +0x234 WerShipAssertPtr : Ptr32 Void
   +0x238 pContextData     : Ptr32 Void
   +0x23c pImageHeaderHash : Ptr32 Void
   +0x240 TracingFlags     : Uint4B
   +0x240 HeapTracingEnabled : Pos 0, 1 Bit
   +0x240 CritSecTracingEnabled : Pos 1, 1 Bit
   +0x240 SpareTracingBits : Pos 2, 30 Bits
0:000> dt _KPROCESS
ntdll!_KPROCESS
   +0x000 Header           : _DISPATCHER_HEADER
   +0x010 ProfileListHead  : _LIST_ENTRY
   +0x018 DirectoryTableBase : Uint4B
   +0x01c LdtDescriptor    : _KGDTENTRY
   +0x024 Int21Descriptor  : _KIDTENTRY
   +0x02c ThreadListHead   : _LIST_ENTRY
   +0x034 ProcessLock      : Uint4B
   +0x038 Affinity         : _KAFFINITY_EX
   +0x044 ReadyListHead    : _LIST_ENTRY
   +0x04c SwapListEntry    : _SINGLE_LIST_ENTRY
   +0x050 ActiveProcessors : _KAFFINITY_EX
   +0x05c AutoAlignment    : Pos 0, 1 Bit
   +0x05c DisableBoost     : Pos 1, 1 Bit
   +0x05c DisableQuantum   : Pos 2, 1 Bit
   +0x05c ActiveGroupsMask : Pos 3, 1 Bit
   +0x05c ReservedFlags    : Pos 4, 28 Bits
   +0x05c ProcessFlags     : Int4B
   +0x060 BasePriority     : Char
   +0x061 QuantumReset     : Char
   +0x062 Visited          : UChar
   +0x063 Unused3          : UChar
   +0x064 ThreadSeed       : [1] Uint4B
   +0x068 IdealNode        : [1] Uint2B
   +0x06a IdealGlobalNode  : Uint2B
   +0x06c Flags            : _KEXECUTE_OPTIONS
   +0x06d Unused1          : UChar
   +0x06e IopmOffset       : Uint2B
   +0x070 Unused4          : Uint4B
   +0x074 StackCount       : _KSTACK_COUNT
   +0x078 ProcessListEntry : _LIST_ENTRY
   +0x080 CycleTime        : Uint8B
   +0x088 KernelTime       : Uint4B
   +0x08c UserTime         : Uint4B
   +0x090 VdmTrapcHandler  : Ptr32 Void

0:000> dt _EPROCESS
ntdll!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x098 ProcessLock      : _EX_PUSH_LOCK
   +0x0a0 CreateTime       : _LARGE_INTEGER
   +0x0a8 ExitTime         : _LARGE_INTEGER
   +0x0b0 RundownProtect   : _EX_RUNDOWN_REF
   +0x0b4 UniqueProcessId  : Ptr32 Void
   +0x0b8 ActiveProcessLinks : _LIST_ENTRY
   +0x0c0 ProcessQuotaUsage : [2] Uint4B
   +0x0c8 ProcessQuotaPeak : [2] Uint4B
   +0x0d0 CommitCharge     : Uint4B
   +0x0d4 QuotaBlock       : Ptr32 _EPROCESS_QUOTA_BLOCK
   +0x0d8 CpuQuotaBlock    : Ptr32 _PS_CPU_QUOTA_BLOCK
   +0x0dc PeakVirtualSize  : Uint4B
   +0x0e0 VirtualSize      : Uint4B
   +0x0e4 SessionProcessLinks : _LIST_ENTRY
   +0x0ec DebugPort        : Ptr32 Void
   +0x0f0 ExceptionPortData : Ptr32 Void
   +0x0f0 ExceptionPortValue : Uint4B
   +0x0f0 ExceptionPortState : Pos 0, 3 Bits
   +0x0f4 ObjectTable      : Ptr32 _HANDLE_TABLE
   +0x0f8 Token            : _EX_FAST_REF
   +0x0fc WorkingSetPage   : Uint4B
   +0x100 AddressCreationLock : _EX_PUSH_LOCK
   +0x104 RotateInProgress : Ptr32 _ETHREAD
   +0x108 ForkInProgress   : Ptr32 _ETHREAD
   +0x10c HardwareTrigger  : Uint4B
   +0x110 PhysicalVadRoot  : Ptr32 _MM_AVL_TABLE
   +0x114 CloneRoot        : Ptr32 Void
   +0x118 NumberOfPrivatePages : Uint4B
   +0x11c NumberOfLockedPages : Uint4B
   +0x120 Win32Process     : Ptr32 Void
   +0x124 Job              : Ptr32 _EJOB
   +0x128 SectionObject    : Ptr32 Void
   +0x12c SectionBaseAddress : Ptr32 Void
   +0x130 Cookie           : Uint4B
   +0x134 Spare8           : Uint4B
   +0x138 WorkingSetWatch  : Ptr32 _PAGEFAULT_HISTORY
   +0x13c Win32WindowStation : Ptr32 Void
   +0x140 InheritedFromUniqueProcessId : Ptr32 Void
   +0x144 LdtInformation   : Ptr32 Void
   +0x148 VdmObjects       : Ptr32 Void
   +0x14c ConsoleHostProcess : Uint4B
   +0x150 DeviceMap        : Ptr32 Void
   +0x154 EtwDataSource    : Ptr32 Void
   +0x158 FreeTebHint      : Ptr32 Void
   +0x160 PageDirectoryPte : _HARDWARE_PTE_X86
   +0x160 Filler           : Uint8B
   +0x168 Session          : Ptr32 Void
   +0x16c ImageFileName    : [15] UChar
   +0x17b PriorityClass    : UChar
   +0x17c JobLinks         : _LIST_ENTRY
   +0x184 LockedPagesList  : Ptr32 Void
   +0x188 ThreadListHead   : _LIST_ENTRY
   +0x190 SecurityPort     : Ptr32 Void
   +0x194 PaeTop           : Ptr32 Void
   +0x198 ActiveThreads    : Uint4B
   +0x19c ImagePathHash    : Uint4B
   +0x1a0 DefaultHardErrorProcessing : Uint4B
   +0x1a4 LastThreadExitStatus : Int4B
   +0x1a8 Peb              : Ptr32 _PEB
   +0x1ac PrefetchTrace    : _EX_FAST_REF
   +0x1b0 ReadOperationCount : _LARGE_INTEGER
   +0x1b8 WriteOperationCount : _LARGE_INTEGER
   +0x1c0 OtherOperationCount : _LARGE_INTEGER
   +0x1c8 ReadTransferCount : _LARGE_INTEGER
   +0x1d0 WriteTransferCount : _LARGE_INTEGER
   +0x1d8 OtherTransferCount : _LARGE_INTEGER
   +0x1e0 CommitChargeLimit : Uint4B
   +0x1e4 CommitChargePeak : Uint4B
   +0x1e8 AweInfo          : Ptr32 Void
   +0x1ec SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
   +0x1f0 Vm               : _MMSUPPORT
   +0x25c MmProcessLinks   : _LIST_ENTRY
   +0x264 HighestUserAddress : Ptr32 Void
   +0x268 ModifiedPageCount : Uint4B
   +0x26c Flags2           : Uint4B
   +0x26c JobNotReallyActive : Pos 0, 1 Bit
   +0x26c AccountingFolded : Pos 1, 1 Bit
   +0x26c NewProcessReported : Pos 2, 1 Bit
   +0x26c ExitProcessReported : Pos 3, 1 Bit
   +0x26c ReportCommitChanges : Pos 4, 1 Bit
   +0x26c LastReportMemory : Pos 5, 1 Bit
   +0x26c ReportPhysicalPageChanges : Pos 6, 1 Bit
   +0x26c HandleTableRundown : Pos 7, 1 Bit
   +0x26c NeedsHandleRundown : Pos 8, 1 Bit
   +0x26c RefTraceEnabled  : Pos 9, 1 Bit
   +0x26c NumaAware        : Pos 10, 1 Bit
   +0x26c ProtectedProcess : Pos 11, 1 Bit
   +0x26c DefaultPagePriority : Pos 12, 3 Bits
   +0x26c PrimaryTokenFrozen : Pos 15, 1 Bit
   +0x26c ProcessVerifierTarget : Pos 16, 1 Bit
   +0x26c StackRandomizationDisabled : Pos 17, 1 Bit
   +0x26c AffinityPermanent : Pos 18, 1 Bit
   +0x26c AffinityUpdateEnable : Pos 19, 1 Bit
   +0x26c PropagateNode    : Pos 20, 1 Bit
   +0x26c ExplicitAffinity : Pos 21, 1 Bit
   +0x26c Spare1           : Pos 22, 1 Bit
   +0x26c ForceRelocateImages : Pos 23, 1 Bit
   +0x26c DisallowStrippedImages : Pos 24, 1 Bit
   +0x26c LowVaAccessible  : Pos 25, 1 Bit
   +0x270 Flags            : Uint4B
   +0x270 CreateReported   : Pos 0, 1 Bit
   +0x270 NoDebugInherit   : Pos 1, 1 Bit
   +0x270 ProcessExiting   : Pos 2, 1 Bit
   +0x270 ProcessDelete    : Pos 3, 1 Bit
   +0x270 Wow64SplitPages  : Pos 4, 1 Bit
   +0x270 VmDeleted        : Pos 5, 1 Bit
   +0x270 OutswapEnabled   : Pos 6, 1 Bit
   +0x270 Outswapped       : Pos 7, 1 Bit
   +0x270 ForkFailed       : Pos 8, 1 Bit
   +0x270 Wow64VaSpace4Gb  : Pos 9, 1 Bit
   +0x270 AddressSpaceInitialized : Pos 10, 2 Bits
   +0x270 SetTimerResolution : Pos 12, 1 Bit
   +0x270 BreakOnTermination : Pos 13, 1 Bit
   +0x270 DeprioritizeViews : Pos 14, 1 Bit
   +0x270 WriteWatch       : Pos 15, 1 Bit
   +0x270 ProcessInSession : Pos 16, 1 Bit
   +0x270 OverrideAddressSpace : Pos 17, 1 Bit
   +0x270 HasAddressSpace  : Pos 18, 1 Bit
   +0x270 LaunchPrefetched : Pos 19, 1 Bit
   +0x270 InjectInpageErrors : Pos 20, 1 Bit
   +0x270 VmTopDown        : Pos 21, 1 Bit
   +0x270 ImageNotifyDone  : Pos 22, 1 Bit
   +0x270 PdeUpdateNeeded  : Pos 23, 1 Bit
   +0x270 VdmAllowed       : Pos 24, 1 Bit
   +0x270 CrossSessionCreate : Pos 25, 1 Bit
   +0x270 ProcessInserted  : Pos 26, 1 Bit
   +0x270 DefaultIoPriority : Pos 27, 3 Bits
   +0x270 ProcessSelfDelete : Pos 30, 1 Bit
   +0x270 SetTimerResolutionLink : Pos 31, 1 Bit
   +0x274 ExitStatus       : Int4B
   +0x278 VadRoot          : _MM_AVL_TABLE
   +0x298 AlpcContext      : _ALPC_PROCESS_CONTEXT
   +0x2a8 TimerResolutionLink : _LIST_ENTRY
   +0x2b0 RequestedTimerResolution : Uint4B
   +0x2b4 ActiveThreadsHighWatermark : Uint4B
   +0x2b8 SmallestTimerResolution : Uint4B
   +0x2bc TimerResolutionStackRecord : Ptr32 _PO_DIAG_STACK_RECORD

0:000> dt _LDR_DATA_TABLE_ENTRY
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY
   +0x008 InMemoryOrderLinks : _LIST_ENTRY
   +0x010 InInitializationOrderLinks : _LIST_ENTRY
   +0x018 DllBase          : Ptr32 Void
   +0x01c EntryPoint       : Ptr32 Void
   +0x020 SizeOfImage      : Uint4B
   +0x024 FullDllName      : _UNICODE_STRING
   +0x02c BaseDllName      : _UNICODE_STRING
   +0x034 Flags            : Uint4B
   +0x038 LoadCount        : Uint2B
   +0x03a TlsIndex         : Uint2B
   +0x03c HashLinks        : _LIST_ENTRY
   +0x03c SectionPointer   : Ptr32 Void
   +0x040 CheckSum         : Uint4B
   +0x044 TimeDateStamp    : Uint4B
   +0x044 LoadedImports    : Ptr32 Void
   +0x048 EntryPointActivationContext : Ptr32 _ACTIVATION_CONTEXT
   +0x04c PatchInformation : Ptr32 Void
   +0x050 ForwarderLinks   : _LIST_ENTRY
   +0x058 ServiceTagLinks  : _LIST_ENTRY
   +0x060 StaticLinks      : _LIST_ENTRY
   +0x068 ContextInformation : Ptr32 Void
   +0x06c OriginalBase     : Uint4B
   +0x070 LoadTime         : _LARGE_INTEGER
 dt _PEB
ntdll!_PEB
   +0x000 InheritedAddressSpace : UChar
   +0x001 ReadImageFileExecOptions : UChar
   +0x002 BeingDebugged    : UChar
   +0x003 BitField         : UChar
   +0x003 ImageUsesLargePages : Pos 0, 1 Bit
   +0x003 IsProtectedProcess : Pos 1, 1 Bit
   +0x003 IsLegacyProcess  : Pos 2, 1 Bit
   +0x003 IsImageDynamicallyRelocated : Pos 3, 1 Bit
   +0x003 SkipPatchingUser32Forwarders : Pos 4, 1 Bit
   +0x003 SpareBits        : Pos 5, 3 Bits
   +0x004 Mutant           : Ptr32 Void
   +0x008 ImageBaseAddress : Ptr32 Void
   +0x00c Ldr              : Ptr32 _PEB_LDR_DATA
   +0x010 ProcessParameters : Ptr32 _RTL_USER_PROCESS_PARAMETERS
   +0x014 SubSystemData    : Ptr32 Void
   +0x018 ProcessHeap      : Ptr32 Void
   +0x01c FastPebLock      : Ptr32 _RTL_CRITICAL_SECTION
   +0x020 AtlThunkSListPtr : Ptr32 Void
   +0x024 IFEOKey          : Ptr32 Void
   +0x028 CrossProcessFlags : Uint4B
   +0x028 ProcessInJob     : Pos 0, 1 Bit
   +0x028 ProcessInitializing : Pos 1, 1 Bit
   +0x028 ProcessUsingVEH  : Pos 2, 1 Bit
   +0x028 ProcessUsingVCH  : Pos 3, 1 Bit
   +0x028 ProcessUsingFTH  : Pos 4, 1 Bit
   +0x028 ReservedBits0    : Pos 5, 27 Bits
   +0x02c KernelCallbackTable : Ptr32 Void
   +0x02c UserSharedInfoPtr : Ptr32 Void
   +0x030 SystemReserved   : [1] Uint4B
   +0x034 AtlThunkSListPtr32 : Uint4B
   +0x038 ApiSetMap        : Ptr32 Void
   +0x03c TlsExpansionCounter : Uint4B
   +0x040 TlsBitmap        : Ptr32 Void
   +0x044 TlsBitmapBits    : [2] Uint4B
   +0x04c ReadOnlySharedMemoryBase : Ptr32 Void
   +0x050 HotpatchInformation : Ptr32 Void
   +0x054 ReadOnlyStaticServerData : Ptr32 Ptr32 Void
   +0x058 AnsiCodePageData : Ptr32 Void
   +0x05c OemCodePageData  : Ptr32 Void
   +0x060 UnicodeCaseTableData : Ptr32 Void
   +0x064 NumberOfProcessors : Uint4B
   +0x068 NtGlobalFlag     : Uint4B
   +0x070 CriticalSectionTimeout : _LARGE_INTEGER
   +0x078 HeapSegmentReserve : Uint4B
   +0x07c HeapSegmentCommit : Uint4B
   +0x080 HeapDeCommitTotalFreeThreshold : Uint4B
   +0x084 HeapDeCommitFreeBlockThreshold : Uint4B
   +0x088 NumberOfHeaps    : Uint4B
   +0x08c MaximumNumberOfHeaps : Uint4B
   +0x090 ProcessHeaps     : Ptr32 Ptr32 Void
   +0x094 GdiSharedHandleTable : Ptr32 Void
   +0x098 ProcessStarterHelper : Ptr32 Void
   +0x09c GdiDCAttributeList : Uint4B
   +0x0a0 LoaderLock       : Ptr32 _RTL_CRITICAL_SECTION
   +0x0a4 OSMajorVersion   : Uint4B
   +0x0a8 OSMinorVersion   : Uint4B
   +0x0ac OSBuildNumber    : Uint2B
   +0x0ae OSCSDVersion     : Uint2B
   +0x0b0 OSPlatformId     : Uint4B
   +0x0b4 ImageSubsystem   : Uint4B
   +0x0b8 ImageSubsystemMajorVersion : Uint4B
   +0x0bc ImageSubsystemMinorVersion : Uint4B
   +0x0c0 ActiveProcessAffinityMask : Uint4B
   +0x0c4 GdiHandleBuffer  : [34] Uint4B
   +0x14c PostProcessInitRoutine : Ptr32     void
   +0x150 TlsExpansionBitmap : Ptr32 Void
   +0x154 TlsExpansionBitmapBits : [32] Uint4B
   +0x1d4 SessionId        : Uint4B
   +0x1d8 AppCompatFlags   : _ULARGE_INTEGER
   +0x1e0 AppCompatFlagsUser : _ULARGE_INTEGER
   +0x1e8 pShimData        : Ptr32 Void
   +0x1ec AppCompatInfo    : Ptr32 Void
   +0x1f0 CSDVersion       : _UNICODE_STRING
   +0x1f8 ActivationContextData : Ptr32 _ACTIVATION_CONTEXT_DATA
   +0x1fc ProcessAssemblyStorageMap : Ptr32 _ASSEMBLY_STORAGE_MAP
   +0x200 SystemDefaultActivationContextData : Ptr32 _ACTIVATION_CONTEXT_DATA
   +0x204 SystemAssemblyStorageMap : Ptr32 _ASSEMBLY_STORAGE_MAP
   +0x208 MinimumStackCommit : Uint4B
   +0x20c FlsCallback      : Ptr32 _FLS_CALLBACK_INFO
   +0x210 FlsListHead      : _LIST_ENTRY
   +0x218 FlsBitmap        : Ptr32 Void
   +0x21c FlsBitmapBits    : [4] Uint4B
   +0x22c FlsHighIndex     : Uint4B
   +0x230 WerRegistrationData : Ptr32 Void
   +0x234 WerShipAssertPtr : Ptr32 Void
   +0x238 pContextData     : Ptr32 Void
   +0x23c pImageHeaderHash : Ptr32 Void
   +0x240 TracingFlags     : Uint4B
   +0x240 HeapTracingEnabled : Pos 0, 1 Bit
   +0x240 CritSecTracingEnabled : Pos 1, 1 Bit
   +0x240 SpareTracingBits : Pos 2, 30 Bits
0:000> dt _PEB_LDR_DATA
ntdll!_PEB_LDR_DATA
   +0x000 Length           : Uint4B
   +0x004 Initialized      : UChar
   +0x008 SsHandle         : Ptr32 Void
   +0x00c InLoadOrderModuleList : _LIST_ENTRY
   +0x014 InMemoryOrderModuleList : _LIST_ENTRY
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY
   +0x024 EntryInProgress  : Ptr32 Void
   +0x028 ShutdownInProgress : UChar
   +0x02c ShutdownThreadId : Ptr32 Void
win xp  ring 3
0:000> dt _NT_TIB
ntdll!_NT_TIB
   +0x000 ExceptionList    : Ptr32 _EXCEPTION_REGISTRATION_RECORD
   +0x004 StackBase        : Ptr32 Void
   +0x008 StackLimit       : Ptr32 Void
   +0x00c SubSystemTib     : Ptr32 Void
   +0x010 FiberData        : Ptr32 Void
   +0x010 Version          : Uint4B
   +0x014 ArbitraryUserPointer : Ptr32 Void
   +0x018 Self             : Ptr32 _NT_TIB
0:000> dt _TEB
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x01c EnvironmentPointer : Ptr32 Void
   +0x020 ClientId         : _CLIENT_ID
   +0x028 ActiveRpcHandle  : Ptr32 Void
   +0x02c ThreadLocalStoragePointer : Ptr32 Void
   +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
   +0x034 LastErrorValue   : Uint4B
   +0x038 CountOfOwnedCriticalSections : Uint4B
   +0x03c CsrClientThread  : Ptr32 Void
   +0x040 Win32ThreadInfo  : Ptr32 Void
   +0x044 User32Reserved   : [26] Uint4B
   +0x0ac UserReserved     : [5] Uint4B
   +0x0c0 WOW32Reserved    : Ptr32 Void
   +0x0c4 CurrentLocale    : Uint4B
   +0x0c8 FpSoftwareStatusRegister : Uint4B
   +0x0cc SystemReserved1  : [54] Ptr32 Void
   +0x1a4 ExceptionCode    : Int4B
   +0x1a8 ActivationContextStack : _ACTIVATION_CONTEXT_STACK
   +0x1bc SpareBytes1      : [24] UChar
   +0x1d4 GdiTebBatch      : _GDI_TEB_BATCH
   +0x6b4 RealClientId     : _CLIENT_ID
   +0x6bc GdiCachedProcessHandle : Ptr32 Void
   +0x6c0 GdiClientPID     : Uint4B
   +0x6c4 GdiClientTID     : Uint4B
   +0x6c8 GdiThreadLocalInfo : Ptr32 Void
   +0x6cc Win32ClientInfo  : [62] Uint4B
   +0x7c4 glDispatchTable  : [233] Ptr32 Void
   +0xb68 glReserved1      : [29] Uint4B
   +0xbdc glReserved2      : Ptr32 Void
   +0xbe0 glSectionInfo    : Ptr32 Void
   +0xbe4 glSection        : Ptr32 Void
   +0xbe8 glTable          : Ptr32 Void
   +0xbec glCurrentRC      : Ptr32 Void
   +0xbf0 glContext        : Ptr32 Void
   +0xbf4 LastStatusValue  : Uint4B
   +0xbf8 StaticUnicodeString : _UNICODE_STRING
   +0xc00 StaticUnicodeBuffer : [261] Uint2B
   +0xe0c DeallocationStack : Ptr32 Void
   +0xe10 TlsSlots         : [64] Ptr32 Void
   +0xf10 TlsLinks         : _LIST_ENTRY
   +0xf18 Vdm              : Ptr32 Void
   +0xf1c ReservedForNtRpc : Ptr32 Void
   +0xf20 DbgSsReserved    : [2] Ptr32 Void
   +0xf28 HardErrorsAreDisabled : Uint4B
   +0xf2c Instrumentation  : [16] Ptr32 Void
   +0xf6c WinSockData      : Ptr32 Void
   +0xf70 GdiBatchCount    : Uint4B
   +0xf74 InDbgPrint       : UChar
   +0xf75 FreeStackOnTermination : UChar
   +0xf76 HasFiberData     : UChar
   +0xf77 IdealProcessor   : UChar
   +0xf78 Spare3           : Uint4B
   +0xf7c ReservedForPerf  : Ptr32 Void
   +0xf80 ReservedForOle   : Ptr32 Void
   +0xf84 WaitingOnLoaderLock : Uint4B
   +0xf88 Wx86Thread       : _Wx86ThreadState
   +0xf94 TlsExpansionSlots : Ptr32 Ptr32 Void
   +0xf98 ImpersonationLocale : Uint4B
   +0xf9c IsImpersonating  : Uint4B
   +0xfa0 NlsCache         : Ptr32 Void
   +0xfa4 pShimData        : Ptr32 Void
   +0xfa8 HeapVirtualAffinity : Uint4B
   +0xfac CurrentTransactionHandle : Ptr32 Void
   +0xfb0 ActiveFrame      : Ptr32 _TEB_ACTIVE_FRAME
   +0xfb4 SafeThunkCall    : UChar
   +0xfb5 BooleanSpare     : [3] UChar
0:000> dt _PEB
ntdll!_PEB
   +0x000 InheritedAddressSpace : UChar
   +0x001 ReadImageFileExecOptions : UChar
   +0x002 BeingDebugged    : UChar
   +0x003 SpareBool        : UChar
   +0x004 Mutant           : Ptr32 Void
   +0x008 ImageBaseAddress : Ptr32 Void
   +0x00c Ldr              : Ptr32 _PEB_LDR_DATA
   +0x010 ProcessParameters : Ptr32 _RTL_USER_PROCESS_PARAMETERS
   +0x014 SubSystemData    : Ptr32 Void
   +0x018 ProcessHeap      : Ptr32 Void
   +0x01c FastPebLock      : Ptr32 _RTL_CRITICAL_SECTION
   +0x020 FastPebLockRoutine : Ptr32 Void
   +0x024 FastPebUnlockRoutine : Ptr32 Void
   +0x028 EnvironmentUpdateCount : Uint4B
   +0x02c KernelCallbackTable : Ptr32 Void
   +0x030 SystemReserved   : [1] Uint4B
   +0x034 AtlThunkSListPtr32 : Uint4B
   +0x038 FreeList         : Ptr32 _PEB_FREE_BLOCK
   +0x03c TlsExpansionCounter : Uint4B
   +0x040 TlsBitmap        : Ptr32 Void
   +0x044 TlsBitmapBits    : [2] Uint4B
   +0x04c ReadOnlySharedMemoryBase : Ptr32 Void
   +0x050 ReadOnlySharedMemoryHeap : Ptr32 Void
   +0x054 ReadOnlyStaticServerData : Ptr32 Ptr32 Void
   +0x058 AnsiCodePageData : Ptr32 Void
   +0x05c OemCodePageData  : Ptr32 Void
   +0x060 UnicodeCaseTableData : Ptr32 Void
   +0x064 NumberOfProcessors : Uint4B
   +0x068 NtGlobalFlag     : Uint4B
   +0x070 CriticalSectionTimeout : _LARGE_INTEGER
   +0x078 HeapSegmentReserve : Uint4B
   +0x07c HeapSegmentCommit : Uint4B
   +0x080 HeapDeCommitTotalFreeThreshold : Uint4B
   +0x084 HeapDeCommitFreeBlockThreshold : Uint4B
   +0x088 NumberOfHeaps    : Uint4B
   +0x08c MaximumNumberOfHeaps : Uint4B
   +0x090 ProcessHeaps     : Ptr32 Ptr32 Void
   +0x094 GdiSharedHandleTable : Ptr32 Void
   +0x098 ProcessStarterHelper : Ptr32 Void
   +0x09c GdiDCAttributeList : Uint4B
   +0x0a0 LoaderLock       : Ptr32 Void
   +0x0a4 OSMajorVersion   : Uint4B
   +0x0a8 OSMinorVersion   : Uint4B
   +0x0ac OSBuildNumber    : Uint2B
   +0x0ae OSCSDVersion     : Uint2B
   +0x0b0 OSPlatformId     : Uint4B
   +0x0b4 ImageSubsystem   : Uint4B
   +0x0b8 ImageSubsystemMajorVersion : Uint4B
   +0x0bc ImageSubsystemMinorVersion : Uint4B
   +0x0c0 ImageProcessAffinityMask : Uint4B
   +0x0c4 GdiHandleBuffer  : [34] Uint4B
   +0x14c PostProcessInitRoutine : Ptr32     void
   +0x150 TlsExpansionBitmap : Ptr32 Void
   +0x154 TlsExpansionBitmapBits : [32] Uint4B
   +0x1d4 SessionId        : Uint4B
   +0x1d8 AppCompatFlags   : _ULARGE_INTEGER
   +0x1e0 AppCompatFlagsUser : _ULARGE_INTEGER
   +0x1e8 pShimData        : Ptr32 Void
   +0x1ec AppCompatInfo    : Ptr32 Void
   +0x1f0 CSDVersion       : _UNICODE_STRING
   +0x1f8 ActivationContextData : Ptr32 Void
   +0x1fc ProcessAssemblyStorageMap : Ptr32 Void
   +0x200 SystemDefaultActivationContextData : Ptr32 Void
   +0x204 SystemAssemblyStorageMap : Ptr32 Void
   +0x208 MinimumStackCommit : Uint4B

lkd> dt _KPROCESS
ntdll!_KPROCESS
   +0x000 Header           : _DISPATCHER_HEADER
   +0x010 ProfileListHead  : _LIST_ENTRY
   +0x018 DirectoryTableBase : [2] Uint4B
   +0x020 LdtDescriptor    : _KGDTENTRY
   +0x028 Int21Descriptor  : _KIDTENTRY
   +0x030 IopmOffset       : Uint2B
   +0x032 Iopl             : UChar
   +0x033 Unused           : UChar
   +0x034 ActiveProcessors : Uint4B
   +0x038 KernelTime       : Uint4B
   +0x03c UserTime         : Uint4B
   +0x040 ReadyListHead    : _LIST_ENTRY
   +0x048 SwapListEntry    : _SINGLE_LIST_ENTRY
   +0x04c VdmTrapcHandler  : Ptr32 Void
   +0x050 ThreadListHead   : _LIST_ENTRY
   +0x058 ProcessLock      : Uint4B
   +0x05c Affinity         : Uint4B
   +0x060 StackCount       : Uint2B
   +0x062 BasePriority     : Char
   +0x063 ThreadQuantum    : Char
   +0x064 AutoAlignment    : UChar
   +0x065 State            : UChar
   +0x066 ThreadSeed       : UChar
   +0x067 DisableBoost     : UChar
   +0x068 PowerState       : UChar
   +0x069 DisableQuantum   : UChar
   +0x06a IdealNode        : UChar
   +0x06b Flags            : _KEXECUTE_OPTIONS
   +0x06b ExecuteOptions   : UChar
0:000> dt _EPROCESS
ntdll!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x06c ProcessLock      : _EX_PUSH_LOCK
   +0x070 CreateTime       : _LARGE_INTEGER
   +0x078 ExitTime         : _LARGE_INTEGER
   +0x080 RundownProtect   : _EX_RUNDOWN_REF
   +0x084 UniqueProcessId  : Ptr32 Void
   +0x088 ActiveProcessLinks : _LIST_ENTRY
   +0x090 QuotaUsage       : [3] Uint4B
   +0x09c QuotaPeak        : [3] Uint4B
   +0x0a8 CommitCharge     : Uint4B
   +0x0ac PeakVirtualSize  : Uint4B
   +0x0b0 VirtualSize      : Uint4B
   +0x0b4 SessionProcessLinks : _LIST_ENTRY
   +0x0bc DebugPort        : Ptr32 Void
   +0x0c0 ExceptionPort    : Ptr32 Void
   +0x0c4 ObjectTable      : Ptr32 _HANDLE_TABLE
   +0x0c8 Token            : _EX_FAST_REF
   +0x0cc WorkingSetLock   : _FAST_MUTEX
   +0x0ec WorkingSetPage   : Uint4B
   +0x0f0 AddressCreationLock : _FAST_MUTEX
   +0x110 HyperSpaceLock   : Uint4B
   +0x114 ForkInProgress   : Ptr32 _ETHREAD
   +0x118 HardwareTrigger  : Uint4B
   +0x11c VadRoot          : Ptr32 Void
   +0x120 VadHint          : Ptr32 Void
   +0x124 CloneRoot        : Ptr32 Void
   +0x128 NumberOfPrivatePages : Uint4B
   +0x12c NumberOfLockedPages : Uint4B
   +0x130 Win32Process     : Ptr32 Void
   +0x134 Job              : Ptr32 _EJOB
   +0x138 SectionObject    : Ptr32 Void
   +0x13c SectionBaseAddress : Ptr32 Void
   +0x140 QuotaBlock       : Ptr32 _EPROCESS_QUOTA_BLOCK
   +0x144 WorkingSetWatch  : Ptr32 _PAGEFAULT_HISTORY
   +0x148 Win32WindowStation : Ptr32 Void
   +0x14c InheritedFromUniqueProcessId : Ptr32 Void
   +0x150 LdtInformation   : Ptr32 Void
   +0x154 VadFreeHint      : Ptr32 Void
   +0x158 VdmObjects       : Ptr32 Void
   +0x15c DeviceMap        : Ptr32 Void
   +0x160 PhysicalVadList  : _LIST_ENTRY
   +0x168 PageDirectoryPte : _HARDWARE_PTE_X86
   +0x168 Filler           : Uint8B
   +0x170 Session          : Ptr32 Void
   +0x174 ImageFileName    : [16] UChar
   +0x184 JobLinks         : _LIST_ENTRY
   +0x18c LockedPagesList  : Ptr32 Void
   +0x190 ThreadListHead   : _LIST_ENTRY
   +0x198 SecurityPort     : Ptr32 Void
   +0x19c PaeTop           : Ptr32 Void
   +0x1a0 ActiveThreads    : Uint4B
   +0x1a4 GrantedAccess    : Uint4B
   +0x1a8 DefaultHardErrorProcessing : Uint4B
   +0x1ac LastThreadExitStatus : Int4B
   +0x1b0 Peb              : Ptr32 _PEB
   +0x1b4 PrefetchTrace    : _EX_FAST_REF
   +0x1b8 ReadOperationCount : _LARGE_INTEGER
   +0x1c0 WriteOperationCount : _LARGE_INTEGER
   +0x1c8 OtherOperationCount : _LARGE_INTEGER
   +0x1d0 ReadTransferCount : _LARGE_INTEGER
   +0x1d8 WriteTransferCount : _LARGE_INTEGER
   +0x1e0 OtherTransferCount : _LARGE_INTEGER
   +0x1e8 CommitChargeLimit : Uint4B
   +0x1ec CommitChargePeak : Uint4B
   +0x1f0 AweInfo          : Ptr32 Void
   +0x1f4 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
   +0x1f8 Vm               : _MMSUPPORT
   +0x238 LastFaultCount   : Uint4B
   +0x23c ModifiedPageCount : Uint4B
   +0x240 NumberOfVads     : Uint4B
   +0x244 JobStatus        : Uint4B
   +0x248 Flags            : Uint4B
   +0x248 CreateReported   : Pos 0, 1 Bit
   +0x248 NoDebugInherit   : Pos 1, 1 Bit
   +0x248 ProcessExiting   : Pos 2, 1 Bit
   +0x248 ProcessDelete    : Pos 3, 1 Bit
   +0x248 Wow64SplitPages  : Pos 4, 1 Bit
   +0x248 VmDeleted        : Pos 5, 1 Bit
   +0x248 OutswapEnabled   : Pos 6, 1 Bit
   +0x248 Outswapped       : Pos 7, 1 Bit
   +0x248 ForkFailed       : Pos 8, 1 Bit
   +0x248 HasPhysicalVad   : Pos 9, 1 Bit
   +0x248 AddressSpaceInitialized : Pos 10, 2 Bits
   +0x248 SetTimerResolution : Pos 12, 1 Bit
   +0x248 BreakOnTermination : Pos 13, 1 Bit
   +0x248 SessionCreationUnderway : Pos 14, 1 Bit
   +0x248 WriteWatch       : Pos 15, 1 Bit
   +0x248 ProcessInSession : Pos 16, 1 Bit
   +0x248 OverrideAddressSpace : Pos 17, 1 Bit
   +0x248 HasAddressSpace  : Pos 18, 1 Bit
   +0x248 LaunchPrefetched : Pos 19, 1 Bit
   +0x248 InjectInpageErrors : Pos 20, 1 Bit
   +0x248 VmTopDown        : Pos 21, 1 Bit
   +0x248 Unused3          : Pos 22, 1 Bit
   +0x248 Unused4          : Pos 23, 1 Bit
   +0x248 VdmAllowed       : Pos 24, 1 Bit
   +0x248 Unused           : Pos 25, 5 Bits
   +0x248 Unused1          : Pos 30, 1 Bit
   +0x248 Unused2          : Pos 31, 1 Bit
   +0x24c ExitStatus       : Int4B
   +0x250 NextPageColor    : Uint2B
   +0x252 SubSystemMinorVersion : UChar
   +0x253 SubSystemMajorVersion : UChar
   +0x252 SubSystemVersion : Uint2B
   +0x254 PriorityClass    : UChar
   +0x255 WorkingSetAcquiredUnsafe : UChar
   +0x258 Cookie           : Uint4B

0:000> dt _LDR_DATA_TABLE_ENTRY
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY
   +0x008 InMemoryOrderLinks : _LIST_ENTRY
   +0x010 InInitializationOrderLinks : _LIST_ENTRY
   +0x018 DllBase          : Ptr32 Void
   +0x01c EntryPoint       : Ptr32 Void
   +0x020 SizeOfImage      : Uint4B
   +0x024 FullDllName      : _UNICODE_STRING
   +0x02c BaseDllName      : _UNICODE_STRING
   +0x034 Flags            : Uint4B
   +0x038 LoadCount        : Uint2B
   +0x03a TlsIndex         : Uint2B
   +0x03c HashLinks        : _LIST_ENTRY
   +0x03c SectionPointer   : Ptr32 Void
   +0x040 CheckSum         : Uint4B
   +0x044 TimeDateStamp    : Uint4B
   +0x044 LoadedImports    : Ptr32 Void
   +0x048 EntryPointActivationContext : Ptr32 Void
   +0x04c PatchInformation : Ptr32 Void

0:000> dt _PEB
ntdll!_PEB
   +0x000 InheritedAddressSpace : UChar
   +0x001 ReadImageFileExecOptions : UChar
   +0x002 BeingDebugged    : UChar
   +0x003 SpareBool        : UChar
   +0x004 Mutant           : Ptr32 Void
   +0x008 ImageBaseAddress : Ptr32 Void
   +0x00c Ldr              : Ptr32 _PEB_LDR_DATA
   +0x010 ProcessParameters : Ptr32 _RTL_USER_PROCESS_PARAMETERS
   +0x014 SubSystemData    : Ptr32 Void
   +0x018 ProcessHeap      : Ptr32 Void
   +0x01c FastPebLock      : Ptr32 _RTL_CRITICAL_SECTION
   +0x020 FastPebLockRoutine : Ptr32 Void
   +0x024 FastPebUnlockRoutine : Ptr32 Void
   +0x028 EnvironmentUpdateCount : Uint4B
   +0x02c KernelCallbackTable : Ptr32 Void
   +0x030 SystemReserved   : [1] Uint4B
   +0x034 AtlThunkSListPtr32 : Uint4B
   +0x038 FreeList         : Ptr32 _PEB_FREE_BLOCK
   +0x03c TlsExpansionCounter : Uint4B
   +0x040 TlsBitmap        : Ptr32 Void
   +0x044 TlsBitmapBits    : [2] Uint4B
   +0x04c ReadOnlySharedMemoryBase : Ptr32 Void
   +0x050 ReadOnlySharedMemoryHeap : Ptr32 Void
   +0x054 ReadOnlyStaticServerData : Ptr32 Ptr32 Void
   +0x058 AnsiCodePageData : Ptr32 Void
   +0x05c OemCodePageData  : Ptr32 Void
   +0x060 UnicodeCaseTableData : Ptr32 Void
   +0x064 NumberOfProcessors : Uint4B
   +0x068 NtGlobalFlag     : Uint4B
   +0x070 CriticalSectionTimeout : _LARGE_INTEGER
   +0x078 HeapSegmentReserve : Uint4B
   +0x07c HeapSegmentCommit : Uint4B
   +0x080 HeapDeCommitTotalFreeThreshold : Uint4B
   +0x084 HeapDeCommitFreeBlockThreshold : Uint4B
   +0x088 NumberOfHeaps    : Uint4B
   +0x08c MaximumNumberOfHeaps : Uint4B
   +0x090 ProcessHeaps     : Ptr32 Ptr32 Void
   +0x094 GdiSharedHandleTable : Ptr32 Void
   +0x098 ProcessStarterHelper : Ptr32 Void
   +0x09c GdiDCAttributeList : Uint4B
   +0x0a0 LoaderLock       : Ptr32 Void
   +0x0a4 OSMajorVersion   : Uint4B
   +0x0a8 OSMinorVersion   : Uint4B
   +0x0ac OSBuildNumber    : Uint2B
   +0x0ae OSCSDVersion     : Uint2B
   +0x0b0 OSPlatformId     : Uint4B
   +0x0b4 ImageSubsystem   : Uint4B
   +0x0b8 ImageSubsystemMajorVersion : Uint4B
   +0x0bc ImageSubsystemMinorVersion : Uint4B
   +0x0c0 ImageProcessAffinityMask : Uint4B
   +0x0c4 GdiHandleBuffer  : [34] Uint4B
   +0x14c PostProcessInitRoutine : Ptr32     void
   +0x150 TlsExpansionBitmap : Ptr32 Void
   +0x154 TlsExpansionBitmapBits : [32] Uint4B
   +0x1d4 SessionId        : Uint4B
   +0x1d8 AppCompatFlags   : _ULARGE_INTEGER
   +0x1e0 AppCompatFlagsUser : _ULARGE_INTEGER
   +0x1e8 pShimData        : Ptr32 Void
   +0x1ec AppCompatInfo    : Ptr32 Void
   +0x1f0 CSDVersion       : _UNICODE_STRING
   +0x1f8 ActivationContextData : Ptr32 Void
   +0x1fc ProcessAssemblyStorageMap : Ptr32 Void
   +0x200 SystemDefaultActivationContextData : Ptr32 Void
   +0x204 SystemAssemblyStorageMap : Ptr32 Void
   +0x208 MinimumStackCommit : Uint4B
0:000> dt _PEB_LDR_DATA
ntdll!_PEB_LDR_DATA
   +0x000 Length           : Uint4B
   +0x004 Initialized      : UChar
   +0x008 SsHandle         : Ptr32 Void
   +0x00c InLoadOrderModuleList : _LIST_ENTRY
   +0x014 InMemoryOrderModuleList : _LIST_ENTRY
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY
   +0x024 EntryInProgress  : Ptr32 Void
 */
typedef struct {
	uint32_t KPCR_FS_OFFSET; //KPCR offset based on fs:[0]
	uint32_t KDVB_OFFSET;// 0x34 // KDVB:versionBlock base on KPCR
    uint32_t KPCR_KPRCB_OFFSET; //0x120 KPRCB_OFFSET  base on KPCR
    uint32_t KPCR_KPRCB_PTR_OFFSET; //0x20 KPRCB_PTR_OFFSET  base on KPCR
	uint32_t PSLM_OFFSET;// 0x70 // PsLoadedModuleList based on KDVB
	uint32_t PSAPH_OFFSET;// 0x78 // PsActiveProcessHead base on KDVB
	uint32_t TEB_FS_OFFSET; // self _NT_TIB or self TEB offset based on fs:[0]
	uint32_t DLLBASE_OFFSET; //DllBase based on _LDR_DATA_TABLE_ENTRY (retrive from PsLoadedModuleList)
	uint32_t SIZE_OFFSET; //SizeOfImage based on _LDR_DATA_TABLE_ENTRY
	uint32_t DLLNAME_OFFSET; //BaseDllName based on _LDR_DATA_TABLE_ENTRY
	uint32_t FULLDLLNAME_OFFSET; //FullDllName based on _LDR_DATA_TABLE_ENTRY
	uint32_t PSAPL_OFFSET; // ActiveProcessLinks base on struct _EPROCESS
	uint32_t PSAPID_OFFSET; //UniqueProcessId  base on struct _EPROCESS
	uint32_t PSAPNAME_OFFSET;//ImageFileName  base on struct _EPROCESS
	uint32_t PSAPPID_OFFSET; //InheritedFromUniqueProcessId  base on struct _EPROCESS
	uint32_t PSAPTHREADS_OFFSET; //ActiveThreads   base on struct _EPROCESS
	uint32_t PSAPHANDLES_OFFSET; //ObjectTable  _HANDLE_TABLE base on struct _EPROCESS
	uint64_t PEXIT_TIME;//ExitTime   based on struct _EPROCESS
	uint64_t DIRECTORYTABLEBASE_OFFSET;//DirectoryTableBase based on struct _EPROCESS
	uint32_t PEB_OFFSET; //ProcessEnvironmentBlock based on _TEB
	uint32_t LDR_OFFSET; //Ldr              : Ptr32 _PEB_LDR_DATA based on _PEB
	uint32_t INLOADORDERMODULELIST_OFFSET;// InLoadOrderModuleList based on _PEB_LDR_DATA
}off_set;

//Do not change the order of the constants
typedef enum EWinVer {
    XPSP2=0,
    XPSP3=1,
    XPSP2_CHK=2,
    XPSP3_CHK=3,
    SRV2008SP2=4,
    WIN7SP1 = 5,
    MAXVER
}EWinVer;
typedef struct os_special {
	EWinVer os_version;
	off_set* offset;
}os_special;

namespace dbaf {
namespace plugins {

typedef std::set<uint64_t> PidSet;
typedef std::map<std::string, uint64_t> ModuleSizeMap;


class WindowsMonitor:public dbaf::plugins::OSMonitor
{
    DBAF_PLUGIN

public:
    WindowsMonitor(DBAF* dbaf): dbaf::plugins::OSMonitor(dbaf) {
    	m_kdVersion.KernBase = 0;
    	kernel_proc = NULL;
    	m_os_special = NULL;
        m_ntdllLoadBase = 0;
        m_ntdllNativeBase = 0;
        m_LdrUnloadDllPc = 0;
        m_ntIopDeleteDriverPc = 0;
        m_ntPspExitProcess= 0;
    }
    virtual ~WindowsMonitor();
public:
    static os_special os_specials[];
	static off_set s_xp_offset;
	static off_set s_w7_offset;
    os_special* m_os_special;
	process *kernel_proc;
	unordered_map < uint32_t, pair<module *, uint32_t> > phys_module_map;
private:

    //These are the keys to specify in the configuration file
    static const char *s_windowsKeys[];

    //These are user-friendly strings displayed to the user
    static const char *s_windowsStrings[];

    int m_pointerSize;
    std::string m_ntmodulename;
    uint64_t m_KernelStart;

    uint64_t m_ntkernelNativeBase;
    uint64_t m_ntPspExitProcess;
    uint64_t m_ntKeInitThread;
    uint64_t m_ntKeTerminateThread;
    uint64_t m_ntIopDeleteDriverPc;

    uint64_t m_ntdllLoadBase;
    uint64_t m_ntdllNativeBase;
    uint64_t m_LdrUnloadDllPc;

    EWinVer m_Version;
    bool m_UserMode;
    bool m_KernelMode;
    bool m_isASLR;
    bool m_MonitorModuleLoad;
    bool m_MonitorModuleUnload;
    bool m_MonitorProcessUnload;
    bool m_monitorThreads;

    uint32_t m_pKPCRAddr;
    uint32_t m_pKPRCBAddr;
    windows::DBGKD_GET_VERSION64 m_kdVersion;
    windows::KPRCB32 m_kprcb;

    fsigc::connection m_SyscallConnection;

    bool InitializeKernelAddresses(DBAFExecutionState *state);
    void slotTranslateBlockStart(ExecutionSignal *signal,
            DBAFExecutionState *state,
            TranslationBlock *tb,
            uint64_t pc);
    void slotCatchProcessTermination(DBAFExecutionState *state, uint64_t pc, uint64_t nextpc);
    void sloatUMModuleUnload(DBAFExecutionState *state, uint64_t pc, uint64_t nextpc);
    void sloatKMModuleUnload(DBAFExecutionState *state, uint64_t pc, uint64_t nextpc);
public:
    void initialize();

    unsigned GetPointerSize() const;
    virtual uint64_t GetKernelStart() const;
    uint64_t GetKernelLoadBase() const;
    uint64_t GetPspExitProcessPc() const;
    virtual bool isKernelAddress(uint64_t pc) const;
    uint64_t getCurrentProcess(DBAFExecutionState *state);
    uint64_t getCurrentThread(DBAFExecutionState *state);
    uint64_t getTibAddress(DBAFExecutionState *state);
    bool getTib(DBAFExecutionState *state, dbaf::windows::NT_TIB32 *tib);
    uint64_t getPeb(DBAFExecutionState *state, uint64_t eprocess);
    uint64_t getDirectoryTableBase(DBAFExecutionState *state, uint64_t pProcessEntry);

    inline int is_page_resolved(process *proc, uint32_t page_num);
    inline int unresolved_attempt(process *proc, uint32_t addr);
    process * find_new_process(DBAFExecutionState *state, uint32_t cr3);
    inline int  get_IMAGE_NT_HEADERS(DBAFExecutionState *state, uint32_t cr3, uint32_t base, IMAGE_NT_HEADERS *nth);
    inline int  readustr_with_cr3(DBAFExecutionState *state, uint32_t addr, uint32_t cr3, void *buf);
    char*  get_basename(char *fullname);
    void  update_kernel_modules(DBAFExecutionState *state,  process *proc, target_ulong vaddr);
    void  update_loaded_user_mods_with_peb(DBAFExecutionState *state, process *proc,
    		uint32_t peb, target_ulong vaddr);
    void  extract_export_table(DBAFExecutionState *state,IMAGE_NT_HEADERS *nth, uint32_t cr3, uint32_t base, module *mod);
    void  extract_PE_info(DBAFExecutionState *state,uint32_t cr3, uint32_t base, module *mod);
    void  retrieve_missing_symbols(DBAFExecutionState *state,process *proc, target_ulong vaddr);
    inline void get_new_modules(DBAFExecutionState *state, process * proc, target_ulong vaddr);

    windows::KPRCB32 getKprcb() const { return m_kprcb; }
    uint64_t getKpcrbAddress() const { return m_pKPRCBAddr; }
    uint64_t getBuildNumber() const {
        return m_kdVersion.MinorVersion;
    }
    EWinVer GetVersion() const {
        return m_Version;
    }
    const windows::DBGKD_GET_VERSION64 &getVersionBlock() const {
        return m_kdVersion;
    }

};

class WindowsMonitorState:public PluginState
{
private:

public:
    WindowsMonitorState();
    virtual ~WindowsMonitorState();
    virtual WindowsMonitorState* clone() const;
    static PluginState *factory(Plugin *p, DBAFExecutionState *state);

    friend class WindowsMonitor;
};

} // namespace plugins
} // namespace s2e


#endif
