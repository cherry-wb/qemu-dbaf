extern "C" {
#include "config.h"
#include "qemu-common.h"
}

#include <dbaf/DBAF.h>
#include <dbaf/ConfigFile.h>
#include <dbaf/plugins/OShelper/function_map.h>
#include "WindowsMonitor.h"
#include "WindowsDataStructure.h"

#include <inttypes.h>
#include <string>
#include <list>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <tr1/unordered_map>
#include <tr1/unordered_set>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <queue>
#include <sys/time.h>
#include <math.h>
#include <glib.h>
#include <mcheck.h>
#include <stdio.h>
#include <string>
#include <cstring>
#include <sstream>
#include <iostream>
#include <assert.h>
#include <stddef.h>
#include <cstddef>

using namespace std;
using namespace dbaf;
using namespace dbaf::plugins;

DBAF_DEFINE_PLUGIN(WindowsMonitor, "Plugin for monitoring Windows kernel/user-mode events", "Interceptor");

//These are the keys to specify in the configuration file
const char *WindowsMonitor::s_windowsKeys[] =    {"XPSP2", "XPSP3","XPSP2-CHK", "XPSP3-CHK", "SRV2008SP2", "WIN7SP1"};

//These are user-friendly strings displayed to the user
const char *WindowsMonitor::s_windowsStrings[] =
{"Windows XP SP2 RTM",          "Windows XP SP3 RTM",
 "Windows XP SP2 Checked",      "Windows XP SP3 Checked",
 "Windows Server 2008 SP2 RTM",	"Windows Seven SP1"};
off_set WindowsMonitor::s_xp_offset = {0x1c, 0x34, 0x120, 0x20, 0x70, 0x78, 0x18, 0x18, 0x20, 0x2c, 0x24, 0x88, 0x84, 0x174, 0x14c, 0x1a0, 0xc4, 0x78, 0x18, 0x30, 0xc, 0xc };
off_set WindowsMonitor::s_w7_offset = {0x1c, 0x34, 0x120, 0x20, 0x70, 0x78, 0x18, 0x18, 0x20, 0x2c, 0x24, 0xb8, 0xb4, 0x16c, 0x140, 0x198, 0xf4, 0xa8, 0x18, 0x30, 0xc, 0xc };
os_special WindowsMonitor::os_specials[] = {
		{ XPSP3, &s_xp_offset },
		{ WIN7SP1, &s_w7_offset}, };

WindowsMonitor::~WindowsMonitor()
{

}

void WindowsMonitor::initialize()
{
    string Version = dbaf()->getConfig()->getString(getConfigKey() + ".version");
    m_ntmodulename = dbaf()->getConfig()->getString(getConfigKey() + ".ntmodulename", "ntoskrnl.exe");
    m_UserMode = dbaf()->getConfig()->getBool(getConfigKey() + ".userMode");
    m_KernelMode = dbaf()->getConfig()->getBool(getConfigKey() + ".kernelMode");
    m_isASLR = dbaf()->getConfig()->getBool(getConfigKey() + ".isASLR", false);
    //For debug purposes
    m_MonitorModuleLoad = dbaf()->getConfig()->getBool(getConfigKey() + ".monitorModuleLoad");
    m_MonitorModuleUnload = dbaf()->getConfig()->getBool(getConfigKey() + ".monitorModuleUnload");
    m_MonitorProcessUnload = dbaf()->getConfig()->getBool(getConfigKey() + ".monitorProcessUnload");
    m_monitorThreads = dbaf()->getConfig()->getBool(getConfigKey() + ".monitorThreads", true);
    //default value is for winxp sp3
    m_pointerSize = dbaf()->getConfig()->getInt(getConfigKey() + ".pointerSize", 4);
    m_KernelStart = dbaf()->getConfig()->getInt(getConfigKey() + ".KernelStart", 0x80000000);

    m_ntkernelNativeBase = dbaf()->getConfig()->getInt(getConfigKey() + ".ntkernelNativeBase", 0x00400000);
    // the start pc PspExitProcess function
    m_ntPspExitProcess = dbaf()->getConfig()->getInt(getConfigKey() + ".ntPspExitProcess", 0x004AB0E4);
    //Points to the instruction after which the kernel-mode stack in KTHREAD is properly initialized
    m_ntKeInitThread = dbaf()->getConfig()->getInt(getConfigKey() + ".ntKeInitThread", 0x004b75fc);
    //Points to the start of KeTerminateThread (this function terminates the current thread)
    m_ntKeTerminateThread = dbaf()->getConfig()->getInt(getConfigKey() + ".ntKeTerminateThread", 0x004214C9);
    m_ntIopDeleteDriverPc = dbaf()->getConfig()->getInt(getConfigKey() + ".ntIopDeleteDriverPc", 0x004EB33F);

    m_ntdllNativeBase = dbaf()->getConfig()->getInt(getConfigKey() + ".ntdllNativeBase", 0x7c920000);
    if(!m_isASLR){
    	m_ntdllLoadBase =  dbaf()->getConfig()->getInt(getConfigKey() + ".ntdllLoadBase", 0x7c920000);
    }
    m_LdrUnloadDllPc = dbaf()->getConfig()->getInt(getConfigKey() + ".LdrUnloadDllPc", 0x7C93E12A);

    unsigned i;
    for (i=0; i<(unsigned)MAXVER; ++i) {
        if (strcmp(Version.c_str(), s_windowsKeys[i]) == 0) {
            m_Version = (EWinVer)i;
            break;
        }
    }

    if (i == (EWinVer)MAXVER) {
        dbaf()->getErrorStream() << "Invalid windows version: " << Version << '\n';
        dbaf()->getErrorStream() << "Available versions are:" << '\n';
        for (unsigned j=0; j<MAXVER; ++j) {
            dbaf()->getErrorStream() << s_windowsKeys[j] << ":\t" << s_windowsStrings[j] << '\n';
        }
        exit(-1);
    }

    switch(m_Version) {
        case XPSP2_CHK:
        case XPSP3_CHK:
            dbaf()->getWarningStream() << "You specified a checked build of Windows XP." <<
                    "Only kernel-mode interceptors are supported for now." << '\n';
            break;
        default:
            break;
    }

    //XXX: Warn about some unsupported features
    if (!(m_Version == XPSP3 || m_Version == WIN7SP1) && m_monitorThreads) {
        dbaf()->getWarningStream() << "WindowsMonitor does not support threads for the chosen OS version.\n"
                                   << "Please use monitorThreads=false in the configuration file\n"
                                   << "Plugins that depend on this feature will not work.\n";
        exit(-1);
    }

    int os_specials_size =  sizeof(os_specials) / sizeof(os_special);
    int os_index = 0;
	for (os_index = 0; os_index < os_specials_size; os_index++) {
		if (m_Version == os_specials[os_index].os_version) {

			m_os_special = &os_specials[os_index];
			break;
		}
	}
	if(m_os_special == NULL){
		dbaf()->getWarningStream() << "WindowsMonitor does not support this OS version.\n";
		exit(-1);
	}

    m_pKPCRAddr = 0;
    m_pKPRCBAddr = 0;

    dbaf()->getCorePlugin()->onTranslateBlockStart.connect(
           fsigc::mem_fun(*this, &WindowsMonitor::slotTranslateBlockStart));
}

bool WindowsMonitor::InitializeKernelAddresses(DBAFExecutionState *state)
{
    if (m_pKPCRAddr) {
        return true;
    }
    //Compute the address of the KPCR
    //It is located in fs:0x1c
    uint64_t base = state->readCpu0State(CPU_SEGS, R_FS);
    if (state->readMemoryConcrete(base + m_os_special->offset->KPCR_FS_OFFSET, &m_pKPCRAddr, sizeof(m_pKPCRAddr))) {
        dbaf()->getWarningStream() << "WindowsMonitor: Failed to initialize KPCR, try again." << '\n';
        goto error;
    }
    if (m_pKPCRAddr != base) {
    	 goto error;
    }

    //Read the version block
    uint32_t pKdVersionBlock;
    if (state->readMemoryConcrete(m_pKPCRAddr + m_os_special->offset->KDVB_OFFSET, &pKdVersionBlock, sizeof(pKdVersionBlock))) {
        dbaf()->getWarningStream() << "WindowsMonitor: Failed to read KD version block pointer, try again." << '\n';
        goto error;
    }

    if (state->readMemoryConcrete(pKdVersionBlock, &m_kdVersion, sizeof(m_kdVersion))) {
        dbaf()->getWarningStream() << "WindowsMonitor: Failed to read KD version block, try again." << '\n';
        goto error;
    }

    if(m_kdVersion.KernBase < GetKernelStart()){
    	dbaf()->getWarningStream() << "WindowsMonitor: Failed to read KernBase member of KD version block, try again." << '\n';
    	goto error;
    }

    //Read the KPRCB
    if (state->readMemoryConcrete(m_pKPCRAddr + m_os_special->offset->KPCR_KPRCB_PTR_OFFSET, &m_pKPRCBAddr, sizeof(m_pKPRCBAddr))) {
        dbaf()->getWarningStream() << "WindowsMonitor: Failed to read pointer to KPRCB, try again." << '\n';
        goto error;
    }

    if (m_pKPRCBAddr != m_pKPCRAddr + m_os_special->offset->KPCR_KPRCB_OFFSET) {
        dbaf()->getWarningStream () << "WindowsMonitor: Invalid KPRCB, try again." << '\n';
        goto error;
    }

    if (state->readMemoryConcrete(m_pKPRCBAddr, &m_kprcb, sizeof(m_kprcb))) {
        dbaf()->getWarningStream() << "WindowsMonitor: Failed to read KPRCB, try again." << '\n';
        goto error;
    }

    //Display some info
    dbaf()->getDebugStream() << "InitializeKernelAddresses OK!\nWindows " << m_kdVersion.MinorVersion <<
            (m_kdVersion.MajorVersion == 0xF ? " FREE BUILD" : " CHECKED BUILD") << '\n';
    dbaf()->getDebugStream() << "KernBase " << hexval(GetKernelLoadBase()) << '\n';
    dbaf()->getDebugStream().flush();

    kernel_proc = new process();
	kernel_proc->cr3 = 0;
	strcpy(kernel_proc->name, "<kernel>");
	kernel_proc->pid = 0;
	VMI_create_process(state, kernel_proc);

    return true;

error:
	m_pKPCRAddr = 0;
	m_kdVersion.KernBase = 0;
    return false;

}

void WindowsMonitor::slotTranslateBlockStart(ExecutionSignal *signal,
        DBAFExecutionState *state,
        TranslationBlock *tb,
        uint64_t pc)
{

	if (GetKernelLoadBase() == 0) {
		if (pc > GetKernelStart()) {
			if (!InitializeKernelAddresses(state))
				return;
		} else {
			return;
		}
	}
	target_ulong vaddr = pc;
	uint32_t cr3 = state->readCpuState(CPU_CRS, 3);
	process *proc;

	if(pc > GetKernelStart()) {
		proc = kernel_proc;
		kernel_proc->cr3 = cr3;
		if(m_KernelMode && m_ntIopDeleteDriverPc > 0 && pc == (m_ntIopDeleteDriverPc + (GetKernelLoadBase() - m_ntdllNativeBase)) && m_MonitorModuleUnload){
			signal->connect(fsigc::mem_fun(*this, &WindowsMonitor::sloatKMModuleUnload));
		}
	} else {
		proc = VMI_find_process_by_pgd(cr3);
		if (proc == NULL)
			proc = find_new_process(state, cr3);
	}
	if (proc ) {
		if (!is_page_resolved(proc, vaddr)) {
			get_new_modules(state, proc, vaddr);
			if (!is_page_resolved(proc, vaddr)) {
				int attempts = unresolved_attempt(proc, vaddr);
				if (attempts > 3)
					proc->resolved_pages.insert(vaddr>>12);
			}
		}
		retrieve_missing_symbols(state, proc, vaddr);
		if(m_UserMode && m_ntdllLoadBase > 0 && pc == (m_LdrUnloadDllPc + (m_ntdllLoadBase - m_ntdllNativeBase)) && m_MonitorModuleUnload){
			signal->connect(fsigc::mem_fun(*this, &WindowsMonitor::sloatUMModuleUnload));
		}
	}
	if (m_UserMode && GetKernelLoadBase() != 0 && pc == GetPspExitProcessPc() && m_MonitorProcessUnload) {
		signal->connect(fsigc::mem_fun(*this, &WindowsMonitor::slotCatchProcessTermination));
	}

}
void WindowsMonitor::slotCatchProcessTermination(DBAFExecutionState *state, uint64_t pc, uint64_t nextpc)
{
    //m_UserModeInterceptor->CatchProcessTermination(state);
	uint32_t end_time[2];
	vector<target_ulong> pid_list;
	unordered_map < uint32_t, process * >::iterator iter = process_map.begin();
	for (; iter!=process_map.end(); iter++) {
		process *proc = iter->second;
		if (proc->parent_pid == 0)
			continue;
		state->readMemoryConcrete(proc->EPROC_base_addr
						+ m_os_special->offset->PEXIT_TIME,
						  end_time, 8);
		if (end_time[0] | end_time[1]) {
			pid_list.push_back(proc->pid);
		}
	}

	for (unsigned int i=0; i<pid_list.size(); i++) {
		VMI_remove_process(state, (unsigned int)pid_list[i]);
	}
}
void WindowsMonitor::sloatKMModuleUnload(DBAFExecutionState *state, uint64_t pc, uint64_t nextpc)
{
	uint64_t pDriverObject;
	dbaf::windows::DRIVER_OBJECT32 DrvObject;
	target_ulong esp = state->readCpuState(CPU_REGS,R_ESP);
	if (state->readMemoryConcrete(esp + 4, &pDriverObject, GetPointerSize())) {
		return;
	}
	if (!pDriverObject) {
		return;
	}
	if (state->readMemoryConcrete(pDriverObject,
		&DrvObject, sizeof(DrvObject))) {
			return;
	}
	//Fetch MODULE_ENTRY
	if (!DrvObject.DriverSection) {
		return;
	}
    VMI_remove_module(state, 0,DrvObject.DriverStart);
}
void WindowsMonitor::sloatUMModuleUnload(DBAFExecutionState *state, uint64_t pc, uint64_t nextpc)
{
    dbaf::windows::LDR_DATA_TABLE_ENTRY32 LdrEntry;
    uint64_t pLdrEntry;
    uint32_t cr3;
    process *proc = NULL;
    cr3 = state->readCpuState(CPU_CRS, 3);
	if(pc > GetKernelStart()) {

	} else {
		proc = VMI_find_process_by_pgd(cr3);
		if (proc == NULL)
			return;
	}
    pLdrEntry = state->readCpuState(CPU_REGS,R_ESI);
    if (state->readMemoryConcrete(pLdrEntry, &LdrEntry, sizeof(LdrEntry))) {
        return;
    }
    VMI_remove_module(state, proc->pid,LdrEntry.DllBase);
}

unsigned WindowsMonitor::GetPointerSize() const
{
    return m_pointerSize;
}
uint64_t WindowsMonitor::GetKernelStart() const
{
    return m_KernelStart;
}

uint64_t WindowsMonitor::GetKernelLoadBase() const
{
    if (GetPointerSize() == 4)
        return (uint32_t)m_kdVersion.KernBase;
    else
        return m_kdVersion.KernBase;
}

uint64_t WindowsMonitor::GetPspExitProcessPc() const
{
    uint64_t offset = GetKernelLoadBase() - m_ntkernelNativeBase;
    return m_ntPspExitProcess + offset;
}

bool WindowsMonitor::isKernelAddress(uint64_t pc) const
{
    return pc >= GetKernelStart();
}

uint64_t WindowsMonitor::getCurrentThread(DBAFExecutionState *state)
{
    //It is located in fs:KPCR_CURRENT_THREAD_OFFSET
    uint64_t base = getTibAddress(state);
    uint32_t pThread = 0;
    if (state->readMemoryConcrete(base + FS_CURRENT_THREAD_OFFSET, &pThread, sizeof(pThread))) {
        dbaf()->getWarningStream() << "Failed to get thread address" << '\n';
        return 0;
    }
    return pThread;
}

uint64_t WindowsMonitor::getCurrentProcess(DBAFExecutionState *state)
{
    uint64_t pThread = getCurrentThread(state);
    if (!pThread) {
        return 0;
    }

    uint32_t threadOffset;
    if (m_kdVersion.MinorVersion >= BUILD_LONGHORN) {
        threadOffset = ETHREAD_PROCESS_OFFSET_WIN7;
    }else {
        threadOffset = ETHREAD_PROCESS_OFFSET_XP;
    }

    uint32_t pProcess = 0;
    if (state->readMemoryConcrete(pThread + threadOffset, &pProcess, sizeof(pProcess))) {
        dbaf()->getWarningStream() << "Failed to get process address" << '\n';
        return 0;
    }

    return pProcess;
}

//Retrieves the current Thread Information Block, stored in the FS register
uint64_t WindowsMonitor::getTibAddress(DBAFExecutionState *state)
{
    return state->readCpu0State(CPU_SEGS, R_FS);
}

bool WindowsMonitor::getTib(DBAFExecutionState *state, dbaf::windows::NT_TIB32 *tib)
{
    uint64_t tibAddress = getTibAddress(state);
    return !(state->readMemoryConcrete(tibAddress, &tib, sizeof(*tib)));
}

uint64_t WindowsMonitor::getPeb(DBAFExecutionState *state, uint64_t eprocess)
{
    uint32_t offset;
    if (m_kdVersion.MinorVersion >= BUILD_LONGHORN) {
        offset = offsetof(dbaf::windows::EPROCESS32_WIN7,Peb);
    }else {
        offset = offsetof(dbaf::windows::EPROCESS32_XP,Peb);
    }

    uint32_t peb = 0;
    if (state->readMemoryConcrete(eprocess + offset, &peb, (sizeof(peb)))) {
        return 0;
    }
    return peb;
}
uint64_t WindowsMonitor::getDirectoryTableBase(DBAFExecutionState *state, uint64_t pProcessEntry)
{
    if (m_kdVersion.MinorVersion >= BUILD_LONGHORN) {
        dbaf::windows::EPROCESS32_WIN7 ProcessEntry;

        if (state->readMemoryConcrete(pProcessEntry, &ProcessEntry, sizeof(ProcessEntry))) {
            return 0;
        }

        return ProcessEntry.Pcb.DirectoryTableBase;
    }else {
        dbaf::windows::EPROCESS32_XP ProcessEntry;

        if (state->readMemoryConcrete(pProcessEntry, &ProcessEntry, sizeof(ProcessEntry))) {
            return 0;
        }
        return ProcessEntry.Pcb.DirectoryTableBase;
    }
}


inline int WindowsMonitor::is_page_resolved(process *proc, uint32_t page_num)
{
	return (proc->resolved_pages.find(page_num>>12) != proc->resolved_pages.end());
}

inline int WindowsMonitor::unresolved_attempt(process *proc, uint32_t addr)
{
	unordered_map <uint32_t, int>::iterator iter = proc->unresolved_pages.find(addr>>12);
	if(iter == proc->unresolved_pages.end()) {
		proc->unresolved_pages[addr>>12] = 1;
		return 1;
	}
	iter->second++;

	return iter->second;
}


process * WindowsMonitor::find_new_process(DBAFExecutionState *state, uint32_t cr3) {
	uint32_t kdvb, psAPH, curr_proc, next_proc;
	process *pe;

	if (m_pKPCRAddr == 0)
		return 0;

	state->readMemoryConcrete(m_pKPCRAddr + m_os_special->offset->KDVB_OFFSET, &kdvb, 4);
	state->readMemoryConcrete(kdvb + m_os_special->offset->PSAPH_OFFSET, &psAPH, 4);
	state->readMemoryConcrete(psAPH, &curr_proc, 4);

	while (curr_proc != 0 && curr_proc != psAPH) {
		uint32_t pid, proc_cr3;
		uint32_t curr_proc_base = curr_proc
				- m_os_special->offset->PSAPL_OFFSET;

		state->readMemoryConcrete(curr_proc_base + m_os_special->offset->PSAPID_OFFSET,
				&pid, 4);
		if (VMI_find_process_by_pid(pid) != NULL) //we have seen this process
			goto next;

		state->readMemoryConcrete(curr_proc_base + m_os_special->offset->DIRECTORYTABLEBASE_OFFSET, &proc_cr3, 4);
		if(cr3 != proc_cr3) //This is a new process, but not the current one. Skip it!
			goto next;

		pe = new process();
		pe->EPROC_base_addr = curr_proc_base;
		pe->pid = pid;
		pe->cr3 = proc_cr3;
		state->readMemoryConcrete(curr_proc_base + m_os_special->offset->PSAPNAME_OFFSET,
					 pe->name, NAMESIZE);
		state->readMemoryConcrete(
					curr_proc_base
							+ m_os_special->offset->PSAPPID_OFFSET,
					 &pe->parent_pid, 4);
		VMI_create_process(state, pe);
		return pe;

next:
		state->readMemoryConcrete(curr_proc, &next_proc, 4);
		if (curr_proc == next_proc) { //why do we need this check?
			break;
		}
		curr_proc = next_proc;
	}

	return NULL;

}


inline int  WindowsMonitor::get_IMAGE_NT_HEADERS(DBAFExecutionState *state, uint32_t cr3, uint32_t base, IMAGE_NT_HEADERS *nth)
{
	IMAGE_DOS_HEADER DosHeader;
	state->readMemoryConcrete(cr3, base, &DosHeader, sizeof(IMAGE_DOS_HEADER));

	if (DosHeader.e_magic != (0x5a4d)) {
		return -1;
	}
	if(state->readMemoryConcrete(cr3, base + DosHeader.e_lfanew, nth,
			sizeof(IMAGE_NT_HEADERS)) < 0) {
		return -1;
	}
    return 0;
}

//FIXME: this function may potentially overflow "buf"
inline int  WindowsMonitor::readustr_with_cr3(DBAFExecutionState *state, uint32_t addr, uint32_t cr3, void *buf) {
	uint32_t unicode_data[2];
	int i, j = 0, unicode_len = 0;
	uint8_t unicode_str[MAX_UNICODE_LENGTH] = { '\0' };
	char *store = (char *) buf;

	if (state->readMemoryConcrete(cr3, addr, unicode_data, sizeof(unicode_data)) < 0) {
		store[0] = '\0';
		goto done;
	}

	unicode_len = (int) (unicode_data[0] & 0xFFFF);
	if (unicode_len > MAX_UNICODE_LENGTH)
		unicode_len = MAX_UNICODE_LENGTH;

	if (state->readMemoryConcrete(cr3, unicode_data[1], (void *) unicode_str, unicode_len) < 0) {
		store[0] = '\0';
		goto done;
	}

	for (i = 0, j = 0; i < unicode_len; i += 2, j++) {
		store[j] = tolower(unicode_str[i]);
	}
	store[j] = '\0';

done:
	return j;
}


/* this function convert a full DLL name to a base name. */
char *  WindowsMonitor::get_basename(char *fullname)
{
	int i = 0, last_slash = -1;
	for(; fullname[i] != 0; i++)
		if (fullname[i] == '/' || (fullname[i] == '\\'))
			last_slash = i;

	return fullname + last_slash + 1;
}

void  WindowsMonitor::update_kernel_modules(DBAFExecutionState *state,  process *proc,target_ulong vaddr) {
	uint32_t kdvb, psLM, curr_mod, next_mod;
	uint32_t holder;
	module *curr_entry = NULL;
	if (m_pKPCRAddr == 0)
		return;
	state->readMemoryConcrete(m_pKPCRAddr + m_os_special->offset->KDVB_OFFSET, &kdvb, 4);
	state->readMemoryConcrete(kdvb + m_os_special->offset->PSLM_OFFSET, &psLM, 4);
	state->readMemoryConcrete(psLM, &curr_mod, 4);

	while (curr_mod != 0 && curr_mod != psLM) {
		IMAGE_NT_HEADERS nth;
		uint32_t base = 0;
		state->readMemoryConcrete(
				curr_mod + m_os_special->offset->DLLBASE_OFFSET,
				&base, 4);
		char name[512];
		char key[512];
		char *base_name;

		readustr_with_cr3(state, curr_mod + m_os_special->offset->DLLNAME_OFFSET,
				proc->cr3, name);
		base_name = get_basename(name);

		//We get checksum and use base module name along with checksum as the key to
		//uniquely identify a module.
		//We do not use full module name, because the same module can be referenced through
		//different full paths: e.g., c://windows/system32 and /systemroot/windows/system32.
		if(get_IMAGE_NT_HEADERS(state, proc->cr3, base, &nth) < 0)
			goto next;

		snprintf(key, sizeof(key)-1, "%s:%08x", base_name, nth.OptionalHeader.CheckSum);
		if(m_ntmodulename == base_name){
			if(GetKernelLoadBase() != base){
				m_kdVersion.KernBase = base;
				dbaf()->getWarningStream () << "WindowsMonitor: m_kdVersion may not be initialized correctly." << '\n';
			}
		}
		//See if we have extracted detailed info about this module
		curr_entry = VMI_find_module_by_key(key);
		if (!curr_entry) {
			curr_entry = new module();
			state->readMemoryConcrete(
					curr_mod + m_os_special->offset->SIZE_OFFSET,
					&curr_entry->size, 4); // dllsize  SIZE_OFFSET

			strncpy(curr_entry->name, base_name, sizeof(curr_entry->name)-1);
			readustr_with_cr3(state, curr_mod + m_os_special->offset->FULLDLLNAME_OFFSET, proc->cr3, curr_entry->fullname);
			VMI_add_module(curr_entry, key);
		}

		VMI_insert_module(state, kernel_proc->pid, base, curr_entry);

next:
		state->readMemoryConcrete( curr_mod, &next_mod, 4);
		state->readMemoryConcrete(next_mod + 4, &holder, 4);
		if (holder != curr_mod) {
			break;
		}
		curr_mod = next_mod;
	}

}

void  WindowsMonitor::update_loaded_user_mods_with_peb(DBAFExecutionState *state, process *proc,
		uint32_t peb, target_ulong vaddr)
{
	uint32_t ldr, memlist, first_dll=0, curr_dll, count=0;
	module *curr_entry = NULL;

	if (peb == 0x00) return;

	state->readMemoryConcrete(peb +  m_os_special->offset->LDR_OFFSET, &ldr, 4);
	memlist = ldr + m_os_special->offset->INLOADORDERMODULELIST_OFFSET;
	state->readMemoryConcrete( memlist, &first_dll, 4);

	if (first_dll == 0)	return;

	curr_dll = first_dll;
	do {
		IMAGE_NT_HEADERS nth;
		count++;
		uint32_t base = 0; //, size = 0;
		if (state->readMemoryConcrete( curr_dll + m_os_special->offset->DLLBASE_OFFSET, &base, 4) < 0)
			break;

		if (!is_page_resolved(proc, base)) {
			char name[512];
			char key[512];

			readustr_with_cr3(state, curr_dll + m_os_special->offset->DLLNAME_OFFSET, proc->cr3, name);

			//We get checksum and use base module name along with checksum as the key to
			//uniquely identify a module.
			//We do not use full module name, because the same module can be referenced through
			//different full paths: e.g., c://windows/system32 and /systemroot/windows/system32.
			if(get_IMAGE_NT_HEADERS(state, proc->cr3, base, &nth) < 0)
				goto next;

			snprintf(key, sizeof(key)-1, "%s:%08x", name, nth.OptionalHeader.CheckSum);
			//ini ntdll loadbase
			if(m_ntdllLoadBase == 0 && strcmp("ntdll.dll",name) == 0){
				m_ntdllLoadBase = base;
			}
			//See if we have extracted detailed info about this module
			curr_entry = VMI_find_module_by_key(key);

			if(!curr_entry) { //We haven't seen this module before, even in other process memory spaces
				curr_entry = new module();
				readustr_with_cr3(state, curr_dll + m_os_special->offset->FULLDLLNAME_OFFSET, proc->cr3, curr_entry->fullname);
				state->readMemoryConcrete(curr_dll + m_os_special->offset->SIZE_OFFSET, &curr_entry->size, 4);
				strncpy(curr_entry->name, name, sizeof(curr_entry->name)-1);
				VMI_add_module(curr_entry, key);
			}

			VMI_insert_module(state, proc->pid, base, curr_entry);
		}

next:
		//read the next DLL
		state->readMemoryConcrete(curr_dll, &curr_dll, 4);
	} while (curr_dll != 0 && curr_dll != first_dll && count < MAX_MODULE_COUNT);

}
/*
 * 可以通过数据库文件来加速这个过程，事先解析好相关共用文件的导出表信息，然后存储（以name+checksum为标识），这样就不用每次都动态解析出来了。
 */
void  WindowsMonitor::extract_export_table(DBAFExecutionState *state,IMAGE_NT_HEADERS *nth, uint32_t cr3, uint32_t base, module *mod)
{
	IMAGE_EXPORT_DIRECTORY ied;
	DWORD edt_va;
	//DWORD edt_size;
	DWORD *func_addrs=NULL, *name_addrs=NULL;
	WORD *ordinals=NULL;
	bool symbols_extracted = true;
	int triedtimes;
	DWORD i;
	DWORD checksum = nth->OptionalHeader.CheckSum;
	edt_va = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
//	edt_size = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if(state->readMemoryConcrete(cr3, base + edt_va, &ied, sizeof(ied)) < 0) {
		goto done;
	}

	if(ied.NumberOfFunctions == 0 || ied.NumberOfNames == 0) {
		mod->symbols_extracted = true;
		goto done;
	}

	func_addrs = (DWORD *) malloc (sizeof(DWORD) * ied.NumberOfFunctions);
	name_addrs = (DWORD *) malloc (sizeof(DWORD) * ied.NumberOfNames);
	ordinals = (WORD *) malloc (sizeof(WORD) * ied.NumberOfNames);
	if(!func_addrs || !name_addrs || !ordinals)
		goto done;

	if(state->readMemoryConcrete(cr3, base + ied.AddressOfFunctions, func_addrs,
			sizeof(DWORD) * ied.NumberOfFunctions) < 0) {
		goto done;
	}

	if(state->readMemoryConcrete(cr3, base + ied.AddressOfNames, name_addrs,
			sizeof(DWORD) * ied.NumberOfNames) < 0) {
		goto done;
	}

	if(state->readMemoryConcrete(cr3, base + ied.AddressOfNameOrdinals, ordinals,
			sizeof(WORD) * ied.NumberOfNames) < 0) {
		goto done;
	}
	triedtimes = 0;
	for(i = 0; i < ied.NumberOfNames; i++) {
		WORD index = ordinals[i];
		string functionName;
		if(index >= ied.NumberOfFunctions)
			continue;
		if(!state->readString(cr3, base + name_addrs[i], functionName, 256 )){
			triedtimes ++;
//			cpu_ldub_code(state->getCPUArchState(), base + name_addrs[i] + functionName.length());
			if(triedtimes >= 10){
				symbols_extracted = false;
				break;
			}else
				continue;
		}
		funcmap_insert_function(mod->name, functionName.c_str(), func_addrs[index]);
	}
	if(symbols_extracted)
		dump_module_function(mod->name, checksum);
	mod->symbols_extracted = symbols_extracted;
done:
	if(func_addrs)
		free(func_addrs);
	if(name_addrs)
		free(name_addrs);
	if(ordinals)
		free(ordinals);
}

//Extract info in PE header and export table from a PE module
//If everything is done successfully, mod->symbols_extracted will be set true
void  WindowsMonitor::extract_PE_info(DBAFExecutionState *state,uint32_t cr3, uint32_t base, module *mod)
{
	IMAGE_NT_HEADERS nth;

	if (get_IMAGE_NT_HEADERS(state, cr3, base, &nth) < 0)
		return;

	mod->checksum = nth.OptionalHeader.CheckSum;
	mod->codesize = nth.OptionalHeader.SizeOfCode;
	mod->major = nth.OptionalHeader.MajorImageVersion;
	mod->minor = nth.OptionalHeader.MinorImageVersion;
	extract_export_table(state, &nth, cr3, base, mod);
}


void  WindowsMonitor::retrieve_missing_symbols(DBAFExecutionState *state,process *proc, target_ulong vaddr)
{
	unordered_map < uint32_t,module * >::iterator iter = proc->module_list.begin();

	for(; iter!=proc->module_list.end(); iter++) {
		module *cur_mod = iter->second;
		if (!cur_mod->symbols_extracted && (vaddr > iter->first && vaddr < (iter->first + cur_mod->size))) {
			extract_PE_info(state, proc->cr3, iter->first, cur_mod);
			if (cur_mod->symbols_extracted ) {
				onSymbolsResolved.emit(state,cur_mod);
			}
		}
	}
}

inline void WindowsMonitor::get_new_modules(DBAFExecutionState *state, process * proc, target_ulong vaddr)
{
	uint32_t base = 0, self = 0;
	if (proc == kernel_proc) {
		update_kernel_modules(state, proc, vaddr);
	} else {
		base = state->readCpu0State(CPU_SEGS,R_FS);
		state->readMemoryConcrete(base + m_os_special->offset->TEB_FS_OFFSET, &self, 4);//TEB

		if (base != 0 && base == self) {
			uint32_t peb_addr = base + m_os_special->offset->PEB_OFFSET;
			uint32_t peb;
			state->readMemoryConcrete(peb_addr, &peb, 4);
			update_loaded_user_mods_with_peb(state, proc, peb, vaddr);
		}
	}
}

///////////////////////////////////////////////////////////////////////

WindowsMonitorState::WindowsMonitorState()
{
}

WindowsMonitorState::~WindowsMonitorState()
{

}

WindowsMonitorState* WindowsMonitorState::clone() const
{
    return new WindowsMonitorState(*this);
}

PluginState *WindowsMonitorState::factory(Plugin *p, DBAFExecutionState *state)
{
    return new WindowsMonitorState();
}
