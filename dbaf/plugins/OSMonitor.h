#ifndef __MODULE_MONITOR_PLUGIN_H__
#define __MODULE_MONITOR_PLUGIN_H__
#include <dbaf/Plugin.h>
#include <dbaf/DBAFExecutionState.h>
#include "monitor/monitor.h"

#include <iostream>
#include <list>
#include <tr1/unordered_map>
#include <tr1/unordered_set>

using namespace std;
using namespace std::tr1;

#define NAMESIZEC 16
#define MAX_NAME_LENGTHC 64

namespace dbaf {
namespace plugins {

class module{
public:
	char name[32];
	char fullname[256];
	uint32_t size;
	uint32_t codesize; // use these to identify dll
	uint32_t checksum;
	uint16_t major;
	uint16_t minor;
	bool	symbols_extracted;
	unordered_map < uint32_t, string> function_map_offset;
	unordered_map < string, uint32_t> function_map_name;
	bool Contains(uint64_t RunTimeAddress, uint64_t LoadBase) const {
		uint64_t RVA = RunTimeAddress - LoadBase;
		return RVA < size;
	}
};
struct moduleByName {
    bool operator()(const module& s1,
      const module& s2) const {
        return s1.name < s2.name;
    }

    bool operator()(const module* s1,
      const module* s2) const {
        return s1->name < s2->name;
    }
  };
class process{
public:
    uint32_t cr3;
    uint32_t pid;
    uint32_t parent_pid;
    uint32_t EPROC_base_addr;
    char name[16];
    //map base address to module pointer
    unordered_map < uint32_t,module * >module_list;
    //a set of virtual pages that have been resolved with module information
    unordered_set< uint32_t > resolved_pages;
    unordered_map< uint32_t, int > unresolved_pages;
};
/**
 *  Base class for default OS actions.
 *  It provides an interface for loading/unloading modules and processes.
 *  If you wish to add support for a new OS, implement this interface.
 *
 *  Note: several events use ModuleDescriptor as a parameter.
 *  The passed reference is valid only during the call. Do not store pointers
 *  to such objects, but make a copy instead.
 */
class OSMonitor:public Plugin
{
protected:
   OSMonitor(DBAF* dbaf): Plugin(dbaf){}
   virtual ~OSMonitor(){};
public:
	unordered_map<uint32_t, process *> process_map;
	unordered_map<uint32_t, process *> process_pid_map;
	unordered_map<string, module *> module_name;
public:
	fsigc::signal<void, DBAFExecutionState*, process*> onProcessCreate;
	fsigc::signal<void, DBAFExecutionState*, process*> onProcessExit;
	fsigc::signal<void, DBAFExecutionState*, process*, module*> onModuleLoad;
	fsigc::signal<void, DBAFExecutionState*, process*, module*> onModuleUnLoad;
	fsigc::signal<void, DBAFExecutionState*, module*> onSymbolsResolved;

	virtual uint64_t GetKernelStart() const=0;
	target_ulong getCr3(target_ulong pc);
	process* VMI_find_process_by_pid(uint32_t pid);
	process* VMI_find_process_by_pgd(uint32_t pgd);
	process* VMI_find_process_by_name(char *name);

	module* VMI_find_module_by_pc(target_ulong pc, target_ulong pgd,
			target_ulong *base);
	module* VMI_find_module_by_name(const char *name, target_ulong pgd,
			target_ulong *base);
	module* VMI_find_module_by_base(target_ulong pgd, uint32_t base);
	module* VMI_find_module_by_key(const char *key);

	int VMI_add_module(module *mod, const char *key);

	int VMI_create_process(DBAFExecutionState* state, process *proc);
	int VMI_remove_process(DBAFExecutionState* state, uint32_t pid);
	int VMI_insert_module(DBAFExecutionState* state, uint32_t pid, uint32_t base, module *mod);
	int VMI_remove_module(DBAFExecutionState* state, uint32_t pid, uint32_t base);

	void list_processes(Monitor *mon);
	void list_modules(Monitor *mon,int pid);

};

} // namespace plugins
} // namespace dbaf

#endif
