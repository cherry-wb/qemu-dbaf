/*
 * OSMonitor.cpp
 *
 *  Created on: 2014-6-4
 *      Author: wb
 */

#include "OSMonitor.h"
#include <dbaf/DBAF.h>
#include <dbaf/DBAF_qemu_mini.h>
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
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
#include "cpu.h"
#include "config.h"
#ifdef __cplusplus
};
#endif /* __cplusplus */

namespace dbaf {
namespace plugins {

using namespace std;
using namespace std::tr1;

process* OSMonitor::VMI_find_process_by_name(char *name)
{
	unordered_map < uint32_t, process * >::iterator iter;
	for (iter = process_map.begin(); iter != process_map.end(); iter++) {
		process * proc = iter->second;
		if (strcmp((const char *)name,proc->name) == 0) {
			return proc;
		}
	}
	return 0;
}

process* OSMonitor::VMI_find_process_by_pgd(uint32_t pgd)
{
    unordered_map < uint32_t, process * >::iterator iter =
	process_map.find(pgd);

    if (iter != process_map.end())
		return iter->second;

	return NULL;
}


process *OSMonitor::VMI_find_process_by_pid(uint32_t pid)
{
	unordered_map < uint32_t, process * >::iterator iter =
		process_pid_map.find(pid);

	if (iter == process_pid_map.end())
		return NULL;

	return iter->second;
}


module* OSMonitor::VMI_find_module_by_key(const char *key)
{
	string temp(key);
	unordered_map < string, module * >::iterator iter =
		module_name.find(temp);
	if (iter != module_name.end()){
		return iter->second;
	}
	return NULL;
}

module* OSMonitor::VMI_find_module_by_base(target_ulong pgd, uint32_t base)
{
	unordered_map<uint32_t, process *>::iterator iter = process_map.find(pgd);
	process *proc;

	if (iter == process_pid_map.end()) //pid not found
		return NULL;

	proc = iter->second;

	unordered_map<uint32_t, module *>::iterator iter_m = proc->module_list.find(base);
	if(iter_m == proc->module_list.end())
		return NULL;

	return iter_m->second;
}

module* OSMonitor::VMI_find_module_by_pc(target_ulong pc, target_ulong pgd, target_ulong *base)
{
	process *proc ;
	if (pc >= GetKernelStart()) {
		proc = process_pid_map[0];
	} else {
		unordered_map < uint32_t, process * >::iterator iter_p = process_map.find(pgd);
		if (iter_p == process_map.end())
			return NULL;

		proc = iter_p->second;
	}

	unordered_map< uint32_t, module * >::iterator iter;
	for (iter = proc->module_list.begin(); iter != proc->module_list.end(); iter++) {
		module *mod = iter->second;
		if (iter->first <= pc && mod->size + iter->first > pc) {
			*base = iter->first;
			return mod;
		}
	}

    return NULL;
}

module* OSMonitor::VMI_find_module_by_name(const char *name, target_ulong pgd, target_ulong *base)
{
	unordered_map < uint32_t, process * >::iterator iter_p = process_map.find(pgd);
	if (iter_p == process_map.end())
		return NULL;

	process *proc = iter_p->second;

	unordered_map< uint32_t, module * >::iterator iter;
	for (iter = proc->module_list.begin(); iter != proc->module_list.end(); iter++) {
		module *mod = iter->second;
		if (strcasecmp(mod->name, name) == 0) {
			*base = iter->first;
			return mod;
		}
	}

    return NULL;
}

/*
 *
 * Add module to a global list. per process's module list only keeps pointers to this global list.
 *
 */
int OSMonitor::VMI_add_module(module *mod, const char *key){
	if(mod==NULL)
		return -1;
	string temp(key);
	unordered_map < string, module * >::iterator iter = module_name.find(temp);
	if (iter != module_name.end()){
		return -1;
	}
	module_name[temp]=mod;
	return 1;
}

int OSMonitor::VMI_create_process(DBAFExecutionState* state, process *proc)
{
    unordered_map < uint32_t, process * >::iterator iter =
    	process_pid_map.find(proc->pid);
    if (iter != process_pid_map.end()){
    	VMI_remove_process(state, proc->pid);
    }
    unordered_map < uint32_t, process * >::iterator iter2 =
        	process_map.find(proc->cr3);
    if (iter2 != process_map.end()) {
    	VMI_remove_process(state, iter2->second->pid);
    }
   	process_pid_map[proc->pid] = proc;
   	process_map[proc->cr3] = proc;
   	dbaf()->getDebugStream() << "Caught process create process name:" << proc->name << " pid:"<< proc->pid << " cr3:" << proc->cr3 << " parentid:" << proc->parent_pid <<"\n";
    onProcessCreate.emit(g_dbaf_state,proc);
	return 0;
}


int OSMonitor::VMI_remove_process(DBAFExecutionState* state, uint32_t pid)
{
	process *proc;
    unordered_map < uint32_t, process * >::iterator iter =
    	process_pid_map.find(pid);

    if(iter == process_pid_map.end())
    	return -1;
    proc = iter->second;
	dbaf()->getDebugStream() << "Caught process exit, process name:" << proc->name << " pid:"<< proc->pid <<"\n";
	dbaf()->getDebugStream().flush();
    onProcessExit.emit(g_dbaf_state,proc);
	process_map.erase(iter->second->cr3);
	process_pid_map.erase(iter);
	delete iter->second;
	return 0;
}



int OSMonitor::VMI_insert_module(DBAFExecutionState* state, uint32_t pid, uint32_t base, module *mod)
{
	unordered_map<uint32_t, process *>::iterator iter = process_pid_map.find(
			pid);
	process *proc;
	if (iter == process_pid_map.end()) //pid not found
		return -1;
	proc = iter->second;
	//Now the pages within the module's memory region are all resolved
	//We also need to removed the previous modules if they happen to sit on the same region
	for (uint32_t vaddr = base; vaddr < base + mod->size; vaddr += 4096) {
		proc->resolved_pages.insert(vaddr >> 12);
		proc->unresolved_pages.erase(vaddr >> 12);
		proc->module_list.erase(vaddr);
	}
	//Now we insert the new module in module_list
	proc->module_list[base] = mod;

	dbaf()->getDebugStream() << "Caught module load module name:" << mod->name  << " loadbase:" << hexval(base) << " process name:" << proc->name<< " pid:"<< proc->pid << " cr3:" << proc->cr3<<"\n";
	dbaf()->getDebugStream().flush();
	onModuleLoad.emit(g_dbaf_state,proc,mod);
	return 0;
}

int OSMonitor::VMI_remove_module(DBAFExecutionState* state, uint32_t pid, uint32_t base)
{
	unordered_map<uint32_t, process *>::iterator iter = process_pid_map.find(
			pid);
	process *proc;
	if (iter == process_pid_map.end()) //pid not found
		return -1;

	proc = iter->second;
	unordered_map<uint32_t, module *>::iterator m_iter = proc->module_list.find(base);
	if(m_iter == proc->module_list.end())
		return -1;
	module *mod = m_iter->second;
	for (uint32_t vaddr = base; vaddr < base + mod->size; vaddr += 4096) {
		proc->resolved_pages.erase(vaddr >> 12);
		proc->unresolved_pages.erase(vaddr >> 12);
	}
	dbaf()->getDebugStream() << "Caught module unload module name:" << mod->name  << " loadbase:" << hexval(base) << " process name:" << proc->name<< " pid:"<< proc->pid <<"\n";
	onModuleUnLoad.emit(g_dbaf_state,proc,mod);
	proc->module_list.erase(m_iter);
	return 0;
}
/*
 * FIXME not unique
 */
target_ulong OSMonitor::getCr3(target_ulong pc) {
	unordered_map<uint32_t, process *>::iterator iterp;
	for (iterp = process_map.begin(); iterp != process_map.end(); iterp++) {
		process *proc = iterp->second;
		unordered_map<uint32_t, module *>::iterator iter;
		for (iter = proc->module_list.begin(); iter != proc->module_list.end();
				iter++) {
			module *mod = iter->second;
			if (iter->first <= pc && mod->size + iter->first > pc) {
				return iterp->first;
			}
		}
	}
	return 0;
}
void OSMonitor::list_processes(Monitor *mon) {
	process *proc;
	unordered_map<uint32_t, process *>::iterator iter;

	for (iter = process_map.begin(); iter != process_map.end(); iter++) {
		proc = iter->second;
		monitor_printf(mon, "%d\tcr3=0x%08x\t%s\n", proc->pid, proc->cr3,
				proc->name);
	}
}
void OSMonitor::list_modules(Monitor *mon, int pid) {
	unordered_map<uint32_t, process *>::iterator iter = process_pid_map.find(
			pid);
	if (iter == process_pid_map.end())	//pid not found
		return;

	unordered_map<uint32_t, module *>::iterator iter2;
	process *proc = iter->second;

	for (iter2 = proc->module_list.begin(); iter2 != proc->module_list.end();
			iter2++) {
		monitor_printf(mon, "%20s\t0x%08x\t0x%08x\n", iter2->second->name, iter2->first,
				iter2->second->size);
	}

}
void  OSMonitor::select_process(Monitor *mon,int pid){
	unordered_map<uint32_t, process *>::iterator iter = process_pid_map.find(
			pid);
	if (iter == process_pid_map.end())	//pid not found
		monitor_printf(mon, "process with this pid not found.\n");
	else {
		process *proc = iter->second;
		g_selected_cr3 = proc->cr3;
		monitor_printf(mon, "selected process %20s\t pid:0x%08x\t cr3:0x%08x\n",
				proc->name, proc->pid, proc->cr3);
	}
}
} // namespace plugins
} /* namespace dbaf */

extern "C" void do_guest_ps_internal(Monitor *mon, const QDict *qdict);
extern "C" void do_guest_modules_internal(Monitor *mon, const QDict *qdict);
extern "C" void do_select_process_internal(Monitor *mon, const QDict *qdict);
void do_guest_ps_internal(Monitor *mon, const QDict *qdict){
	dbaf::plugins::OSMonitor *osmonitor =
			static_cast<dbaf::plugins::OSMonitor*>(g_dbaf->getPlugin(
					"Interceptor"));
	if (!osmonitor)
		return;
	osmonitor->list_processes(mon);
}

void do_guest_modules_internal(Monitor *mon, const QDict *qdict) {
	int pid = -1;
	if (qdict_haskey(qdict, "pid")) {
		pid = qdict_get_int(qdict, "pid");
	}

	if (pid == -1) {
		monitor_printf(mon, "need a pid\n");
	}
	dbaf::plugins::OSMonitor *osmonitor =
			static_cast<dbaf::plugins::OSMonitor*>(g_dbaf->getPlugin(
					"Interceptor"));
	if (!osmonitor)
		return;
	osmonitor->list_modules(mon, pid);
}

void do_select_process_internal(Monitor *mon, const QDict *qdict){
	int pid = -1;
	if (qdict_haskey(qdict, "pid")) {
		pid = qdict_get_int(qdict, "pid");
	}

	if (pid == -1) {
		monitor_printf(mon, "need a pid\n");
	}
	dbaf::plugins::OSMonitor *osmonitor =
			static_cast<dbaf::plugins::OSMonitor*>(g_dbaf->getPlugin(
					"Interceptor"));
	if (!osmonitor)
		return;
	osmonitor->select_process(mon, pid);
}
