#include <inttypes.h>
#include <map>
#include <vector>
#include <list>
#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cassert>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <dbaf/DBAF_main.h>
#include <dbaf/DBAF.h>
#include <dbaf/DBAF_qemu_mini.h>
#include <dbaf/plugins/OSMonitor.h>
#include "function_map.h"
#include "monitor/monitor.h"

using namespace std;
using namespace dbaf;
using namespace dbaf::plugins;

// Map ``module name" -> "function name" -> offset
map<string, map<string, uint32_t> > map_function_offset;

// Map "module name" -> "offset" -> "function name"
map<string, map<uint32_t, string> > map_offset_function;

target_ulong funcmap_get_pc(const char *module_name, const char *function_name, target_ulong cr3)
{
	target_ulong base;
	dbaf::plugins::OSMonitor *osmonitor = static_cast<dbaf::plugins::OSMonitor*>(g_dbaf->getPlugin("Interceptor"));
	if(!osmonitor)
		return 0;
	module *mod = osmonitor->VMI_find_module_by_name(module_name, cr3, &base);
	if(!mod)
		return 0;

	map<string, map<string, uint32_t> >::iterator iter = map_function_offset.find(module_name);
	if(iter == map_function_offset.end())
		return 0;

	map<string, uint32_t>::iterator iter2 = iter->second.find(function_name);
	if(iter2 == iter->second.end())
		return 0;

	return iter2->second + base;
}

int funcmap_get_name(target_ulong pc, target_ulong cr3, string &mod_name, string &func_name)
{
	target_ulong base;
	dbaf::plugins::OSMonitor *osmonitor = static_cast<dbaf::plugins::OSMonitor*>(g_dbaf->getPlugin("Interceptor"));
	if(!osmonitor)
		return 0;
	module *mod = osmonitor->VMI_find_module_by_pc(pc, cr3, &base);
	if(!mod)
		return -1;

	map<string, map<uint32_t, string> >::iterator iter = map_offset_function.find(mod->name);
	if (iter == map_offset_function.end())
		return -1;

	map<uint32_t, string>::iterator iter2 = iter->second.find(pc - base);
	if (iter2 == iter->second.end())
		return -1;

	mod_name = mod->name;
	func_name = iter2->second;
	return 0;
}

int funcmap_get_name_c(target_ulong pc, target_ulong cr3, char *mod_name, char *func_name)
{
	string mod, func;
	int ret = funcmap_get_name(pc, cr3, mod, func);
	if(ret == 0) {
		//we assume the caller has allocated enough space for mod_name and func_name
		strncpy(mod_name, mod.c_str(), 512);
		strncpy(func_name, func.c_str(), 512);
	}

	return ret;
}




#define BOUNDED_STR(len) "%" #len "s"
#define BOUNDED_QUOTED(len) "%" #len "[^\"]"
#define BOUNDED_STR_x(len) BOUNDED_STR(len)
#define BOUNDED_QUOTED_x(len) BOUNDED_QUOTED(len)
#define BSTR BOUNDED_STR_x(511)
#define BQUOT BOUNDED_QUOTED_x(511)


void parse_function(const char *message)
{
	char module[512];
	char fname[512];
	uint32_t offset;

	if (sscanf(message, " F " BSTR " " BSTR " %x ", module, fname, &offset) != 3)
		return;

	funcmap_insert_function(module, fname, offset);
}

void dump_module_function(const char* module, uint64_t checksum) {
	map<string, map<string, uint32_t> >::iterator iter =
			map_function_offset.find(module);
	if (iter == map_function_offset.end())
		return;
	map<string, uint32_t>::iterator iterfunc = iter->second.begin();
	if (g_dbaf) {
		while (iterfunc != iter->second.end()) {
			g_dbaf->getDebugStream() << "resolved symbol for mod:" << module << " checksum:" << checksum
					<< " func:" << iterfunc->first << " offset:"
					<< iterfunc->second << endl;
			iterfunc++;
		}
	}
}
void funcmap_insert_function(const char *module, const char *fname, uint32_t offset)
{
	map<string, map<string, uint32_t> >::iterator iter = map_function_offset.find(module);
	if (iter == map_function_offset.end()) {
		map<string, uint32_t> func_offset;
		func_offset[fname] = offset;
		map_function_offset[module] = func_offset;
	} else {
		iter->second.insert(pair<string, uint32_t>(string(fname), offset));
	}

	map<string, map<uint32_t, string> >::iterator iter2 = map_offset_function.find(module);
	if (iter2 == map_offset_function.end()) {
		map<uint32_t, string> offset_func;
		offset_func[offset] = fname;
		map_offset_function[module] = offset_func;
	} else
		iter2->second.insert(pair<uint32_t, string>(offset, fname));

}

void function_map_init()
{

}

void function_map_cleanup()
{
  map_function_offset.clear();
  map_offset_function.clear();
}
extern "C" void do_module_functions_internal(Monitor *mon, const char *module);
void do_module_functions_internal(Monitor *mon,const char *module){
	map<string, map<string, uint32_t> >::iterator iter =
				map_function_offset.find(module);
		if (iter == map_function_offset.end())
			return;
		map<string, uint32_t>::iterator iterfunc = iter->second.begin();
		if (g_dbaf) {
			while (iterfunc != iter->second.end()) {
				monitor_printf(mon, "0x%08x\t%s\n", iterfunc->second, iterfunc->first.c_str());
				iterfunc++;
			}
		}
}
