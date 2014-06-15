/*
 * DBAF_main.c
 *
 *  Created on: Oct 14, 2012
 *      Author: lok
 */

#include <dlfcn.h>
#include "sysemu/sysemu.h"

#include "DBAF_main.h"
#include "monitor/monitor.h"
#include "qemu-common.h"
#include "exec/cpu-all.h"
#include "tcg.h"

#if !(DEBUG_DBAF)
// use micro mechanism
//void DBAF_monitor_printf(Monitor *mon, const char *fmt, ...){}
#else
typedef struct _IO_FILE FILE;
bool firstprint = true;
void DBAF_monitor_printf(Monitor *mon, const char *fmt, ...)
{

    va_list ap;
    va_start(ap, fmt);
    if(firstprint){
    	char pfmt[512]="\n";
    	strcat(pfmt,fmt);
    	firstprint = false;
    	monitor_vprintf(mon, pfmt, ap);
	}else{
		monitor_vprintf(mon, fmt, ap);
	}
    va_end(ap);

}
#endif

BundleInfo dbaf_bundles[] ={
		{ NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	    { NULL,NULL, "" },
	};

int dbaf_bundles_size =  sizeof(dbaf_bundles) / sizeof(BundleInfo);

mon_cmd_t DBAF_mon_cmds[] = {
#include "DBAF_mon_cmds.h"
		{ NULL, NULL , }, };

mon_cmd_t DBAF_info_cmds[] = {
#include "DBAF_info_cmds.h"
		{ NULL, NULL , }, };


int do_load_bundle(Monitor *mon, const QDict *qdict, QObject **ret_data) {
	do_load_bundle_internal(mon, qdict_get_str(qdict, "filename"));
	return (0);
}

void do_load_bundle_internal(Monitor *mon, const char *plugin_path) {
	bundle_interface_t *(*init_bundle)(void);
	char *error;
	BundleInfo* load_bundle = NULL;
	int loaded = 0;
	//先比较是否已经加载
	uint32_t bundlesize=0;
	int counter = 0;
	bundlesize = sizeof(dbaf_bundles) / sizeof(BundleInfo);
	for (counter = 0; counter < bundlesize; counter++) {
		if(strcmp(dbaf_bundles[counter].bundle_path, plugin_path) == 0){
			monitor_printf(mon, "%s has already been loaded! \n", plugin_path);
			loaded = 1;
		}
	}
	if(loaded == 0){
		for (counter = 0; counter < bundlesize; counter++) {
			if (dbaf_bundles[counter].handle == NULL ) {
				load_bundle = &(dbaf_bundles[counter]);
				break;
			}
		}
		load_bundle->handle = dlopen(plugin_path, RTLD_NOW);
		if (NULL == load_bundle->handle) {
			char tempbuf[128];
			strncpy(tempbuf, dlerror(), 127);
			monitor_printf(mon, "%s\n", tempbuf);
			fprintf(stderr, "%s COULD NOT BE LOADED - ERR = [%s]\n", plugin_path,
					tempbuf);
			return;
		}
		dlerror();
		init_bundle = dlsym(load_bundle->handle, "init_bundle");
		if ((error = dlerror()) != NULL ) {
			fprintf(stderr, "%s\n", error);
			dlclose(load_bundle->handle);
			load_bundle->handle = NULL;
			load_bundle->bundle_path[0] = '\0';
			return;
		}

		load_bundle->bundle = init_bundle();

		if (NULL == load_bundle->bundle) {
			monitor_printf(mon, "fail to initialize the bundle!\n");
			dlclose(load_bundle->handle);
			load_bundle->handle = NULL;
			load_bundle->bundle = NULL;
			load_bundle->bundle_path[0] = '\0';
			return;
		}
		strncpy(load_bundle->bundle_path, plugin_path, PATH_MAX);
		monitor_printf(mon, "%s is loaded successfully!\n", plugin_path);
	}


}

int do_enable_bundle(Monitor *mon, const QDict *qdict, QObject **ret_data){
	const char* fpath=NULL;
	BundleInfo* load_bundle = NULL;
	int loaded = 0;
	uint32_t bundlesize=0;
	int counter = 0;
	fpath = qdict_get_str(qdict, "fpath");
	bundlesize = sizeof(dbaf_bundles) / sizeof(BundleInfo);
	for (counter = 0; counter < bundlesize; counter++) {
		if(strcmp(dbaf_bundles[counter].bundle_path, fpath) == 0){
			loaded = 1;
			load_bundle = &(dbaf_bundles[counter]);
		}
	}
	if(loaded == 1){
		if(load_bundle->bundle && load_bundle->bundle->bundle_enable)
			load_bundle->bundle->bundle_enable();
		monitor_printf(default_mon, "%s is enabled!\n", load_bundle->bundle_path);

	}else{
		monitor_printf(default_mon, "%s is not loaded!\n", fpath);
	}
	CPUState *cpu;
	CPU_FOREACH(cpu)
	{
		if (cpu) {
			CPUArchState *env = cpu->env_ptr;
			tb_flush(env);
		}
	}
	return (0);
}
int do_disable_bundle(Monitor *mon, const QDict *qdict, QObject **ret_data){
	const  char* fpath=NULL;
	BundleInfo* load_bundle = NULL;
	int loaded = 0;
	uint32_t bundlesize=0;
	int counter = 0;
	fpath = qdict_get_str(qdict, "fpath");
	bundlesize = sizeof(dbaf_bundles) / sizeof(BundleInfo);
	for (counter = 0; counter < bundlesize; counter++) {
		if(strcmp(dbaf_bundles[counter].bundle_path, fpath) == 0){
			loaded = 1;
			load_bundle = &(dbaf_bundles[counter]);
		}
	}
	if(loaded == 1){
		if(load_bundle->bundle && load_bundle->bundle->bundle_disable)
			load_bundle->bundle->bundle_disable();
		monitor_printf(default_mon, "%s is disabled!\n", load_bundle->bundle_path);

	}else{
		monitor_printf(default_mon, "%s is not loaded!\n", fpath);
	}
	CPUState *cpu;
	CPU_FOREACH(cpu)
	{
		if (cpu) {
			CPUArchState *env = cpu->env_ptr;
			tb_flush(env);
		}
	}
	return (0);
}
int do_unload_bundle(Monitor *mon, const QDict *qdict, QObject **ret_data) {
	const  char* fpath=NULL;
	BundleInfo* load_bundle = NULL;
	int loaded = 0;
	uint32_t bundlesize=0;
	int counter = 0;
	fpath = qdict_get_str(qdict, "fpath");
	bundlesize = sizeof(dbaf_bundles) / sizeof(BundleInfo);
	for (counter = 0; counter < bundlesize; counter++) {
		if(strcmp(dbaf_bundles[counter].bundle_path, fpath) == 0){
			loaded = 1;
			load_bundle = &(dbaf_bundles[counter]);
		}
	}
	if(loaded == 1){
		if(load_bundle->bundle)
			load_bundle->bundle->bundle_cleanup();
		if(load_bundle->handle)
			dlclose(load_bundle->handle);
		load_bundle->handle = NULL;
		load_bundle->bundle = NULL;

		monitor_printf(default_mon, "%s is unloaded!\n", load_bundle->bundle_path);
		load_bundle->bundle_path[0] = '\0';

	}else{
		monitor_printf(default_mon, "%s is not loaded!\n", fpath);
	}
	return (0);
}
void do_guest_ps(Monitor *mon, const QDict *qdict)
{
	do_guest_ps_internal(mon,qdict);
}

void do_guest_modules(Monitor *mon, const QDict *qdict)
{
	do_guest_modules_internal(mon, qdict);
}
void do_module_functions(Monitor *mon, const QDict *qdict){
	const char* module = NULL;
	module = qdict_get_str(qdict, "module");
	do_module_functions_internal(mon, module);
}

