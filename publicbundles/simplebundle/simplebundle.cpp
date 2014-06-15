/*
 Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
 This is a plugin of DECAF. You can redistribute and modify it
 under the terms of BSD license but it is made available
 WITHOUT ANY WARRANTY. See the top-level COPYING file for more details.

 For more information about DECAF and other softwares, see our
 web site at:
 http://sycurelab.ecs.syr.edu/

 If you have any questions about DECAF,please post it on
 http://code.google.com/p/decaf-platform/
 */
/**
 * @author Xunchao Hu, Heng Yin
 * @date Jan 24 2013
 */

#include <sys/time.h>
extern "C"
{
#include "sysemu/sysemu.h"
#include "DBAF_common.h"
#include "DBAF_main.h"
}
#include <dbaf/DBAF.h>
#include <dbaf/Plugin.h>
using namespace dbaf;
namespace dbaf {
class DBAF;
}
extern DBAF* g_dbaf;

extern "C" void do_simplebundle_cmd_internal(Monitor *mon, const QDict *qdict);
extern "C" void simplebundle_cleanup_internal();
extern "C" void simplebundle_enable_internal();
extern "C" void simplebundle_disable_internal();

static int runningState = 0;
void stop_vm(void) {
	if (runstate_check(RUN_STATE_RUNNING)) {
		runningState = 1;
		vm_stop(RUN_STATE_PAUSED);
	} else
		runningState = 0;
}

void start_vm(void) {
	if (runningState) vm_start();
}

void do_simplebundle_cmd_internal(Monitor *mon, const QDict *qdict) {
	if (qdict_haskey(qdict, "cmd")) {
		monitor_printf(mon, "%s command is received\n",
				qdict_get_str(qdict, "cmd"));
	} else
		monitor_printf(mon, "simple_bundle_cmd command is malformed\n");
}
//unload
void simplebundle_cleanup_internal() {
	fprintf(stderr, "simplebundle is cleaned\n");

}
void simplebundle_enable_internal() {
	fprintf(stderr, "simplebundle is enable\n");
	g_dbaf->getPlugin("SimpleBundlePlugin")->Enable();
	g_dbaf->getPlugin("BasicBlockSignalPlugin")->Enable();
}
void simplebundle_disable_internal() {
	fprintf(stderr, "simplebundle is disable\n");
	g_dbaf->getPlugin("SimpleBundlePlugin")->Disable();
	g_dbaf->getPlugin("BasicBlockSignalPlugin")->Disable();
}
