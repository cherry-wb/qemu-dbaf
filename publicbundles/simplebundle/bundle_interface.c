#include <sys/time.h>

#include "DBAF_common.h"
#include "DBAF_main.h"

static bundle_interface_t simplebundle_interface;

void do_simplebundle_cmd_internal(Monitor *mon, const QDict *qdict);
void simplebundle_cleanup_internal();
void simplebundle_enable_internal();
void simplebundle_disable_internal();

void do_simplebundle_cmd(Monitor *mon, const QDict *qdict){
	do_simplebundle_cmd_internal(mon,qdict);
}
void simplebundle_cleanup(){
	simplebundle_cleanup_internal();
}
void simplebundle_enable(){
	simplebundle_enable_internal();
}

void simplebundle_disable(){
	simplebundle_disable_internal();
}


static mon_cmd_t simplebundle_term_cmds[] = {
        #include "bundle_cmds.h"
		{ NULL, NULL, }, };

bundle_interface_t* init_bundle(void) {
	simplebundle_interface.mon_cmds = simplebundle_term_cmds;
	simplebundle_interface.bundle_cleanup = &simplebundle_cleanup;
	simplebundle_interface.bundle_enable = &simplebundle_enable;
	simplebundle_interface.bundle_disable = &simplebundle_disable;
	//initialize the plugin
	fprintf(stderr, "simplebundle init end.\n");
	return (&simplebundle_interface);
}

