{
.name       = "load_bundle",
.args_type  = "filename:F",
.params     = "filename",
.help       = "Load a DBAF bundle",
.mhandler.cmd_new = do_load_bundle,
},


{
.name       = "unload_bundle",
.args_type  = "fpath:F",
.params     = "fpath",
.help       = "Unload the fpath DBAF bundle",
.mhandler.cmd_new = do_unload_bundle,
},
{
.name       = "enable_bundle",
.args_type  = "fpath:F",
.params     = "fpath",
.help       = "Enable the fpath DBAF bundle",
.mhandler.cmd_new = do_enable_bundle,
},


{
.name       = "disable_bundle",
.args_type  = "fpath:F",
.params     = "fpath",
.help       = "Disable the fpath DBAF bundle",
.mhandler.cmd_new = do_disable_bundle,
},

/* operating system information */
{
	.name		= "guest_ps",
	.args_type	= "",
	.mhandler.cmd = do_guest_ps,
	.params		= "",
	.help		= "list the processes on guest system"
},
{
	.name		= "guest_modules",
	.args_type	= "pid:i",
	.mhandler.cmd	= do_guest_modules,
	.params		= "pid",
	.help		= "list the modules of the process with <pid>"
},

{
	.name		= "guest_module_functions",
	.args_type	= "module:S",
	.mhandler.cmd	= do_module_functions,
	.params		= "module",
	.help		= "list the functions of the module"
},

//#ifdef CONFIG_TCG_SYM
///* TCG tainting commands */
//{
//        .name       = "enable_tainting",
//        .args_type  = "",
//        .params     = "",
//        .help       = "Turn on taint tracking",
//        .mhandler.cmd_new = do_enable_tainting,
//},
//{
//        .name       = "disable_tainting",
//        .args_type  = "",
//        .params     = "",
//        .help       = "Turn off taint tracking",
//        .mhandler.cmd_new = do_disable_tainting,
//},
//{
//        .name       = "taint_nic_on",
//        .args_type  = "",
//        .params     = "",
//        .help       = "Turn on tainting of all data coming from the NE2000 NIC",
//        .mhandler.cmd_new = do_taint_nic_on,
//},
//{
//        .name       = "taint_nic_off",
//        .args_type  = "",
//        .params     = "",
//        .help       = "Turn off tainting of all data coming from the NE2000 NIC",
//        .mhandler.cmd_new = do_taint_nic_off,
//},
//{
//        .name       = "taint_mem_usage",
//        .args_type  = "",
//        .params     = "",
//        .help       = "Print usage stats pertaining to tracking tainted memory",
//        .mhandler.cmd_new = do_taint_mem_usage,
//},
//{
//	.name       = "tainted_bytes",
//	.args_type  = "",
//	.params     = "",
//	.help       = "Print the No. of tainted memory bytes",
//	.mhandler.cmd_new = do_tainted_bytes,
//},
//{
//        .name       = "taint_garbage_collect",
//        .args_type  = "",
//        .params     = "",
//        .help       = "Manually garbage collect any unused taint-tracking memory",
//        .mhandler.cmd_new = do_garbage_collect_taint,
//},
//{
//        .name       = "taint_pointers",
//        .args_type  = "load:b,store:b",
//        .params     = "on|off on|off",
//        .help       = "Turn on/off tainting of pointers (load) (store)",
//        .mhandler.cmd_new = do_taint_pointers,
//},
//#endif /* CONFIG_TCG_SYM */

