/*
const char *name;
const char *args_type;
const char *params;
const char *help;
void (*user_print)(Monitor *mon, const QObject *data);
union {
	void (*cmd)(Monitor *mon, const QDict *qdict);
	int  (*cmd_new)(Monitor *mon, const QDict *params, QObject **ret_data);
	int  (*cmd_async)(Monitor *mon, const QDict *params,
					  MonitorCompletion *cb, void *opaque);
} mhandler;
int flags;
struct mon_cmd_t *sub_table;
*/
{
	.name		= "simplebundle_cmd",
	.args_type	= "cmd:s",
	.mhandler.cmd	= do_simplebundle_cmd,
	.params		= "cmd need to be executed",
	.help		= "do simplebundle_cmd"
},
