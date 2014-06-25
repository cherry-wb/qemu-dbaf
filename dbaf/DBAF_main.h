#ifndef DBAF_MAIN_H_
#define DBAF_MAIN_H_

#include "qemu-common.h"
#include "exec/cpu-all.h"
#include "monitor/monitor.h"
#include "sysemu/blockdev.h"
#include "DBAF_common.h"
#ifdef __cplusplus
extern "C"
{
#endif

/*************************************************************************
 * The Plugin interface
 *************************************************************************/
typedef struct _bundle_interface {
  /// array of monitor commands
  mon_cmd_t *mon_cmds; // AWH - was term_cmd_t *term_cmds
  /*!
   * \brief callback for cleaning up states in plugin.
   */
  void (*bundle_cleanup)(void);
  //设置使能状态
  void (*bundle_enable)(void);
  //设置停用状态
  void (*bundle_disable)(void);
  /// \brief CR3 of a specified process to be monitored.
  /// 0 means system-wide monitoring, including all processes and kernel.
  union
  {
    uint32_t monitored_cr3;
    uint32_t monitored_pgd; //alias
  };
} bundle_interface_t;

typedef struct BundleInfo {
	void *handle;
	bundle_interface_t *bundle;
	char bundle_path[PATH_MAX];
} BundleInfo;

extern struct BundleInfo dbaf_bundles[];
extern int dbaf_bundles_size;

extern mon_cmd_t DBAF_mon_cmds[];
extern mon_cmd_t DBAF_info_cmds[];

extern void do_load_bundle_internal(Monitor *mon, const char *plugin_path);
extern int do_load_bundle(Monitor *mon, const QDict *qdict, QObject **ret_data);
extern int do_unload_bundle(Monitor *mon, const QDict *qdict, QObject **ret_data);
extern int do_enable_bundle(Monitor *mon, const QDict *qdict, QObject **ret_data);
extern int do_disable_bundle(Monitor *mon, const QDict *qdict, QObject **ret_data);

void do_guest_ps(Monitor *mon, const QDict *qdict);
void do_guest_modules(Monitor *mon, const QDict *qdict);
void do_module_functions(Monitor *mon, const QDict *qdict);
void do_select_process(Monitor *mon, const QDict *qdict);

extern void do_guest_ps_internal(Monitor *mon, const QDict *qdict);
extern void do_guest_modules_internal(Monitor *mon, const QDict *qdict);
extern void do_module_functions_internal(Monitor *mon, const char *module);
extern void do_select_process_internal(Monitor *mon, const QDict *qdict);

void do_enable_llvm(Monitor *mon, const QDict *qdict);
void do_disable_llvm(Monitor *mon, const QDict *qdict);
void do_enable_llvm_helpers(Monitor *mon, const QDict *qdict);
void do_disable_llvm_helpers(Monitor *mon, const QDict *qdict);
void do_enable_llvm_all(Monitor *mon, const QDict *qdict);
void do_disable_llvm_all(Monitor *mon, const QDict *qdict);

void do_flush_tb(void);
void do_enable_llvm_internal(void);
void do_disable_llvm_internal(void);
void do_enable_llvm_helpers_internal(void);
void do_disable_llvm_helpers_internal(void);
#ifdef __cplusplus
}
#endif

#endif /* DBAF_MAIN_H_ */
