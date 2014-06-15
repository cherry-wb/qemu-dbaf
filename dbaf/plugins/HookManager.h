#ifndef DBAF_PLUGINS_HOOKMANAGER_H
#define DBAF_PLUGINS_HOOKMANAGER_H

#include <tr1/unordered_map>
#include <dbaf/Plugin.h>
#include <dbaf/plugins/CorePlugin.h>
#include <dbaf/DBAFExecutionState.h>
#include <dbaf/plugins/OSMonitor.h>

#ifdef TARGET_ARM
#include "ArmHookManager.h"
#elif defined (TARGET_I386)
#include <dbaf/plugins/X86HookManager.h>
#endif


namespace dbaf {
namespace plugins {

/**
 * Note: the HookManager is target dependent, so the actual class
 * is a compile-time alias to the arch-specific version.
 */

#ifdef TARGET_ARM
typedef ARMHookManager HookManager;
typedef ARMHookManagerState HookManagerState;
#elif defined (TARGET_I386)
typedef X86HookManager HookManager;
typedef X86HookManagerState HookManagerState;
#endif

#define DECLARE_HOOK_POINT(name, ...) \
    void name(DBAFExecutionState* state, HookManagerState *fns); \
    void name##Ret(DBAFExecutionState* state, ##__VA_ARGS__)

#define DECLARE_HOOK_POINT_CALL(name, ...) \
    void name(DBAFExecutionState* state, HookManagerState *fns, __VA_ARGS__)

#define DECLARE_HOOK_POINT_RET(name, ...) \
    void name##Ret(DBAFExecutionState* state, ##__VA_ARGS__)

#define DECLARE_HOOKER_STRUC(cl, m, f) {#m, #f, (CallBack)&cl::f }

template <typename F>
struct WindowsApiHooker {
	const char *modname;
    const char *funcname;
    F function;
};

}
}

#endif // DBAF_PLUGINS_HOOKMANAGER_H
