/*
 * Kernel32Hooker.h
 *
 *  Created on: 2014-6-14
 *      Author: wb
 */

#ifndef KERNEL32HOOKER_H_
#define KERNEL32HOOKER_H_
#include <limits.h>
#include <stdint.h>
#include <dbaf/Plugin.h>
#include <dbaf/plugins/CorePlugin.h>
#include <dbaf/plugins/HookManager.h>
#include <dbaf/plugins/OSMonitor.h>
#include <dbaf/signals/signals.h>

namespace dbaf {
class DBAFExecutionState;

namespace plugins {

class Kernel32Hooker  : public Plugin {
	DBAF_PLUGIN

private:

public:
	typedef void (dbaf::plugins::Kernel32Hooker::*CallBack)(DBAFExecutionState* state, HookManagerState *fns);
	typedef const WindowsApiHooker<CallBack> WindowsApiHookArray;
	void slotProcessCreate(DBAFExecutionState* state, process* proc);
	void slotModuleLoad(DBAFExecutionState* state, process* proc, module* mod);
public:
	Kernel32Hooker(DBAF* dbaf): Plugin(dbaf) {
		m_Monitor = NULL;
		m_hookManager = NULL;
    }
	virtual ~Kernel32Hooker();
	void initialize();

	OSMonitor* m_Monitor;
	HookManager* m_hookManager;

	static WindowsApiHookArray s_hooks[];
	DECLARE_HOOK_POINT(CreateFileA,uint32_t lpFileName, uint32_t dwCreationDisposition,  uint32_t dwFlagsAndAttributes);
    DECLARE_HOOK_POINT(GetCommandLineA);

};

class Kernel32HookerState: public PluginState
{

public:
    Kernel32HookerState() {
    }
    ~Kernel32HookerState() {}
    static PluginState *factory(Plugin*, DBAFExecutionState*) {
        return new Kernel32HookerState();
    }
    Kernel32HookerState *clone() const {
        return new Kernel32HookerState(*this);
    }
};
} /* namespace plugins */
} /* namespace dbaf */
#endif /* KERNEL32HOOKER_H_ */
