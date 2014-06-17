/*
 * SimpleBundlePlugin.h
 *
 *  Created on: 2014-5-25
 *      Author: wb
 */

#ifndef SIMPLE_BUNDLEPLUGIN_H_
#define SIMPLE_BUNDLEPLUGIN_H_
#include <limits.h>
#include <stdint.h>
#include <dbaf/Plugin.h>
#include <dbaf/plugins/CorePlugin.h>
#include <dbaf/signals/signals.h>
namespace dbaf {
class DBAFExecutionState;
class SimpleBundlePlugin  : public Plugin {
	DBAF_PLUGIN

	private:
public:
	SimpleBundlePlugin(DBAF* dbaf): Plugin(dbaf) {
    }
	virtual ~SimpleBundlePlugin();
	 void initialize();
	 void slotTranslateInstructionStart(ExecutionSignal *signal,
	                                                    DBAFExecutionState *state,
	                                                    TranslationBlock *tb,
	                                                    uint64_t pc);
	 void slotTranslateInstructionEnd(ExecutionSignal *signal,
	                                                    DBAFExecutionState *state,
	                                                    TranslationBlock *tb,
	                                                    uint64_t pc);

	void slotTranslateRegisterAccessEnd(ExecutionSignal *signal,
			DBAFExecutionState *state, TranslationBlock *tb, uint64_t pc,
			uint64_t rmask, uint64_t wmask, bool ismemoryaccess);
	/*
	 * 在指令执行后，相关的寄存器读写已完成，才会调用这个会调
	 */
	 void onRegisterAccess(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc, bool isCall);

	 void onInstructionExecutionBefore(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc);
	 void onInstructionExecutionAfter(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc);
	 void onMemoryAccess(DBAFExecutionState* state, uint64_t vaddr,
			uint64_t haddr, uint8_t* buf, unsigned size, int flagmask,
			MemoryAccessType atype);

};

class SimpleBundlePluginState: public PluginState
{

public:
    SimpleBundlePluginState() {
    }
    ~SimpleBundlePluginState() {}
    static PluginState *factory(Plugin*, DBAFExecutionState*) {
        return new SimpleBundlePluginState();
    }
    SimpleBundlePluginState *clone() const {
        return new SimpleBundlePluginState(*this);
    }
};
} /* namespace dbaf */
#endif /* SIMPLE_BUNDLEPLUGIN_H_ */
