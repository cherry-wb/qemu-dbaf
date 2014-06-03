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
	 void onInstructionExecutionBefore(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc);
	 void onInstructionExecutionAfter(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc);

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
