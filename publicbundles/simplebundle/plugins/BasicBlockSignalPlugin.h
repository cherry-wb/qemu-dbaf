/*
 * BasicBlockSignalPlugin.h
 *
 *  Created on: 2014-5-25
 *      Author: wb
 */

#ifndef B_B_SINGAL_PLUGIN_H_
#define B_B_SINGAL_PLUGIN_H_
#include <limits.h>
#include <stdint.h>
#include <dbaf/Plugin.h>
#include <dbaf/plugins/CorePlugin.h>
#include <dbaf/signals/signals.h>
namespace dbaf {
class DBAFExecutionState;
class BasicBlockSignalPlugin  : public Plugin {
	DBAF_PLUGIN

	private:
public:
	BasicBlockSignalPlugin(DBAF* dbaf): Plugin(dbaf) {
    }
	virtual ~BasicBlockSignalPlugin();
	 void initialize();

	 void slotTranslateBlockStart(ExecutionSignal *signal,
	                                                    DBAFExecutionState *state,
	                                                    TranslationBlock *tb,
	                                                    uint64_t pc);
	 void slotTranslateBlockEnd(ExecutionSignal *signal,
	                                                    DBAFExecutionState *state,
	                                                    TranslationBlock *tb,
	                                                    uint64_t pc, bool is_static_target, uint64_t static_target_pc);
	 void onBlockStartExecution(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc);
	 void onBlockEndExecution(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc);

};

class BasicBlockSignalPluginState: public PluginState
{

public:
    BasicBlockSignalPluginState() {
    }
    ~BasicBlockSignalPluginState() {}
    static PluginState *factory(Plugin*, DBAFExecutionState*) {
        return new BasicBlockSignalPluginState();
    }
    BasicBlockSignalPluginState *clone() const {
        return new BasicBlockSignalPluginState(*this);
    }
};
} /* namespace dbaf */
#endif /* B_B_SINGAL_PLUGIN_H_ */
