/*
 * SignalTesterPlugin.h
 *
 *  Created on: 2014-5-25
 *      Author: wb
 */

#ifndef SIGNALTESTERPLUGIN_H_
#define SIGNALTESTERPLUGIN_H_
#include <dbaf/Plugin.h>
#include <dbaf/plugins/CorePlugin.h>
#include <dbaf/signals/signals.h>
namespace dbaf {
class DBAFExecutionState;
class SignalTesterPlugin  : public Plugin {
	DBAF_PLUGIN

	private:
public:
	SignalTesterPlugin(DBAF* dbaf): Plugin(dbaf) {
    }
	virtual ~SignalTesterPlugin();
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

class SignalTesterPluginState: public PluginState
{

public:
    SignalTesterPluginState() {
    }
    ~SignalTesterPluginState() {}
    static PluginState *factory(Plugin*, DBAFExecutionState*) {
        return new SignalTesterPluginState();
    }
    SignalTesterPluginState *clone() const {
        return new SignalTesterPluginState(*this);
    }
};
} /* namespace dbaf */
#endif /* SIGNALTESTERPLUGIN_H_ */
