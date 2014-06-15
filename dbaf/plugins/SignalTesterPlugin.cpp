/*
 * SignalTesterPlugin.cpp
 *
 *  Created on: 2014-5-25
 *      Author: wb
 */

#include "SignalTesterPlugin.h"
#include "CorePlugin.h"
#include <dbaf/DBAF.h>
#include <dbaf/DBAF_qemu.h>
#include <dbaf/DBAFExecutionState.h>
#include <dbaf/DBAFSJLJ.h>


using namespace std;

namespace dbaf {

DBAF_DEFINE_PLUGIN(SignalTesterPlugin, "DBAF SignalTesterPlugin functionality", "SignalTesterPlugin",);

SignalTesterPlugin::~SignalTesterPlugin() {
}

void SignalTesterPlugin::initialize() {
	dbaf()->getCorePlugin()->onTranslateInstructionStart.connect(fsigc::mem_fun(*this, &SignalTesterPlugin::slotTranslateInstructionStart));
	dbaf()->getCorePlugin()->onTranslateInstructionEnd.connect(fsigc::mem_fun(*this, &SignalTesterPlugin::slotTranslateInstructionEnd));
}
void SignalTesterPlugin::slotTranslateInstructionStart(ExecutionSignal *signal,
                                                   DBAFExecutionState *state,
                                                   TranslationBlock *tb,
                                                   uint64_t pc)
{
	if(isEnabled()){
		dbaf()->getDebugStream()<< "TranslateInstructionStart pc=" << std::hex << pc << endl;
		signal->connect(fsigc::mem_fun(*this,&SignalTesterPlugin::onInstructionExecutionBefore));
	}
}
void SignalTesterPlugin::slotTranslateInstructionEnd(ExecutionSignal *signal,
                                                   DBAFExecutionState *state,
                                                   TranslationBlock *tb,
                                                   uint64_t pc) {
	if (isEnabled()) {
		dbaf()->getDebugStream() << "TranslateInstructionEnd pc=" << std::hex
				<< pc << endl;
		signal->connect(
				fsigc::mem_fun(*this,
						&SignalTesterPlugin::onInstructionExecutionAfter));
	}
}
void SignalTesterPlugin::onInstructionExecutionBefore(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc){
	dbaf()->getDebugStream()<< "ExecuteInstruction Before pc=" << std::hex << pc <<" nextpc=" << nextpc << endl;
}
void SignalTesterPlugin::onInstructionExecutionAfter(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc){
	dbaf()->getDebugStream()<< "ExecuteInstruction After pc=" << std::hex << pc <<" nextpc=" << nextpc << endl;
}

} /* namespace dbaf */
