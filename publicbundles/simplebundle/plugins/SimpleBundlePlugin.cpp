/*
 * SimpleBundlePlugin.cpp
 *
 *  Created on: 2014-5-25
 *      Author: wb
 */

#include "SimpleBundlePlugin.h"
#include <dbaf/plugins/CorePlugin.h>
#include <dbaf/DBAF.h>
#include <dbaf/DBAF_qemu.h>
#include <dbaf/DBAFExecutionState.h>
#include <dbaf/DBAFSJLJ.h>
#include <vector>
#include <inttypes.h>

using namespace std;

namespace dbaf {

DBAF_DEFINE_PLUGIN(SimpleBundlePlugin, "DBAF SimpleBundlePlugin functionality", "SimpleBundlePlugin",);

SimpleBundlePlugin::~SimpleBundlePlugin() {
}

void SimpleBundlePlugin::initialize() {
	dbaf()->getDebugStream()<< "SimpleBundlePlugin::initialize" << endl;
	dbaf()->getCorePlugin()->onTranslateInstructionStart.connect(fsigc::mem_fun(*this, &SimpleBundlePlugin::slotTranslateInstructionStart));
	dbaf()->getCorePlugin()->onTranslateInstructionEnd.connect(fsigc::mem_fun(*this, &SimpleBundlePlugin::slotTranslateInstructionEnd));
}
void SimpleBundlePlugin::slotTranslateInstructionStart(ExecutionSignal *signal,
                                                   DBAFExecutionState *state,
                                                   TranslationBlock *tb,
                                                   uint64_t pc)
{
	if(isEnabled())
	{
		dbaf()->getDebugStream()<< "TranslateInstructionStart pc=" << std::hex << pc << endl;
		signal->connect(fsigc::mem_fun(*this,&SimpleBundlePlugin::onInstructionExecutionBefore));
	}
}
void SimpleBundlePlugin::slotTranslateInstructionEnd(ExecutionSignal *signal,
                                                   DBAFExecutionState *state,
                                                   TranslationBlock *tb,
                                                   uint64_t pc)
{
	if(isEnabled())
	{
		dbaf()->getDebugStream()<< "TranslateInstructionEnd pc=" << std::hex << pc << endl;
		signal->connect(fsigc::mem_fun(*this,&SimpleBundlePlugin::onInstructionExecutionAfter));
	}
}
void SimpleBundlePlugin::onInstructionExecutionBefore(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc){
	dbaf()->getDebugStream()<< "ExecuteInstruction Before pc=" << std::hex << pc <<" nextpc=" << nextpc << endl;
}
void SimpleBundlePlugin::onInstructionExecutionAfter(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc){
	dbaf()->getDebugStream()<< "ExecuteInstruction After pc=" << std::hex << pc <<" nextpc=" << nextpc << endl;
}

} /* namespace dbaf */
