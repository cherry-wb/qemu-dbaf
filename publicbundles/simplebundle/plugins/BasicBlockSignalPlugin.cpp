/*
 * BasicBlockSignalPlugin.cpp
 *
 *  Created on: 2014-5-25
 *      Author: wb
 */

#include "BasicBlockSignalPlugin.h"
#include <dbaf/plugins/CorePlugin.h>
#include <dbaf/DBAF.h>
#include <dbaf/DBAF_qemu.h>
#include <dbaf/DBAFExecutionState.h>
#include <dbaf/DBAFSJLJ.h>
#include <vector>
#include <inttypes.h>

using namespace std;

namespace dbaf {

DBAF_DEFINE_PLUGIN(BasicBlockSignalPlugin, "DBAF BasicBlockSignalPlugin functionality", "BasicBlockSignalPlugin",);

BasicBlockSignalPlugin::~BasicBlockSignalPlugin() {
}

void BasicBlockSignalPlugin::initialize() {
	dbaf()->getDebugStream()<< "BasicBlockSignalPlugin::initialize" << endl;
	dbaf()->getCorePlugin()->onTranslateBlockStart.connect(fsigc::mem_fun(*this, &BasicBlockSignalPlugin::slotTranslateBlockStart));
	dbaf()->getCorePlugin()->onTranslateBlockEnd.connect(fsigc::mem_fun(*this, &BasicBlockSignalPlugin::slotTranslateBlockEnd));
}
void BasicBlockSignalPlugin::slotTranslateBlockStart(ExecutionSignal *signal,
                                                   DBAFExecutionState *state,
                                                   TranslationBlock *tb,
                                                   uint64_t pc){
//	if(isEnabled())
//	{
		dbaf()->getDebugStream()<< "TranslateBlockStart pc=" << std::hex << pc << endl;
		signal->connect(fsigc::mem_fun(*this,&BasicBlockSignalPlugin::onBlockStartExecution));
//	}
}
void BasicBlockSignalPlugin::slotTranslateBlockEnd(ExecutionSignal *signal,
                                                   DBAFExecutionState *state,
                                                   TranslationBlock *tb,
                                                   uint64_t pc, bool is_static_target, uint64_t static_target_pc){
	if(isEnabled())
	{
		dbaf()->getDebugStream()<< "TranslateBlockEnd pc=" << std::hex << pc << endl;
		signal->connect(fsigc::mem_fun(*this,&BasicBlockSignalPlugin::onBlockEndExecution));
	}
}
void BasicBlockSignalPlugin::onBlockStartExecution(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc){
	dbaf()->getDebugStream()<< "onBlockStartExecution pc=" << std::hex << pc <<" nextpc=" << nextpc << endl;
}
void BasicBlockSignalPlugin::onBlockEndExecution(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc){
	dbaf()->getDebugStream()<< "onBlockEndExecution pc=" << std::hex << pc <<" nextpc=" << nextpc << endl;
}

} /* namespace dbaf */
