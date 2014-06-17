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
#include <iomanip>
#include <bitset>
#include <stdlib.h>
#include <dbaf/utils/disasplus.h>
using namespace std;
namespace dbaf {

DBAF_DEFINE_PLUGIN(SimpleBundlePlugin, "DBAF SimpleBundlePlugin functionality", "SimpleBundlePlugin",);

SimpleBundlePlugin::~SimpleBundlePlugin() {
}

void SimpleBundlePlugin::initialize() {
	dbaf()->getDebugStream()<< "SimpleBundlePlugin::initialize" << endl;
//	dbaf()->getCorePlugin()->onTranslateInstructionStart.connect(fsigc::mem_fun(*this, &SimpleBundlePlugin::slotTranslateInstructionStart));
//	dbaf()->getCorePlugin()->onTranslateInstructionEnd.connect(fsigc::mem_fun(*this, &SimpleBundlePlugin::slotTranslateInstructionEnd));
//	dbaf()->getCorePlugin()->onMemoryAccess.connect(fsigc::mem_fun(*this, &SimpleBundlePlugin::onMemoryAccess));
	dbaf()->getCorePlugin()->onTranslateRegisterAccessEnd.connect(fsigc::mem_fun(*this, &SimpleBundlePlugin::slotTranslateRegisterAccessEnd));
}
void SimpleBundlePlugin::slotTranslateRegisterAccessEnd(ExecutionSignal *signal,
		DBAFExecutionState *state, TranslationBlock *tb, uint64_t pc,
		uint64_t rmask, uint64_t wmask, bool ismemoryaccess){
	//dbaf()->getDebugStream()<< "TranslateRegisterAccessEnd pc=" << std::hex << pc << " rmask=" << bitset<32>(rmask)<< " wmask=" << bitset<32>(wmask)<< endl;
	if ((wmask & (1 << R_ESP))) {
		bool isCall = false;
		if (tb->dbaf_tb_type == TB_CALL || tb->dbaf_tb_type == TB_CALL_IND) {
			isCall = true;
		}
		signal->connect(
				fsigc::bind(
						fsigc::mem_fun(*this,
								&SimpleBundlePlugin::onRegisterAccess),
						isCall));
	}

}
/*
 * 在指令执行后，相关的寄存器读写已完成，才会调用这个会调
 */
 void SimpleBundlePlugin::onRegisterAccess(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc, bool isCall){

	 dbaf()->getDebugStream()<< "ESP RegisterAccess pc=" << std::hex << pc <<" nextpc=" << nextpc << endl;
	 target_disas_to_ofstream(&(dbaf()->getDebugStream()), state->getCPUArchState(), pc);
 }

void SimpleBundlePlugin::onMemoryAccess(DBAFExecutionState* state, uint64_t vaddr,
			uint64_t haddr, uint8_t* buf, unsigned size, int flagmask, MemoryAccessType atype){
	dbaf()->getDebugStream()<< "addr:" << setw(16) << hexval(vaddr) << " \thaddr:"<< setw(16) << hexval(haddr) << " \tisWrite:" << (flagmask & 1) << "\tisIO"<<((flagmask >> 1) & 1) << "\taccesstype:" << StringMemoryAccessType(atype)<< endl;
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
//	if(isEnabled())
//	{
		dbaf()->getDebugStream()<< "TranslateInstructionEnd pc=" << std::hex << pc << endl;
		signal->connect(fsigc::mem_fun(*this,&SimpleBundlePlugin::onInstructionExecutionAfter));
//	}
}
void SimpleBundlePlugin::onInstructionExecutionBefore(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc){
	dbaf()->getDebugStream()<< "ExecuteInstruction Before pc=" << std::hex << pc <<" nextpc=" << nextpc << endl;
}
void SimpleBundlePlugin::onInstructionExecutionAfter(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc){
	dbaf()->getDebugStream()<< "ExecuteInstruction After pc=" << std::hex << pc <<" nextpc=" << nextpc << endl;
}

} /* namespace dbaf */
