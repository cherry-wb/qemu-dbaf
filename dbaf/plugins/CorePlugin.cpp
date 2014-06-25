extern "C" {
#include "config.h"
#include "tcg-op.h"
#include "cpu.h"
#include "qemu-common.h"
#include "exec/helper-head.h"
}

#include "CorePlugin.h"
#include <dbaf/DBAF.h>
#include <dbaf/DBAF_qemu.h>
#include <dbaf/DBAFExecutionState.h>
#include <dbaf/DBAFSJLJ.h>


using namespace std;

namespace dbaf {
    DBAF_DEFINE_PLUGIN(CorePlugin, "DBAF core functionality", "Core",);
} // namespace dbaf
using namespace dbaf;
extern "C" void helper_dbaf_tcg_execution_handler(CPUArchState* env, void*  signal, target_ulong pc, target_ulong nextpc);
bool trace_memory_access_code = false;
bool trace_memory_access_data = false;
bool trace_memory_access_kernel = false;
bool trace_memory_access_user = false;
bool trace_memory_access_ksmap = false;
bool trace_memory_access_mmu = false;
bool trace_memory_access_cmmu = false;
bool trace_memory_read = false;
bool trace_memory_write = false;
void CorePlugin::initialize()
{
	dbaf()->getDebugStream()<< "execution_handler at " << (void*) helper_dbaf_tcg_execution_handler <<"\n";
	trace_memory_access_code = dbaf()->getConfig()->getBool(getConfigKey() + ".trace_memory_access_code", false);
	trace_memory_access_data = dbaf()->getConfig()->getBool(getConfigKey() + ".trace_memory_access_data", false);
	trace_memory_access_kernel = dbaf()->getConfig()->getBool(getConfigKey() + ".trace_memory_access_kernel", false);
	trace_memory_access_user = dbaf()->getConfig()->getBool(getConfigKey() + ".trace_memory_access_user", false);
	trace_memory_access_ksmap = dbaf()->getConfig()->getBool(getConfigKey() + ".trace_memory_access_ksmap", false);
	trace_memory_access_mmu = dbaf()->getConfig()->getBool(getConfigKey() + ".trace_memory_access_mmu", false);
	trace_memory_access_cmmu = dbaf()->getConfig()->getBool(getConfigKey() + ".trace_memory_access_cmmu", false);
	trace_memory_read = dbaf()->getConfig()->getBool(getConfigKey() + ".trace_memory_read", false);
	trace_memory_write = dbaf()->getConfig()->getBool(getConfigKey() + ".trace_memory_write", false);
	update_current_pc = dbaf()->getConfig()->getBool(getConfigKey() + ".update_current_pc", false);
}

/******************************/
/* Functions called from QEMU */
int g_dbaf_enable_signals = true;
/*
static inline void gen_helper_dbaf_tcg_execution_handler(TCGv_ptr argenv,TCGv_ptr argsignal,TCGv argpc,TCGv argnextpc){
	  TCGArg args[4];
      args[1 - 1] = GET_TCGV_PTR(argenv);
      args[2 - 1] = GET_TCGV_PTR(argsignal);
#if TARGET_LONG_BITS == 32
	  args[3-1] = GET_TCGV_I32(argpc);
#else
	  args[3-1] = GET_TCGV_I64(argpc);
#endif

#if TARGET_LONG_BITS == 32
	  args[4-1] = GET_TCGV_I32(argnextpc);
#else
	  args[4-1] = GET_TCGV_I64(argnextpc);
#endif

	  tcg_gen_callN(&tcg_ctx,(void*)helper_dbaf_tcg_execution_handler, TCG_CALL_DUMMY_ARG, 4, args);
}
*/

/* Instrument generated code to emit signal on execution */
/* Next pc, when != -1, indicates with which value to update the program counter
   before calling the annotation. This is useful when instrumenting instructions
   that do not explicitely update the program counter by themselves. */
static void dbaf_tcg_instrument_code(TCGv_ptr cpn_env, ExecutionSignal* signal, target_ulong pc, TCGv nextpc)
{
	tcg_gen_dbaf_start(pc);
    TCGv tpc = tcg_temp_new();
    TCGv_ptr tsignal = tcg_const_ptr((tcg_target_ulong)signal);
    tcg_gen_movi_tl(tpc, pc);
	gen_helper_dbaf_tcg_execution_handler(cpn_env, tsignal, tpc, nextpc);
    tcg_temp_free(tpc);
    tcg_temp_free_ptr(tsignal);
    tcg_gen_dbaf_end(pc);
}



static void dbaf_on_exception_slow(CPUArchState* env,unsigned intNb)
{
	CPUState *cs = ENV_GET_CPU(env);

    try {
        g_dbaf->getCorePlugin()->onException.emit(g_dbaf_state, intNb, env->eip);
    } catch(dbaf::CpuExitException&) {
        siglongjmp(cs->jmp_env, 1);
    }
}



extern "C" {

void dbaf_on_exception(CPUArchState* env,unsigned intNb)
{
    if(unlikely(!g_dbaf->getCorePlugin()->onException.empty())) {
        dbaf_on_exception_slow(env,intNb);
    }
}
void dbaf_on_translate_block_start(CPUArchState* env,TCGv_ptr cpn_env,
        DBAF* dbaf, DBAFExecutionState* state,
        TranslationBlock *tb, uint64_t pc, TCGv nextpc)
{
	CPUState *cs = ENV_GET_CPU(env);
    ExecutionSignal *signal = static_cast<ExecutionSignal*>(
                                    tb->dbaf_extra->executionSignals.back());
    assert(signal->empty());

    try {
        dbaf->getCorePlugin()->onTranslateBlockStart.emit(signal, state, tb, pc);
        if(!signal->empty()) {
            dbaf_tcg_instrument_code(cpn_env, signal, pc, nextpc);
            tb->dbaf_extra->executionSignals.push_back(new ExecutionSignal);
        }
    } catch(dbaf::CpuExitException&) {
        siglongjmp(cs->jmp_env, 1);
    }
}

void dbaf_on_translate_block_end(CPUArchState* env,TCGv_ptr cpn_env,
        DBAF* dbaf, DBAFExecutionState *state,
        TranslationBlock *tb,
        uint64_t insPc, int staticTarget, uint64_t targetPc, TCGv nextpc)
{
	CPUState *cs = ENV_GET_CPU(env);
    ExecutionSignal *signal = static_cast<ExecutionSignal*>(
                                    tb->dbaf_extra->executionSignals.back());
    assert(signal->empty());

    try {
        dbaf->getCorePlugin()->onTranslateBlockEnd.emit(
                signal, state, tb, insPc,
                staticTarget, targetPc);
		if(!signal->empty()) {
			dbaf_tcg_instrument_code(cpn_env, signal, insPc, nextpc);
			tb->dbaf_extra->executionSignals.push_back(new ExecutionSignal);
		}
    } catch(dbaf::CpuExitException&) {
        siglongjmp(cs->jmp_env, 1);
    }
}

void dbaf_on_translate_instruction_start(CPUArchState* env,TCGv_ptr cpn_env,
        DBAF* dbaf, DBAFExecutionState* state,
        TranslationBlock *tb, uint64_t pc, TCGv nextpc)
{
	CPUState *cs = ENV_GET_CPU(env);
    ExecutionSignal *signal = static_cast<ExecutionSignal*>(
                                    tb->dbaf_extra->executionSignals.back());
    assert(signal->empty());

    try {
        dbaf->getCorePlugin()->onTranslateInstructionStart.emit(signal, state, tb, pc);
        if(!signal->empty()) {
            dbaf_tcg_instrument_code(cpn_env, signal, pc, nextpc);
            tb->dbaf_extra->executionSignals.push_back(new ExecutionSignal);
        }
    } catch(dbaf::CpuExitException&) {
        siglongjmp(cs->jmp_env, 1);
    }
}

void dbaf_on_translate_jump_start(CPUArchState* env,TCGv_ptr cpn_env,
        DBAF* dbaf, DBAFExecutionState* state,
        TranslationBlock *tb, uint64_t pc, int jump_type, TCGv nextpc)
{
	CPUState *cs = ENV_GET_CPU(env);

    ExecutionSignal *signal = static_cast<ExecutionSignal*>(
                                    tb->dbaf_extra->executionSignals.back());
    assert(signal->empty());

    try {
        dbaf->getCorePlugin()->onTranslateJumpStart.emit(signal, state, tb,
                                                        pc, jump_type);
        if(!signal->empty()) {
            dbaf_tcg_instrument_code(cpn_env, signal, pc, nextpc);
            tb->dbaf_extra->executionSignals.push_back(new ExecutionSignal);
        }
    } catch(dbaf::CpuExitException&) {
        siglongjmp(cs->jmp_env, 1);
    }
}

//Nextpc is the program counter of the of the instruction that
//follows the one at pc, only if it does not change the control flow.
void dbaf_on_translate_instruction_end(CPUArchState* env,TCGv_ptr cpn_env,
        DBAF* dbaf, DBAFExecutionState* state,
        TranslationBlock *tb, uint64_t pc, TCGv nextpc)
{
	CPUState *cs = ENV_GET_CPU(env);

    ExecutionSignal *signal = static_cast<ExecutionSignal*>(
                                    tb->dbaf_extra->executionSignals.back());
    assert(signal->empty());

    try {
        dbaf->getCorePlugin()->onTranslateInstructionEnd.emit(signal, state, tb, pc);
        if(!signal->empty()) {
            dbaf_tcg_instrument_code(cpn_env, signal, pc, nextpc);
            tb->dbaf_extra->executionSignals.push_back(new ExecutionSignal);
        }
    } catch(dbaf::CpuExitException&) {
        siglongjmp(cs->jmp_env, 1);
    }
}

void dbaf_on_translate_register_access(CPUArchState* env,TCGv_ptr cpn_env,
        TranslationBlock *tb, uint64_t pc,
        uint64_t readMask, uint64_t writeMask, int isMemoryAccess, TCGv nextpc)
{
	CPUState *cs = ENV_GET_CPU(env);

    ExecutionSignal *signal = static_cast<ExecutionSignal*>(
                                    tb->dbaf_extra->executionSignals.back());
    assert(signal->empty());

    try {
        g_dbaf->getCorePlugin()->onTranslateRegisterAccessEnd.emit(signal,
                  g_dbaf_state, tb, pc, readMask, writeMask, (bool)isMemoryAccess);

        if(!signal->empty()) {
            dbaf_tcg_instrument_code(cpn_env, signal, pc, nextpc);
            tb->dbaf_extra->executionSignals.push_back(new ExecutionSignal);
        }
    } catch(dbaf::CpuExitException&) {
        siglongjmp(cs->jmp_env, 1);
    }
}
static void dbaf_trace_memory_access_slow(CPUArchState* env,
        uint64_t vaddr, uint64_t haddr, uint8_t* buf, unsigned size,
        int isWrite, int isIO, MemoryAccessType atype)
{
	CPUState *cs = ENV_GET_CPU(env);
    try {
    	int mask = 0;
    	mask |= isWrite;
    	mask |= 1 << 2*isIO;
    	g_dbaf->getCorePlugin()->onMemoryAccess.emit(g_dbaf_state,
            vaddr,haddr, buf,size, mask, atype);
    }  catch(dbaf::CpuExitException&) {
        siglongjmp(cs->jmp_env, 1);
    }
}

/**
 * We split the function in two parts so that the common case when
 * there is no instrumentation is as fast as possible.
 */
void dbaf_trace_memory_access(CPUArchState* env,
        uint64_t vaddr, uint64_t haddr, uint8_t* buf, unsigned size,
        int isWrite, int isIO, MemoryAccessType atype)
{
    if(unlikely(!g_dbaf->getCorePlugin()->onMemoryAccess.empty())
    		&& ((trace_memory_read && ((isWrite & 1) == 0)) || (trace_memory_write && (isWrite & 1)))
#ifdef TARGET_I386
    		&& (g_selected_cr3 !=0 && env->cr[3] == g_selected_cr3)
#endif
    		) {
        dbaf_trace_memory_access_slow(env, vaddr, haddr, buf, size, isWrite, isIO, atype);
    }
}
void dbaf_trace_memory_access_code(CPUArchState* env,uint64_t vaddr, uint64_t haddr, uint8_t* buf, unsigned size,
        int isWrite, int isIO){
	if(trace_memory_access_code)dbaf_trace_memory_access(env, vaddr, haddr, buf, size, isWrite, isIO, AT_CODE);
}
void dbaf_trace_memory_access_data(CPUArchState* env,uint64_t vaddr, uint64_t haddr, uint8_t* buf, unsigned size,
        int isWrite, int isIO){
	if(trace_memory_access_data)dbaf_trace_memory_access(env, vaddr, haddr, buf, size, isWrite, isIO, AT_DATA);
}
void dbaf_trace_memory_access_kernel(CPUArchState* env,uint64_t vaddr, uint64_t haddr, uint8_t* buf, unsigned size,
        int isWrite, int isIO){
	if(trace_memory_access_kernel)dbaf_trace_memory_access(env, vaddr, haddr, buf, size, isWrite, isIO, AT_KERNEL);
}
void dbaf_trace_memory_access_user(CPUArchState* env,uint64_t vaddr, uint64_t haddr, uint8_t* buf, unsigned size,
        int isWrite, int isIO){
	if(trace_memory_access_user)dbaf_trace_memory_access(env, vaddr, haddr, buf, size, isWrite, isIO, AT_USER);
}
void dbaf_trace_memory_access_ksmap(CPUArchState* env,uint64_t vaddr, uint64_t haddr, uint8_t* buf, unsigned size,
        int isWrite, int isIO){
	if(trace_memory_access_ksmap)dbaf_trace_memory_access(env, vaddr, haddr, buf, size, isWrite, isIO, AT_KSMAP);
}
void dbaf_trace_memory_access_mmu(CPUArchState* env,uint64_t vaddr, uint64_t haddr, uint8_t* buf, unsigned size,
        int isWrite, int isIO){
	if(trace_memory_access_mmu)dbaf_trace_memory_access(env, vaddr, haddr, buf, size, isWrite, isIO, AT_MMU);
}
void dbaf_trace_memory_access_cmmu(CPUArchState* env,uint64_t vaddr, uint64_t haddr, uint8_t* buf, unsigned size,
        int isWrite, int isIO){
	if(trace_memory_access_cmmu)dbaf_trace_memory_access(env, vaddr, haddr, buf, size, isWrite, isIO, AT_CMMU);
}

void dbaf_on_page_fault(CPUArchState* env,DBAF *dbaf, DBAFExecutionState* state, uint64_t addr, int is_write)
{
	CPUState *cs = ENV_GET_CPU(env);
    try {
        dbaf->getCorePlugin()->onPageFault.emit(state, addr, (bool)is_write);
    } catch(dbaf::CpuExitException&) {
        siglongjmp(cs->jmp_env, 1);
    }
}

void dbaf_on_tlb_miss(CPUArchState* env,DBAF *dbaf, DBAFExecutionState* state, uint64_t addr, int is_write)
{
	CPUState *cs = ENV_GET_CPU(env);
    try {
        dbaf->getCorePlugin()->onTlbMiss.emit(state, addr, (bool)is_write);
    } catch(dbaf::CpuExitException&) {
        siglongjmp(cs->jmp_env, 1);
    }
}

void dbaf_on_privilege_change(CPUArchState* env,unsigned previous, unsigned current)
{
	CPUState *cs = ENV_GET_CPU(env);

    try {
        g_dbaf->getCorePlugin()->onPrivilegeChange.emit(g_dbaf_state, previous, current);
    } catch(dbaf::CpuExitException&) {
    	siglongjmp(cs->jmp_env, 1);
    }
}

void dbaf_on_page_directory_change(CPUArchState* env,uint64_t previous, uint64_t current)
{
	CPUState *cs = ENV_GET_CPU(env);
    try {
        g_dbaf->getCorePlugin()->onPageDirectoryChange.emit(g_dbaf_state, previous, current);
    } catch(dbaf::CpuExitException&) {
    	siglongjmp(cs->jmp_env, 1);
    }
}

void dbaf_on_initialization_complete(void)
{
    try {
        g_dbaf->getCorePlugin()->onInitializationComplete.emit(g_dbaf_state);
    } catch(dbaf::CpuExitException&) {
        assert(false && "Cannot throw exceptions here. VM state may be inconsistent at this point.");
    }
}

void helper_dbaf_tcg_execution_handler(CPUArchState* env,void*  signal, target_ulong pc, target_ulong nextpc)//
{
	 CPUState *cs = ENV_GET_CPU(env);
    try {
        ExecutionSignal *s = (ExecutionSignal*)signal;
        if (g_dbaf_enable_signals) {
            s->emit(g_dbaf_state, pc, nextpc);
        }
    } catch(dbaf::CpuExitException&) {
    	siglongjmp(cs->jmp_env, 1);
    }
}
void helper_dbaf_tcg_custom_instruction_handler(CPUArchState* env,uint64_t arg)
{
//    assert(!g_dbaf->getCorePlugin()->onCustomInstruction.empty() &&
//           "You must activate a plugin that uses custom instructions.");
    CPUState *cs = ENV_GET_CPU(env);
    try {
        g_dbaf->getCorePlugin()->onCustomInstruction.emit(g_dbaf_state, arg);
    } catch(dbaf::CpuExitException&) {
    	siglongjmp(cs->jmp_env, 1);
    }
}
const char * StringMemoryAccessType(MemoryAccessType type) {
	switch (type) {
	case AT_CODE:
		return "CODE";
	case AT_DATA:
		return "DATA";
	case AT_KERNEL:
		return "KERNEL";
	case AT_USER:
		return "USER";
	case AT_KSMAP:
		return "KSMAP";
	case AT_CMMU:
		return "CMMU";
	case AT_MMU:
		return "MMU";
	default:
		return "Unknown";
	}
}
}

