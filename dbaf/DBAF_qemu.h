/*
 * DBAF_qemu.h
 *
 *  Created on: 2014-5-16
 *      Author: wb
 */

#ifndef DBAF_QEMU_H_
#define DBAF_QEMU_H_
#include "DBAF_qemu_mini.h"
#ifdef __cplusplus
namespace dbaf {
    struct DBAFTBExtra;
}
using dbaf::DBAFTBExtra;
#else
struct DBAFTBExtra;
#endif
struct CPUX86State;
struct TranslationBlock;
#ifndef TCGv
struct TCGv;
struct TCGv_ptr;
#endif

#ifdef __cplusplus
extern "C" {
#endif

void dbaf_on_translate_block_start(CPUArchState* env,TCGv_ptr cpn_env,
		struct DBAF* dbaf,struct DBAFExecutionState* state,
		struct TranslationBlock *tb, uint64_t pc, TCGv nextpc);
void dbaf_on_translate_block_end(CPUArchState* env,TCGv_ptr cpn_env,
		struct DBAF* dbaf, struct DBAFExecutionState *state,
		struct TranslationBlock *tb,
        uint64_t insPc, int staticTarget, uint64_t targetPc, TCGv nextpc);
void dbaf_on_translate_instruction_start(CPUArchState* env,TCGv_ptr cpn_env,
		struct  DBAF* dbaf, struct DBAFExecutionState* state,
		struct TranslationBlock *tb, uint64_t pc, TCGv nextpc);
void dbaf_on_translate_instruction_end(CPUArchState* env,TCGv_ptr cpn_env,
		struct DBAF* dbaf, struct DBAFExecutionState* state,
		struct TranslationBlock *tb, uint64_t pc, TCGv nextpc);
void dbaf_on_translate_jump_start(CPUArchState* env,TCGv_ptr cpn_env,
		struct DBAF* dbaf,struct DBAFExecutionState* state,
		struct TranslationBlock *tb, uint64_t pc, int jump_type, TCGv nextpc);
void dbaf_on_translate_register_access(CPUArchState* env,TCGv_ptr cpn_env,
		struct TranslationBlock *tb, uint64_t pc,
		uint64_t readMask, uint64_t writeMask, int isMemoryAccess, TCGv nextpc);
//void dbaf_trace_memory_access(CPUArchState* env,uint64_t vaddr, uint64_t haddr, uint8_t* buf, unsigned size,
//        int isWrite, int isIO);
void dbaf_on_exception(CPUArchState* env,unsigned intNb);
void dbaf_on_initialization_complete(void);
//void dbaf_on_page_fault(CPUArchState* env,struct DBAF *dbaf, struct DBAFExecutionState* state, uint64_t addr, int is_write);
//void dbaf_on_tlb_miss(CPUArchState* env,struct DBAF *dbaf, struct DBAFExecutionState* state, uint64_t addr, int is_write);
//void dbaf_on_privilege_change(CPUArchState* env,unsigned previous, unsigned current);
//void dbaf_on_page_directory_change(CPUArchState* env,uint64_t previous, uint64_t current);

void dbaf_tb_alloc(struct TranslationBlock *tb);
void dbaf_tb_free(struct TranslationBlock *tb);

#ifdef __cplusplus
}
#endif

#endif /* DBAF_QEMU_H_ */
