/*
 * DBAF_qemu_mini.h
 *
 *  Created on: 2014-5-16
 *      Author: wb
 */

#ifndef DBAF_QEMU_MINI_H_
#define DBAF_QEMU_MINI_H_
#ifdef __cplusplus
namespace dbaf {
    class DBAF;
    class DBAFExecutionState;
}
using dbaf::DBAF;
using dbaf::DBAFExecutionState;
#else
struct DBAF;
struct DBAFExecutionState;
#endif

#ifdef __cplusplus
extern "C" {
#endif
/* This should never be accessed from C++ code */
/* Functions from DBAF.cpp */
extern struct DBAF* g_dbaf;
extern struct DBAFExecutionState* g_dbaf_state;
extern int g_dbaf_enable_signals;
extern uint64_t g_selected_cr3;
/** Initialize DBAF instance. Called by main() */
struct DBAF* DBAF_initialize(int argc, char** argv,const char *s2e_config_file);
struct DBAFExecutionState* DBAF_state_initialize(void);
/** Relese DBAF instance and all DBAF-related objects. Called by main() */
void DBAF_close(struct DBAF* dbaf);

#ifdef __cplusplus
}
#endif

#endif /* DBAF_QEMU_MINI_H_ */
