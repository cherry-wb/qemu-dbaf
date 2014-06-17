/*
 * disasplus.h
 *
 *  Created on: 2014-6-17
 *      Author: wb
 */

#ifndef DISASPLUS_H_
#define DISASPLUS_H_
#include <fstream>
extern "C" {
#include "qemu-common.h"
#include "cpu.h"
}

void target_disas_to_ofstream(std::ofstream *out, CPUArchState *env,
        target_ulong pc, int nb_insn, int flags);
void target_disas_to_ofstream(std::ofstream *out, CPUArchState *env,
        target_ulong pc);
#endif /* DISASPLUS_H_ */
