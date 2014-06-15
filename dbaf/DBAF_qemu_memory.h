/*
 * DBAF_qemu_memory.h
 *
 *  Created on: 2014-6-4
 *      Author: wb
 */

#ifndef DBAF_QEMU_MEMORY_H_
#define DBAF_QEMU_MEMORY_H_
#include <dbaf/DBAF_common.h>
#include "qemu-common.h"

DBAF_errno_t DBAF_read_mem(CPUState* cpu, target_ulong vaddr, void *buf, uint64_t len);
DBAF_errno_t DBAF_write_mem(CPUState* cpu, target_ulong vaddr, void *buf, uint64_t len);
DBAF_errno_t DBAF_read_mem_with_pgd(CPUState* cpu, target_ulong cr3, target_ulong vaddr, void *buf, uint64_t len);
DBAF_errno_t DBAF_write_mem_with_pgd(CPUState* cpu, target_ulong cr3, target_ulong vaddr, void *buf, uint64_t len);


#endif /* DBAF_QEMU_MEMORY_H_ */
