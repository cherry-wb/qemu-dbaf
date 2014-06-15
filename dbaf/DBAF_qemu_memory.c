/*
 * DBAF_qemu_memory.c
 *
 *  Created on: 2014-6-4
 *      Author: wb
 */
#include "qemu-common.h"
#include "exec/cpu-all.h"
#include "cpu.h"
#include "tcg.h"
#include <dbaf/DBAF_qemu_memory.h>
hwaddr DBAF_get_phys_addr(CPUState* cpu, target_ulong addr);
hwaddr DBAF_get_phys_addr_with_pgd(CPUState *cpu, target_ulong pgd, target_ulong addr);
DBAF_errno_t DBAF_memory_rw(CPUState* cpu, target_ulong addr, void *buf, uint64_t len, int is_write);
DBAF_errno_t DBAF_memory_rw_with_pgd(CPUState* cpu, target_ulong pgd, target_ulong addr, void *buf, uint64_t len, int is_write);
hwaddr DBAF_get_phys_addr(CPUState* cpu, target_ulong addr) {
	hwaddr phys_addr;
	target_ulong page;
	if (cpu == NULL ) {
		cpu = current_cpu ? current_cpu : first_cpu;
	}
	page = addr & TARGET_PAGE_MASK;
	phys_addr = cpu_get_phys_page_debug(cpu, page);
	/* if no physical page mapped, return an error */
	if (phys_addr == -1)
		return -1;
	phys_addr += (addr & ~TARGET_PAGE_MASK);
	return phys_addr;
}

hwaddr DBAF_get_phys_addr_with_pgd(CPUState *cpu, target_ulong pgd, target_ulong addr)
{
	CPUArchState *env;
	target_ulong saved_cr3;
	hwaddr phys_addr;
	target_ulong page;
	if (cpu == NULL ) {
		cpu = current_cpu ? current_cpu : first_cpu;
	}
	env = cpu->env_ptr;
	saved_cr3 = env->cr[3];

	env->cr[3] = pgd;
	page = addr & TARGET_PAGE_MASK;
	phys_addr = cpu_get_phys_page_debug(cpu, page);
	env->cr[3] = saved_cr3;
	if (phys_addr == -1)
			return -1;
	phys_addr += (addr & ~TARGET_PAGE_MASK);
	return phys_addr;
}

DBAF_errno_t DBAF_memory_rw(CPUState* cpu, target_ulong addr, void *buf, uint64_t len, int is_write) {
	int l;
	hwaddr phys_addr;
	target_ulong page;

	if (cpu == NULL ) {
		cpu = current_cpu ? current_cpu : first_cpu;
	}
	while (len > 0) {
		page = addr & TARGET_PAGE_MASK;
		phys_addr = DBAF_get_phys_addr(cpu, addr);
		if (phys_addr == -1 || phys_addr > ram_size) {
			return -1;
		}
		l = (page + TARGET_PAGE_SIZE) - addr;
		if (l > len)
			l = len;

		cpu_physical_memory_rw(phys_addr, buf, l, is_write);
		len -= l;
		buf += l;
		addr += l;
	}
	return 0;
}

DBAF_errno_t DBAF_memory_rw_with_pgd(CPUState* cpu, target_ulong pgd, target_ulong addr, void *buf, uint64_t len, int is_write) {
	int l;
	hwaddr phys_addr;
	target_ulong page;
	if (cpu == NULL ) {
		cpu = current_cpu ? current_cpu : first_cpu;
	}
	while (len > 0) {
		page = addr & TARGET_PAGE_MASK;
		phys_addr = DBAF_get_phys_addr_with_pgd(cpu, pgd, addr);
		if (phys_addr == -1)
			return -1;
		l = (page + TARGET_PAGE_SIZE) - addr;
		if (l > len)
			l = len;
		cpu_physical_memory_rw(phys_addr, buf, l,is_write);
		len -= l;
		buf += l;
		addr += l;
	}
	return 0;
}

DBAF_errno_t DBAF_read_mem(CPUState* cpu, target_ulong vaddr, void *buf, uint64_t len) {
	return DBAF_memory_rw(cpu, vaddr, buf, len, 0);
}

DBAF_errno_t DBAF_write_mem(CPUState* cpu, target_ulong vaddr, void *buf, uint64_t len) {
	return DBAF_memory_rw(cpu, vaddr, buf, len, 1);
}

DBAF_errno_t DBAF_read_mem_with_pgd(CPUState* cpu, target_ulong cr3, target_ulong vaddr, void *buf, uint64_t len) {
	return DBAF_memory_rw_with_pgd(cpu, cr3, vaddr, buf, len, 0);
}

DBAF_errno_t DBAF_write_mem_with_pgd(CPUState* cpu, target_ulong cr3, target_ulong vaddr, void *buf, uint64_t len) {
	return DBAF_memory_rw_with_pgd(cpu, cr3, vaddr, buf, len, 1);
}


