/*
 * disasplus.cpp
 *
 *  Created on: 2014-6-17
 *      Author: wb
 */

#include "disasplus.h"
extern "C" {
#include "config.h"
#include "disas/bfd.h"
#include "elf.h"
#include <errno.h>
#include "cpu.h"
}
#include <iostream>
#include <fstream>
using namespace std;
#include <inttypes.h>
typedef struct CPUDebug {
    struct disassemble_info info;
    CPUArchState *env;
} CPUDebug;

/* Print address in hex, truncated to the width of a target virtual address. */
static void
generic_print_target_address(bfd_vma addr, struct disassemble_info *info)
{
    uint64_t mask = ~0ULL >> (64 - TARGET_VIRT_ADDR_SPACE_BITS);
    (*info->fprintf_func) (info->stream, "0x%lx", addr & mask);
}

static int
generic_read_memory (bfd_vma memaddr, bfd_byte *myaddr, int length,
                     struct disassemble_info *info)
{
    CPUDebug *s = container_of(info, CPUDebug, info);

    cpu_memory_rw_debug(ENV_GET_CPU(s->env), memaddr, myaddr, length, 0);
    return 0;
}

static int GCC_FMT_ATTR(2, 3)
ofstream_fprintf(FILE *file, const char *fmt, ...)
{
	std::ofstream* ostream =(std::ofstream*) file;
	va_list ap;
	va_start(ap, fmt);
	char *buf;
	buf = g_strdup_vprintf(fmt, ap);
	*ostream << buf;
	g_free(buf);
	va_end(ap);
    return 0;
}

void target_disas_to_ofstream(std::ofstream *_stream, CPUArchState *env,
                   target_ulong pc, int nb_insn, int flags)
{
    int count, i;
    CPUDebug s;
    int (*print_insn)(bfd_vma pc, disassemble_info *info);

    INIT_DISASSEMBLE_INFO(s.info, (FILE *)_stream, ofstream_fprintf);

    s.env = env;
    s.info.read_memory_func = generic_read_memory;
    s.info.print_address_func = generic_print_target_address;

    s.info.buffer_vma = pc;

#ifdef TARGET_WORDS_BIGENDIAN
    s.info.endian = BFD_ENDIAN_BIG;
#else
    s.info.endian = BFD_ENDIAN_LITTLE;
#endif
#if defined(TARGET_I386)
    if (flags == 2) {
        s.info.mach = bfd_mach_x86_64;
    } else if (flags == 1) {
        s.info.mach = bfd_mach_i386_i8086;
    } else {
        s.info.mach = bfd_mach_i386_i386;
    }
    print_insn = print_insn_i386;
#elif defined(TARGET_ARM)
    print_insn = print_insn_arm;
#elif defined(TARGET_ALPHA)
    print_insn = print_insn_alpha;
#elif defined(TARGET_SPARC)
    print_insn = print_insn_sparc;
#ifdef TARGET_SPARC64
    s.info.mach = bfd_mach_sparc_v9b;
#endif
#elif defined(TARGET_PPC)
#ifdef TARGET_PPC64
    s.info.mach = bfd_mach_ppc64;
#else
    s.info.mach = bfd_mach_ppc;
#endif
    print_insn = print_insn_ppc;
#elif defined(TARGET_M68K)
    print_insn = print_insn_m68k;
#elif defined(TARGET_MIPS)
#ifdef TARGET_WORDS_BIGENDIAN
    print_insn = print_insn_big_mips;
#else
    print_insn = print_insn_little_mips;
#endif
#elif defined(TARGET_SH4)
    s.info.mach = bfd_mach_sh4;
    print_insn = print_insn_sh;
#elif defined(TARGET_S390X)
    s.info.mach = bfd_mach_s390_64;
    print_insn = print_insn_s390;
#elif defined(TARGET_MOXIE)
    s.info.mach = bfd_arch_moxie;
    print_insn = print_insn_moxie;
#elif defined(TARGET_LM32)
    s.info.mach = bfd_mach_lm32;
    print_insn = print_insn_lm32;
#else
    monitor_printf(mon, "0x" TARGET_FMT_lx
                   ": Asm output not supported on this arch\n", pc);
    return;
#endif

    for(i = 0; i < nb_insn; i++) {
    	ofstream_fprintf((FILE *)_stream , "0x" TARGET_FMT_lx ":  ", pc);
        count = print_insn(pc, &s.info);
        ofstream_fprintf((FILE *)_stream, "\n");
	if (count < 0)
	    break;
        pc += count;
    }
}
void target_disas_to_ofstream(std::ofstream *out, CPUArchState *env,
        target_ulong pc){
	target_disas_to_ofstream(out, env, pc, 1, 0);
}
