/*
 * DBAF_common.h
 *
 *  Created on: 2014-5-15
 *      Author: wb
 */

#ifndef DBAF_COMMON_H_
#define DBAF_COMMON_H_
#include <stdint.h>
#include "qemu-common.h"
#include  "monitor/monitor.h"
#include "config-host.h"
#include "config-target.h"

typedef target_ulong gva_t;
//Interestingly enough - target_phys_addr_t is defined as uint64 - what to do?
typedef target_ulong gpa_t;

//to determine the HOST type - we use the definitions from TCG
// We use the same logic as defined in tcg.h
//typedef tcg_target_ulong hva_t;
//typedef tcg_target_ulong hpa_t;
#if UINTPTR_MAX == UINT32_MAX
  typedef uint32_t hva_t;
  typedef uint32_t hpa_t;
#elif UINTPTR_MAX == UINT64_MAX
  typedef uint64_t hva_t;
  typedef uint64_t hpa_t;
#else
  #error BLARB
#endif

typedef uintptr_t DBAF_Handle;
#define DBAF_NULL_HANDLE ((uintptr_t)NULL)

//Used for addresses since -1 is a rarely used-if ever 32-bit address
#define INV_ADDR (-1) //0xFFFFFFFF is only for 32-bit

typedef int DBAF_errno_t;
/**
 * Returned when a pointer is NULL when it should not have been
 */
#define NULL_POINTER_ERROR (-101)

/**
 * Returned when a pointer already points to something, although the function is expected to malloc a new area of memory.
 * This is used to signify that there is a potential for a memory leak.
 */
#define NON_NULL_POINTER_ERROR (-102)

/**
 * Returned when malloc fails. Out of memory.
 */
#define OOM_ERROR (-103)

/**
 * Returned when there is an error reading memory - for the guest.
 */
#define MEM_READ_ERROR (-104)

#define FILE_OPEN_ERROR (-105)
#define FILE_READ_ERROR (-105)
#define FILE_WRITE_ERROR (-105)

/**
 * Returned by functions that needed to search for an item before it can continue, but couldn't find it.
 */
#define ITEM_NOT_FOUND_ERROR (-106)

/**
 * Returned when one of the parameters into the function doesn't check out.
 */
#define PARAMETER_ERROR (-107)


/*** Define Registers ***/

/* segment registers */
#define es_reg 100
#define cs_reg 101
#define ss_reg 102
#define ds_reg 103
#define fs_reg 104
#define gs_reg 105

/* address-modifier dependent registers */
#define eAX_reg 108
#define eCX_reg 109
#define eDX_reg 110
#define eBX_reg 111
#define eSP_reg 112
#define eBP_reg 113
#define eSI_reg 114
#define eDI_reg 115

/* 8-bit registers */
#define al_reg 116
#define cl_reg 117
#define dl_reg 118
#define bl_reg 119
#define ah_reg 120
#define ch_reg 121
#define dh_reg 122
#define bh_reg 123

/* 16-bit registers */
#define ax_reg 124
#define cx_reg 125
#define dx_reg 126
#define bx_reg 127
#define sp_reg 128
#define bp_reg 129
#define si_reg 130
#define di_reg 131

/* 32-bit registers */
#define eax_reg 132
#define ecx_reg 133
#define edx_reg 134
#define ebx_reg 135
#define esp_reg 136
#define ebp_reg 137
#define esi_reg 138
#define edi_reg 139


#define indir_dx_reg 150


#ifndef __cplusplus
#define true 1
#define false 0
#endif

#ifdef CONFIG_DEBUG_DBAF
#define DEBUG_DBAF 1
#else
#define DEBUG_DBAF 0
#endif

#if !(DEBUG_DBAF)
#define DBAF_monitor_printf(mon,fmt,...)
#else
typedef struct _IO_FILE FILE;
extern void DBAF_monitor_printf(Monitor *mon, const char *fmt, ...) GCC_FMT_ATTR(2, 3);
#endif
#endif /* DBAF_COMMON_H_ */
