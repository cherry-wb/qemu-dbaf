/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>

DBAF is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about DBAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DBAF,please post it on
http://code.google.com/p/dbaf-platform/
*/
/*
 * Output.h
 *
 *  Created on: Sep 29, 2011
 *      Author: lok
 */

#ifndef OUTPUT_H_
#define OUTPUT_H_

#include <stdio.h>
#include "monitor/monitor.h"

#ifdef __cplusplus
extern "C"
{
#endif

void DBAF_printf(const char* fmt, ...);
void DBAF_mprintf(const char* fmt, ...);
void DBAF_fprintf(FILE* fp, const char* fmt, ...);
void DBAF_vprintf(FILE* fp, const char* fmt, va_list ap);
void DBAF_flush(void);
void DBAF_fflush(FILE* fp);

FILE* DBAF_get_output_fp(void);
Monitor* DBAF_get_output_mon(void);
const FILE* DBAF_get_monitor_fp(void);

void DBAF_do_set_output_file(Monitor* mon, const char* fileName);
void DBAF_output_init(Monitor* mon);
void DBAF_output_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* OUTPUT_H_ */
