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
