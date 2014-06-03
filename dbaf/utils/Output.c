#include "Output.h"

//file pointers should never be in the kernel memory range so this should work
static const void* DBAF_OUTPUT_MONITOR_FD = (void*)0xFEEDBEEF;

FILE* ofp = NULL;
Monitor* pMon = NULL;

void DBAF_printf(const char* fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  DBAF_vprintf(ofp, fmt, ap);
  va_end(ap);
}

void DBAF_fprintf(FILE* fp, const char* fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  if ( (pMon != NULL) && (((void*)fp == (void*)pMon) || (fp == DBAF_OUTPUT_MONITOR_FD)) )
  {
    monitor_vprintf(pMon, fmt, ap);
  }
  else
  {
    DBAF_vprintf(fp, fmt, ap);
  }
  va_end(ap);
}

void DBAF_mprintf(const char* fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  if (pMon != NULL)
  {
    monitor_vprintf(pMon, fmt, ap);
  }
  else
  {
    vprintf(fmt, ap);
  }
  va_end(ap);
}

void DBAF_vprintf(FILE* fp, const char *fmt, va_list ap)
{
  if (fp == NULL)
  {
    //that means either use stdout or monitor
    if (pMon != NULL)
    {
      monitor_vprintf(pMon, fmt, ap);
    }
    else
    {
      vprintf(fmt, ap);
    }
  }
  else
  {
    vfprintf(fp, fmt, ap);
  }
}

void DBAF_flush(void)
{
  DBAF_fflush(ofp);
}

void DBAF_fflush(FILE* fp)
{
  if (fp == NULL)
  {
    if (pMon != NULL)
    {
      //nothing to do here
    }
    else
    {
      fflush(stdout);
    }
  }
  else
  {
    fflush(fp);
  }
}

void DBAF_do_set_output_file(Monitor* mon, const char* fileName)
{
  if (ofp != NULL)
  {
    return;
  }

  if (strcmp(fileName, "stdout") == 0)
  {
    DBAF_output_cleanup();
    return;
  }
  pMon = mon; //make a local copy of the monitor
  //open the file
  ofp = fopen(fileName, "w");
  if (ofp == NULL)
  {
    DBAF_printf("Could not open the file [%s]\n", fileName);
  }
}

void DBAF_output_init(Monitor* mon)
{
  if (mon != NULL)
  {
    pMon = mon;
  }
  else
  {
    pMon = default_mon;
  }
}

void DBAF_output_cleanup(void)
{
  if (ofp != NULL)
  {
    fflush(ofp);
    fclose(ofp);
  }
  ofp = NULL;
  pMon = NULL;
}


FILE* DBAF_get_output_fp(void)
{
  return (ofp);
}

Monitor* DBAF_get_output_mon(void)
{
  return (pMon);
}

const FILE* DBAF_get_monitor_fp(void)
{
  return (DBAF_OUTPUT_MONITOR_FD);
}
