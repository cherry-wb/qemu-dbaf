#ifndef DBAFLJLJ_H
#define DBAFLJLJ_H

#include <config.h>
#include <setjmp.h>
#define dbaf_sigsetjmp sigsetjmp
#define dbaf_siglongjmp siglongjmp
#define dbaf_sigjmp_buf sigjmp_buf
#endif
