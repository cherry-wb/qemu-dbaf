/* Helper file for declaring TCG helper functions.
   This one defines data structures private to tcg.c.  */

#ifndef HELPER_TCG_H
#define HELPER_TCG_H 1

#include <exec/helper-head.h>

#define DEF_HELPER_FLAGS_0(NAME, FLAGS, ret) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0), \
    .reg_rmask= 0, .reg_wmask = 0, \
    .accesses_mem = 1 },

#define DEF_HELPER_FLAGS_1(NAME, FLAGS, ret, t1) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1), \
    .reg_rmask= 0, .reg_wmask = 0, \
    .accesses_mem = 1 },

#define DEF_HELPER_FLAGS_2(NAME, FLAGS, ret, t1, t2) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2), \
    .reg_rmask= 0, .reg_wmask = 0, \
    .accesses_mem = 1 },

#define DEF_HELPER_FLAGS_3(NAME, FLAGS, ret, t1, t2, t3) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3), \
    .reg_rmask= 0, .reg_wmask = 0, \
    .accesses_mem = 1 },

#define DEF_HELPER_FLAGS_4(NAME, FLAGS, ret, t1, t2, t3, t4) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4), \
    .reg_rmask= 0, .reg_wmask = 0, \
    .accesses_mem = 1 },

#define DEF_HELPER_FLAGS_5(NAME, FLAGS, ret, t1, t2, t3, t4, t5) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) \
    | dh_sizemask(t5, 5), \
    .reg_rmask= 0, .reg_wmask = 0, \
    .accesses_mem = 1 },

#define DEF_HELPER_FLAGS_0_M(NAME, FLAGS, ret, rm, wm, m) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0), \
    .reg_rmask=rm, .reg_wmask =wm, .accesses_mem = m },

#define DEF_HELPER_FLAGS_1_M(NAME, FLAGS, ret, t1, rm, wm, m) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1), \
    .reg_rmask=rm, .reg_wmask =wm, .accesses_mem = m },

#define DEF_HELPER_FLAGS_2_M(NAME, FLAGS, ret, t1, t2, rm, wm, m) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2), \
    .reg_rmask=rm, .reg_wmask =wm, .accesses_mem = m },

#define DEF_HELPER_FLAGS_3_M(NAME, FLAGS, ret, t1, t2, t3, rm, wm, m) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3), \
    .reg_rmask=rm, .reg_wmask =wm, .accesses_mem = m },

#define DEF_HELPER_FLAGS_4_M(NAME, FLAGS, ret, t1, t2, t3, t4, rm, wm, m) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4), \
    .reg_rmask=rm, .reg_wmask =wm, .accesses_mem = m },

#define DEF_HELPER_FLAGS_5_M(NAME, FLAGS, ret, t1, t2, t3, t4, t5, rm, wm, m) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) \
    | dh_sizemask(t5, 5), \
    .reg_rmask=rm, .reg_wmask =wm, .accesses_mem = m },

#ifdef CONFIG_DBAF
#include "helper-copy-tcg.h"
#else
#include "helper.h"
#endif
#include "tcg-runtime.h"

#undef DEF_HELPER_FLAGS_0
#undef DEF_HELPER_FLAGS_1
#undef DEF_HELPER_FLAGS_2
#undef DEF_HELPER_FLAGS_3
#undef DEF_HELPER_FLAGS_4
#undef DEF_HELPER_FLAGS_5

#endif /* HELPER_TCG_H */
