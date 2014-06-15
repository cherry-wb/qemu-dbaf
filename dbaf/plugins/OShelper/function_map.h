#ifndef _FUNCTION_MAP_H_
#define _FUNCTION_MAP_H_

#ifdef __cplusplus
extern "C" {
#endif

void function_map_init(void);
void function_map_cleanup(void);

target_ulong funcmap_get_pc(const char *module_name, const char *function_name, target_ulong cr3);

int funcmap_get_name_c(target_ulong pc, target_ulong cr3, char *mod_name, char *func_name);

void funcmap_insert_function(const char *module, const char *fname, uint32_t offset);

void dump_module_function(const char* module, uint64_t checksum);

extern void parse_function(const char *message);

#ifdef __cplusplus
};
#endif


#endif

