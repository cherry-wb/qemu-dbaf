extern "C" {
#include "config.h"
#include "qemu-common.h"
}

#include "DBAFExecutionState.h"
#include <dbaf/Plugin.h>
#include <dbaf/DBAF.h>
#include <iomanip>
#include <sstream>
extern "C" {
#include <dbaf/DBAF_qemu_memory.h>
}
namespace dbaf {

DBAFExecutionState::DBAFExecutionState()
{
	cpu = NULL;
}

DBAFExecutionState::~DBAFExecutionState()
{
    PluginStateMap::iterator it;

    for(it = m_PluginState.begin(); it != m_PluginState.end(); ++it) {
        delete it->second;
    }
}
target_ulong DBAFExecutionState::readCpuState(CPUContentType _type, int index) {
	CPUArchState *env;
	cpu = current_cpu ? current_cpu : first_cpu;
	env = (CPUArchState *)cpu->env_ptr;
	switch (_type) {
	case CPU_SEGS:
		return env->segs[index].base;
	case CPU_REGS:
		return env->regs[index];
	case CPU_CRS:
		return env->cr[index];
	default: {
			fprintf(stderr,"error: unknow CPUContentType.");
			exit(-1);
		}
	}
}
target_ulong DBAFExecutionState::getCr3(){
	return readCpuState(CPU_CRS,3);
}
target_ulong DBAFExecutionState::getEip() {
	CPUArchState *env;
	cpu = current_cpu ? current_cpu : first_cpu;
	env = (CPUArchState *) cpu->env_ptr;
	return env->eip;
}
target_ulong DBAFExecutionState::getEax(){
	return readCpuState(CPU_REGS,R_EAX);
}
target_ulong DBAFExecutionState::getEbx(){
	return readCpuState(CPU_REGS,R_EBX);
}
target_ulong DBAFExecutionState::getEcx(){
	return readCpuState(CPU_REGS,R_ECX);
}
target_ulong DBAFExecutionState::getEdx(){
	return readCpuState(CPU_REGS,R_EDX);
}
target_ulong DBAFExecutionState::getEbp(){
	return readCpuState(CPU_REGS,R_EBP);
}
target_ulong DBAFExecutionState::getEsp(){
	return readCpuState(CPU_REGS,R_ESP);
}
target_ulong DBAFExecutionState::readCpu0State(CPUContentType _type, int index) {
	CPUState *cpu0;
	CPUArchState *env;
	CPU_FOREACH(cpu0)
	{
		if (cpu0->cpu_index == 0) {
			break;
		}
	}
	env = (CPUArchState *)cpu0->env_ptr;
	switch (_type) {
	case CPU_SEGS:
		return env->segs[index].base;
	case CPU_REGS:
		return env->regs[index];
	case CPU_CRS:
		return env->cr[index];
	default: {
		fprintf(stderr,"error: unknow CPUContentType.");
		exit(-1);
	}
	}
}
DBAF_errno_t DBAFExecutionState::readMemory(target_ulong address, void *buf,uint64_t size){
	return DBAF_read_mem(current_cpu, address, buf, size);
}
DBAF_errno_t DBAFExecutionState::readMemory(target_ulong cr3, target_ulong address, void *buf,uint64_t size){
	return DBAF_read_mem_with_pgd(current_cpu, cr3, address, buf, size);
}
bool DBAFExecutionState::IsValidString(const char *str)
	{
	    for (unsigned i=0; str[i]; i++) {
	        if (str[i] > 0x20 && (unsigned)str[i] < 0x80) {
	            continue;
	        }
	        return false;
	    }
	    return true;
	}
bool DBAFExecutionState::readString(target_ulong cr3, target_ulong address,
		std::string &s, uint64_t maxlen) {
	s = "";
	do {
		uint8_t c;
		if (readMemoryConcrete(cr3, address, &c, sizeof(c))) {
			return false;
		}
		if (c) {
			s = s + (char) c;
		} else {
			return true;
		}
		address++;
		maxlen--;
	} while (maxlen != 0);
	return true;
}

bool DBAFExecutionState::readString(target_ulong address, std::string &s, uint64_t maxlen) {
    s = "";
    do {
        uint8_t c;
        if (readMemoryConcrete(address, &c, sizeof(c))){ return false;}
        if (c) {
            s = s + (char)c;
        }else {
            return true;
        }
        address++;
        maxlen--;
    }while(maxlen != 0);
    return true;
}
bool DBAFExecutionState::readUnicodeString(target_ulong cr3, target_ulong address,
		std::string &s, uint64_t maxlen) {
	s = "";
	do {
		uint16_t c;
		if (readMemoryConcrete(cr3, address, &c, sizeof(c))) {
			return false;
		}
		if (c) {
			s = s + (char) c;
		} else {
			return true;
		}
		address+=2;
		maxlen--;
	} while (maxlen != 0);
	return true;
}

bool DBAFExecutionState::readUnicodeString(target_ulong address, std::string &s, uint64_t maxlen) {
    s = "";
    do {
    	uint16_t c;
        if (readMemoryConcrete(address, &c, sizeof(c))){ return false;}
        if (c) {
            s = s + (char)c;
        }else {
            return true;
        }
        address+=2;
        maxlen--;
    }while(maxlen != 0);
    return true;
}
} // namespace dbaf

/******************************/
/* Functions called from QEMU */

extern "C" {


} // extern "C"
