#ifndef DBAF_EXECUTIONSTATE_H
#define DBAF_EXECUTIONSTATE_H
#include <map>
extern "C" {
#include "qemu-common.h"
#include "exec/cpu-all.h"
#include "cpu.h"
}
#include "DBAF_common.h"

#include <string>
using namespace std;

namespace dbaf {
enum CPUContentType {
	CPU_SEGS, CPU_REGS, CPU_CRS
};
class Plugin;
class PluginState;
class DBAFExecutionState;

//typedef std::tr1::unordered_map<const Plugin*, PluginState*> PluginStateMap;
typedef std::map<const Plugin*, PluginState*> PluginStateMap;
typedef PluginState* (*PluginStateFactory)(Plugin *p, DBAFExecutionState *s);


class DBAFExecutionState
{
protected:
    PluginStateMap m_PluginState;
private:
    CPUState *cpu;
public:
    enum AddressType {
        VirtualAddress, PhysicalAddress, HostAddress
    };

    DBAFExecutionState();
    ~DBAFExecutionState();

    target_ulong readCpuState(CPUContentType _type, int index);
    target_ulong readCpu0State(CPUContentType _type, int index);

    DBAF_errno_t readMemory(target_ulong address, void *buf,uint64_t size);
    DBAF_errno_t readMemory(target_ulong cr3, target_ulong address, void *buf,uint64_t size);
    DBAF_errno_t readMemoryConcrete(target_ulong address, void *buf,uint64_t size){
    	return readMemory(address,buf,size);
    }
	DBAF_errno_t readMemoryConcrete(target_ulong cr3, target_ulong address,
			void *buf, uint64_t size) {
		return readMemory(cr3, address, buf, size);
	}
	bool IsValidString(const char *str);
	bool readString(target_ulong cr3, target_ulong address, std::string &s,
			uint64_t maxlen);
	bool readString(target_ulong address, std::string &s, uint64_t maxlen);
	bool readUnicodeString(target_ulong cr3, target_ulong address, std::string &s,
			uint64_t maxlen);
	bool readUnicodeString(target_ulong address, std::string &s, uint64_t maxlen);

    CPUArchState* getCPUArchState(){
    	cpu = current_cpu ? current_cpu : first_cpu;
    	return (CPUArchState*)cpu->env_ptr;
    }
    target_ulong getCr3();
    target_ulong getEip();
    target_ulong getEax();
    target_ulong getEbx();
    target_ulong getEcx();
    target_ulong getEdx();
    target_ulong getEbp();
    target_ulong getEsp();

    PluginState* getPluginState(Plugin *plugin, PluginStateFactory factory) {
        PluginStateMap::iterator it = m_PluginState.find(plugin);
        if (it == m_PluginState.end()) {
            PluginState *ret = factory(plugin, this);
            m_PluginState[plugin] = ret;
            return ret;
        }
        return (*it).second;
    }
};


}

#endif // DBAF_EXECUTIONSTATE_H
