extern "C" {
#include "config.h"
#include "qemu-common.h"
}

#include "HookManager.h"
#include <dbaf/DBAF.h>
#include <dbaf/ConfigFile.h>
#include <dbaf/plugins/OShelper/function_map.h>
#include <iostream>

namespace dbaf {
namespace plugins {

DBAF_DEFINE_PLUGIN(HookManager, "Api calls/returns hook plugin", "", "Interceptor",);

void X86HookManager::initialize()
{
    dbaf()->getCorePlugin()->onTranslateBlockStart.connect(
            fsigc::mem_fun(*this, &X86HookManager::slotTranslateBlockStart));

    dbaf()->getCorePlugin()->onTranslateJumpStart.connect(
            fsigc::mem_fun(*this, &X86HookManager::slotTranslateJumpStart));

    m_monitor = static_cast<OSMonitor*>(dbaf()->getPlugin("Interceptor"));

    if(m_monitor){
    	m_monitor->onSymbolsResolved.connect(
            fsigc::mem_fun(*this, &X86HookManager::slotSymbolsResolved));
    }
}

X86HookManager::CallSignal* X86HookManager::registerApiCallSignal(
        DBAFExecutionState *state,
        const char *mod, const char *func, uint64_t cr3)
{
    DECLARE_PLUGINSTATE(X86HookManagerState, state);

    return plgState->getApiCallSignal(mod, func, cr3);
}

void X86HookManager::slotTranslateBlockStart(ExecutionSignal *signal,
                                      DBAFExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc)
{
    /* if needed, we connect */
	DECLARE_PLUGINSTATE(X86HookManagerState, state);
	if (plgState->exists(state, pc)) {
		signal->connect(fsigc::mem_fun(*this, &X86HookManager::slotCall));
	}
}

void X86HookManager::slotTranslateJumpStart(ExecutionSignal *signal,
                                             DBAFExecutionState *state,
                                             TranslationBlock *,
                                             uint64_t, int jump_type)
{
    if(jump_type == JT_RET || jump_type == JT_LRET) {
        signal->connect(fsigc::mem_fun(*this,
                            &X86HookManager::slotRet));
    }
}

void X86HookManager::slotCall(DBAFExecutionState *state, uint64_t pc, uint64_t nextpc)
{
    DECLARE_PLUGINSTATE(X86HookManagerState, state);

    return plgState->slotCall(state, pc);
}

void X86HookManager::disconnect(DBAFExecutionState *state, const module &desc)
{
    DECLARE_PLUGINSTATE(X86HookManagerState, state);

    return plgState->disconnect(desc);
}


void X86HookManager::registerReturnSignal(DBAFExecutionState *state, X86HookManager::ReturnSignal &sig)
{
    DECLARE_PLUGINSTATE(X86HookManagerState, state);
    plgState->registerReturnSignal(state, sig);
}

void X86HookManager::slotSymbolsResolved(DBAFExecutionState *state, module* mod){
	 DECLARE_PLUGINSTATE(X86HookManagerState, state);
	 plgState->processSymbolsResolved(mod);
}

void X86HookManager::slotRet(DBAFExecutionState *state, uint64_t pc, uint64_t nextpc)
{
    DECLARE_PLUGINSTATE(X86HookManagerState, state);

    return plgState->slotRet(state, pc, true);
}

X86HookManagerState::X86HookManagerState()
{
	m_plugin = NULL;
}

X86HookManagerState::~X86HookManagerState()
{

}

X86HookManagerState* X86HookManagerState::clone() const
{
    X86HookManagerState *ret = new X86HookManagerState(*this);
    assert(ret->m_returnDescriptors.size() == m_returnDescriptors.size());
    return ret;
}

PluginState *X86HookManagerState::factory(Plugin *p, DBAFExecutionState *s)
{
    X86HookManagerState *ret = new X86HookManagerState();
    ret->m_plugin = static_cast<X86HookManager*>(p);
    return ret;
}

X86HookManager::CallSignal* X86HookManagerState::getApiCallSignal(
		const char *mod, const char *func, uint64_t cr3)
{
	target_ulong pc = funcmap_get_pc(mod, func, cr3);
	if (pc != 0) {
		std::pair<ApiDescriptorsMap::iterator, ApiDescriptorsMap::iterator>
				range = m_callDescriptors.equal_range(pc);

		for(ApiDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
			if(it->second.cr3 == cr3)
				return &it->second.signal;
		}
	}
//	const char *mod,
//	const char *func,
//	target_ulong cr3,

    ApiDescriptor descriptor = { cr3, string(mod), string(func), X86HookManager::CallSignal() };
    ApiDescriptorsMap::iterator it;
	if (pc == 0) {
		it = m_unresolvedApiDescriptors.insert(
				std::make_pair(m_unresolvedApiDescriptors.size(), descriptor));
	} else {
		m_plugin->dbaf()->getDebugStream() << "hooked modname:" << mod<< " funcname:" << func << " at pc:" << hexval(pc) << " and cr3:" << cr3 << endl;
		it = m_newApiDescriptors.insert(std::make_pair(pc, descriptor));
	}

    return &it->second.signal;
}

void X86HookManagerState::processSymbolsResolved(module* mod){
	if (!m_unresolvedApiDescriptors.empty()) {
		ApiDescriptorsMap::iterator it = m_unresolvedApiDescriptors.begin();
		while (it != m_unresolvedApiDescriptors.end()) {
			const ApiDescriptor &call = (*it).second;
			ApiDescriptorsMap::iterator iterase = it;
			++it;
			if(strcmp(mod->name,call.mod.c_str()) == 0){
				target_ulong pc = funcmap_get_pc(call.mod.c_str(),
						call.func.c_str(), call.cr3);
				if (pc != 0) {
					m_plugin->dbaf()->getDebugStream() << "hooked modname:" << call.mod << " funcname:" << call.func << " at pc:" << hexval(pc) << " and cr3:" << call.cr3 << endl;
					m_newApiDescriptors.insert(std::make_pair(pc, call));
					m_unresolvedApiDescriptors.erase(iterase);
				}
			}
		}
	}
}
void X86HookManagerState::slotCall(DBAFExecutionState *state, uint64_t pc)
{
    target_ulong cr3 = state->getCr3();
    target_ulong eip = state->getEip();

    if (!m_newApiDescriptors.empty()) {
        m_callDescriptors.insert(m_newApiDescriptors.begin(), m_newApiDescriptors.end());
        m_newApiDescriptors.clear();
    }

    /* Issue signals attached to all calls (eip==-1 means catch-all) */
    if (!m_callDescriptors.empty()) {
        std::pair<ApiDescriptorsMap::iterator, ApiDescriptorsMap::iterator>
                range = m_callDescriptors.equal_range((uint64_t)-1);
        for(ApiDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
            ApiDescriptor cd = (*it).second;
            if(it->second.cr3 == (uint64_t)-1 || it->second.cr3 == cr3) {
                cd.signal.emit(state, this);
            }
        }
        if (!m_newApiDescriptors.empty()) {
            m_callDescriptors.insert(m_newApiDescriptors.begin(), m_newApiDescriptors.end());
            m_newApiDescriptors.clear();
        }
    }

    /* Issue signals attached to specific calls */
    if (!m_callDescriptors.empty()) {
        std::pair<ApiDescriptorsMap::iterator, ApiDescriptorsMap::iterator>
                range;

        range = m_callDescriptors.equal_range(eip);
        for(ApiDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
            ApiDescriptor cd = (*it).second;
            if(it->second.cr3 == (uint64_t)-1 || it->second.cr3 == cr3) {
                cd.signal.emit(state, this);
            }
        }
        if (!m_newApiDescriptors.empty()) {
            m_callDescriptors.insert(m_newApiDescriptors.begin(), m_newApiDescriptors.end());
            m_newApiDescriptors.clear();
        }
    }
}
bool X86HookManagerState::exists(DBAFExecutionState *state, uint64_t eip){
	if (!m_newApiDescriptors.empty()) {
		std::pair<ApiDescriptorsMap::iterator, ApiDescriptorsMap::iterator> range =
				m_newApiDescriptors.equal_range(eip);
		for (ApiDescriptorsMap::iterator it = range.first; it != range.second;
				++it) {
				return true;
		}
	}
	if (!m_callDescriptors.empty()) {
		std::pair<ApiDescriptorsMap::iterator, ApiDescriptorsMap::iterator> range =
				m_callDescriptors.equal_range(eip);
		for (ApiDescriptorsMap::iterator it = range.first; it != range.second;
				++it) {
				return true;
		}
	}
	return false;
}
/**
 *  A call handler can invoke this function to register a return handler.
 *  XXX: We assume that the passed execution state corresponds to the state in which
 *  this instance of HookManagerState is used.
 */
void X86HookManagerState::registerReturnSignal(DBAFExecutionState *state, X86HookManager::ReturnSignal &sig)
{
    if(sig.empty()) {
        return;
    }

    target_ulong esp;

    esp = state->getEsp();

    uint64_t cr3 = state->getCr3();
    ReturnDescriptor descriptor = {cr3, sig };
    m_returnDescriptors.insert(std::make_pair(esp, descriptor));
}

/**
 *  When emitSignal is false, this function simply removes all the return descriptors
 * for the current stack pointer. This can be used when a return handler manually changes the
 * program counter and/or wants to exit to the cpu loop and avoid being called again.
 *
 *  Note: all the return handlers will be erased if emitSignal is false, not just the one
 * that issued the call. Also note that it not possible to return from the handler normally
 * whenever this function is called from within a return handler.
 */
void X86HookManagerState::slotRet(DBAFExecutionState *state, uint64_t pc, bool emitSignal)
{
	target_ulong cr3 = state->getCr3();
	target_ulong esp = state->getEsp();

    if (m_returnDescriptors.empty()) {
        return;
    }

    bool finished = true;
    do {
        finished = true;
        std::pair<ReturnDescriptorsMap::iterator, ReturnDescriptorsMap::iterator>
                range = m_returnDescriptors.equal_range(esp);
        for(ReturnDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
            if(it->second.cr3 == cr3) {
                if (emitSignal) {
                    it->second.signal.emit(state);
                }
                m_returnDescriptors.erase(it);
                finished = false;
                break;
            }
        }
    } while(!finished);
}

void X86HookManagerState::disconnect(const module &desc, ApiDescriptorsMap &descMap)
{
    ApiDescriptorsMap::iterator it = descMap.begin();
    while (it != descMap.end()) {
    	target_ulong moduleloadbase;
        uint64_t addr = (*it).first;
        const ApiDescriptor &call = (*it).second;
        module* selected = m_plugin->m_monitor->VMI_find_module_by_pc((target_ulong)addr,call.cr3,&moduleloadbase);
        if (strcmp(selected->name, desc.name) == 0) {
            ApiDescriptorsMap::iterator it2 = it;
            ++it;
            descMap.erase(it2);
        }else {
            ++it;
        }
    }
}

//Disconnect all address that belong to desc.
//This is useful to unregister all handlers when a module is unloaded
void X86HookManagerState::disconnect(const module &desc)
{

    disconnect(desc, m_callDescriptors);
    disconnect(desc, m_newApiDescriptors);
    disconnect(desc, m_unresolvedApiDescriptors);

}


} // namespace plugins
} // namespace dbaf
