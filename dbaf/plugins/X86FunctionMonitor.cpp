extern "C" {
#include "config.h"
#include "qemu-common.h"
}

#include "FunctionMonitor.h"
#include <dbaf/DBAF.h>
#include <dbaf/ConfigFile.h>

#include <iostream>

namespace dbaf {
namespace plugins {

DBAF_DEFINE_PLUGIN(FunctionMonitor, "Function calls/returns monitoring plugin", "",);

void X86FunctionMonitor::initialize()
{
    dbaf()->getCorePlugin()->onTranslateBlockEnd.connect(
            fsigc::mem_fun(*this, &X86FunctionMonitor::slotTranslateBlockEnd));

    dbaf()->getCorePlugin()->onTranslateJumpStart.connect(
            fsigc::mem_fun(*this, &X86FunctionMonitor::slotTranslateJumpStart));

    m_monitor = static_cast<OSMonitor*>(dbaf()->getPlugin("Interceptor"));
}

//XXX: Implement onmoduleunload to automatically clear all call signals
X86FunctionMonitor::CallSignal* X86FunctionMonitor::getCallSignal(
        DBAFExecutionState *state,
        uint64_t eip, uint64_t cr3)
{
    DECLARE_PLUGINSTATE(X86FunctionMonitorState, state);

    return plgState->getCallSignal(eip, cr3);
}

void X86FunctionMonitor::slotTranslateBlockEnd(ExecutionSignal *signal,
                                      DBAFExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc, bool, uint64_t)
{
    /* We intercept all call and ret translation blocks */
    if (tb->dbaf_tb_type == TB_CALL || tb->dbaf_tb_type == TB_CALL_IND) {
        signal->connect(fsigc::mem_fun(*this,
                            &X86FunctionMonitor::slotCall));
    }
}

void X86FunctionMonitor::slotTranslateJumpStart(ExecutionSignal *signal,
                                             DBAFExecutionState *state,
                                             TranslationBlock *,
                                             uint64_t, int jump_type)
{
    if(jump_type == JT_RET || jump_type == JT_LRET) {
        signal->connect(fsigc::mem_fun(*this,
                            &X86FunctionMonitor::slotRet));
    }
}

void X86FunctionMonitor::slotCall(DBAFExecutionState *state, uint64_t pc, uint64_t nextpc)
{
    DECLARE_PLUGINSTATE(X86FunctionMonitorState, state);

    return plgState->slotCall(state, pc);
}

void X86FunctionMonitor::disconnect(DBAFExecutionState *state, const module &desc)
{
    DECLARE_PLUGINSTATE(X86FunctionMonitorState, state);

    return plgState->disconnect(desc);
}


void X86FunctionMonitor::registerReturnSignal(DBAFExecutionState *state, X86FunctionMonitor::ReturnSignal &sig)
{
    DECLARE_PLUGINSTATE(X86FunctionMonitorState, state);
    plgState->registerReturnSignal(state, sig);
}


void X86FunctionMonitor::slotRet(DBAFExecutionState *state, uint64_t pc, uint64_t nextpc)
{
    DECLARE_PLUGINSTATE(X86FunctionMonitorState, state);

    return plgState->slotRet(state, pc, true);
}

X86FunctionMonitorState::X86FunctionMonitorState()
{

}

X86FunctionMonitorState::~X86FunctionMonitorState()
{

}

X86FunctionMonitorState* X86FunctionMonitorState::clone() const
{
    X86FunctionMonitorState *ret = new X86FunctionMonitorState(*this);
    m_plugin->dbaf()->getDebugStream() << "Forking FunctionMonitorState ret=" << hexval(ret) << '\n';
    assert(ret->m_returnDescriptors.size() == m_returnDescriptors.size());
    return ret;
}

PluginState *X86FunctionMonitorState::factory(Plugin *p, DBAFExecutionState *s)
{
    X86FunctionMonitorState *ret = new X86FunctionMonitorState();
    ret->m_plugin = static_cast<X86FunctionMonitor*>(p);
    return ret;
}

X86FunctionMonitor::CallSignal* X86FunctionMonitorState::getCallSignal(
        uint64_t eip, uint64_t cr3)
{
    std::pair<CallDescriptorsMap::iterator, CallDescriptorsMap::iterator>
            range = m_callDescriptors.equal_range(eip);

    for(CallDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
        if(it->second.cr3 == cr3)
            return &it->second.signal;
    }


    CallDescriptor descriptor = { cr3, X86FunctionMonitor::CallSignal() };
    CallDescriptorsMap::iterator it =
            m_newCallDescriptors.insert(std::make_pair(eip, descriptor));

    return &it->second.signal;
}


void X86FunctionMonitorState::slotCall(DBAFExecutionState *state, uint64_t pc)
{
    target_ulong cr3 = state->getCr3();
    target_ulong eip = state->getEip();

    if (!m_newCallDescriptors.empty()) {
        m_callDescriptors.insert(m_newCallDescriptors.begin(), m_newCallDescriptors.end());
        m_newCallDescriptors.clear();
    }

    /* Issue signals attached to all calls (eip==-1 means catch-all) */
    if (!m_callDescriptors.empty()) {
        std::pair<CallDescriptorsMap::iterator, CallDescriptorsMap::iterator>
                range = m_callDescriptors.equal_range((uint64_t)-1);
        for(CallDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
            CallDescriptor cd = (*it).second;
            if(it->second.cr3 == (uint64_t)-1 || it->second.cr3 == cr3) {
                cd.signal.emit(state, this);
            }
        }
        if (!m_newCallDescriptors.empty()) {
            m_callDescriptors.insert(m_newCallDescriptors.begin(), m_newCallDescriptors.end());
            m_newCallDescriptors.clear();
        }
    }

    /* Issue signals attached to specific calls */
    if (!m_callDescriptors.empty()) {
        std::pair<CallDescriptorsMap::iterator, CallDescriptorsMap::iterator>
                range;

        range = m_callDescriptors.equal_range(eip);
        for(CallDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
            CallDescriptor cd = (*it).second;
            if(it->second.cr3 == (uint64_t)-1 || it->second.cr3 == cr3) {
                cd.signal.emit(state, this);
            }
        }
        if (!m_newCallDescriptors.empty()) {
            m_callDescriptors.insert(m_newCallDescriptors.begin(), m_newCallDescriptors.end());
            m_newCallDescriptors.clear();
        }
    }
}

/**
 *  A call handler can invoke this function to register a return handler.
 *  XXX: We assume that the passed execution state corresponds to the state in which
 *  this instance of FunctionMonitorState is used.
 */
void X86FunctionMonitorState::registerReturnSignal(DBAFExecutionState *state, X86FunctionMonitor::ReturnSignal &sig)
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
void X86FunctionMonitorState::slotRet(DBAFExecutionState *state, uint64_t pc, bool emitSignal)
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

void X86FunctionMonitorState::disconnect(const module &desc, CallDescriptorsMap &descMap)
{
    CallDescriptorsMap::iterator it = descMap.begin();
    while (it != descMap.end()) {
    	target_ulong moduleloadbase;
        uint64_t addr = (*it).first;
        const CallDescriptor &call = (*it).second;
        module* selected = m_plugin->m_monitor->VMI_find_module_by_pc((target_ulong)addr,call.cr3,&moduleloadbase);
        if (strcmp(selected->name, desc.name) == 0) {
            CallDescriptorsMap::iterator it2 = it;
            ++it;
            descMap.erase(it2);
        }else {
            ++it;
        }
    }
}

//Disconnect all address that belong to desc.
//This is useful to unregister all handlers when a module is unloaded
void X86FunctionMonitorState::disconnect(const module &desc)
{

    disconnect(desc, m_callDescriptors);
    disconnect(desc, m_newCallDescriptors);

    //XXX: we assume there are no more return descriptors active when the module is unloaded
}


} // namespace plugins
} // namespace dbaf
