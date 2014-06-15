#ifndef DBAF_PLUGINS_X86FUNCTIONMONITOR_H
#define DBAF_PLUGINS_X86FUNCTIONMONITOR_H

#include <dbaf/Plugin.h>
#include <dbaf/plugins/CorePlugin.h>
#include <dbaf/DBAFExecutionState.h>
#include <dbaf/plugins/OSMonitor.h>

#include <tr1/unordered_map>

namespace dbaf {
namespace plugins {

class X86FunctionMonitorState;

class X86FunctionMonitor : public Plugin
{
    DBAF_PLUGIN
public:
    X86FunctionMonitor(DBAF* dbaf): Plugin(dbaf) {}

    typedef fsigc::signal<void, DBAFExecutionState*> ReturnSignal;
    typedef fsigc::signal<void, DBAFExecutionState*, X86FunctionMonitorState*> CallSignal;

    void initialize();

    CallSignal* getCallSignal(
            DBAFExecutionState *state,
            uint64_t eip, uint64_t cr3 = 0);

    void registerReturnSignal(DBAFExecutionState *state, X86FunctionMonitor::ReturnSignal &sig);

    void disconnect(DBAFExecutionState *state, const module &desc);
protected:
    void slotTranslateBlockEnd(ExecutionSignal*, DBAFExecutionState *state,
                               TranslationBlock *tb, uint64_t pc,
                               bool, uint64_t);

    void slotTranslateJumpStart(ExecutionSignal *signal,
                                DBAFExecutionState *state,
                                TranslationBlock*,
                                uint64_t, int jump_type);

    void slotCall(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc);
    void slotRet(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc);

protected:
    OSMonitor *m_monitor;

    friend class X86FunctionMonitorState;

};

class X86FunctionMonitorState : public PluginState
{

    struct CallDescriptor {
        uint64_t cr3;
        // TODO: add sourceModuleID and targetModuleID
        X86FunctionMonitor::CallSignal signal;
    };

    struct ReturnDescriptor {
        //DBAFExecutionState *state;
        uint64_t cr3;
        // TODO: add sourceModuleID and targetModuleID
        X86FunctionMonitor::ReturnSignal signal;
    };
    typedef std::tr1::unordered_multimap<uint64_t, CallDescriptor> CallDescriptorsMap;
    typedef std::tr1::unordered_multimap<uint64_t, ReturnDescriptor> ReturnDescriptorsMap;

    CallDescriptorsMap m_callDescriptors;
    CallDescriptorsMap m_newCallDescriptors;
    ReturnDescriptorsMap m_returnDescriptors;

    X86FunctionMonitor *m_plugin;

    /* Get a signal that is emitted on function calls. Passing eip = 0 means
       any function, and cr3 = 0 means any cr3 */
    X86FunctionMonitor::CallSignal* getCallSignal(uint64_t eip, uint64_t cr3 = 0);

    void slotCall(DBAFExecutionState *state, uint64_t pc);
    void slotRet(DBAFExecutionState *state, uint64_t pc, bool emitSignal);

    void disconnect(const module &desc, CallDescriptorsMap &descMap);
    void disconnect(const module &desc);

    bool exists(const CallDescriptorsMap &cdm,
                uint64_t eip, uint64_t cr3) const;
public:
    X86FunctionMonitorState();
    virtual ~X86FunctionMonitorState();
    virtual X86FunctionMonitorState* clone() const;
    static PluginState *factory(Plugin *p, DBAFExecutionState *s);

    void registerReturnSignal(DBAFExecutionState *s, X86FunctionMonitor::ReturnSignal &sig);

    friend class X86FunctionMonitor;
};


#define FUNCMON_REGISTER_RETURN(state, fns, func) \
{ \
    FunctionMonitor::ReturnSignal returnSignal; \
    returnSignal.connect(sigc::mem_fun(*this, &func)); \
    fns->registerReturnSignal(state, returnSignal); \
}

#define FUNCMON_REGISTER_RETURN_A(state, fns, func, ...) \
{ \
    FunctionMonitor::ReturnSignal returnSignal; \
    returnSignal.connect(sigc::bind(sigc::mem_fun(*this, &func), __VA_ARGS__)); \
    fns->registerReturnSignal(state, returnSignal); \
}

} // namespace plugins
} // namespace dbaf

#endif // DBAF_PLUGINS_X86FUNCTIONMONITOR_H
