/*
 * X86HookManager.h
 *
 *  Created on: 2014-6-14
 *      Author: wb
 */

#ifndef X86HOOKMANAGER_H_
#define X86HOOKMANAGER_H_

#include <dbaf/Plugin.h>
#include <dbaf/plugins/CorePlugin.h>
#include <dbaf/DBAFExecutionState.h>
#include <dbaf/plugins/OSMonitor.h>

#include <tr1/unordered_map>

namespace dbaf {
namespace plugins {

class X86HookManagerState;

class X86HookManager : public Plugin
{
    DBAF_PLUGIN
public:
    X86HookManager(DBAF* dbaf): Plugin(dbaf) {
    	m_monitor = NULL;
    }

    typedef fsigc::signal<void, DBAFExecutionState*> ReturnSignal;
    typedef fsigc::signal<void, DBAFExecutionState*, X86HookManagerState*> CallSignal;

    void initialize();

    CallSignal* registerApiCallSignal(
            DBAFExecutionState *state,
            const char *mod, const char *func, uint64_t cr3 = 0);

    void registerReturnSignal(DBAFExecutionState *state, X86HookManager::ReturnSignal &sig);

    void disconnect(DBAFExecutionState *state, const module &desc);
protected:
    void slotTranslateBlockStart(ExecutionSignal*, DBAFExecutionState *state,
                               TranslationBlock *tb, uint64_t pc);

    void slotTranslateJumpStart(ExecutionSignal *signal,
                                DBAFExecutionState *state,
                                TranslationBlock*,
                                uint64_t, int jump_type);

    void slotCall(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc);
    void slotRet(DBAFExecutionState* state, uint64_t pc, uint64_t nextpc);
    void slotSymbolsResolved(DBAFExecutionState *state, module *mod);

protected:
    OSMonitor *m_monitor;

    friend class X86HookManagerState;

};

class X86HookManagerState : public PluginState
{

    struct ApiDescriptor {
        uint64_t cr3;
        string mod;
        string func;
        X86HookManager::CallSignal signal;
    };

    struct ReturnDescriptor {
        //DBAFExecutionState *state;
        uint64_t cr3;
        X86HookManager::ReturnSignal signal;
    };
    typedef std::tr1::unordered_multimap<uint64_t, ApiDescriptor> ApiDescriptorsMap;
    typedef std::tr1::unordered_multimap<uint64_t, ReturnDescriptor> ReturnDescriptorsMap;

    ApiDescriptorsMap m_callDescriptors;
    ApiDescriptorsMap m_newApiDescriptors;
    ApiDescriptorsMap m_unresolvedApiDescriptors;
    ReturnDescriptorsMap m_returnDescriptors;

    X86HookManager *m_plugin;

    /* Get a signal that is emitted on function calls. Passing eip = 0 means
       any function, and cr3 = 0 means any cr3 */
    X86HookManager::CallSignal* getApiCallSignal(const char *mod, const char *func, uint64_t cr3 = 0);

    void slotCall(DBAFExecutionState *state, uint64_t pc);
    void slotRet(DBAFExecutionState *state, uint64_t pc, bool emitSignal);

    void disconnect(const module &desc, ApiDescriptorsMap &descMap);
    void disconnect(const module &desc);

    bool exists(DBAFExecutionState *state, uint64_t eip);
public:
    X86HookManagerState();
    virtual ~X86HookManagerState();
    virtual X86HookManagerState* clone() const;
    static PluginState *factory(Plugin *p, DBAFExecutionState *s);

    void registerReturnSignal(DBAFExecutionState *s, X86HookManager::ReturnSignal &sig);

    void processSymbolsResolved(module* mod);

    friend class X86HookManager;
};


#define HOOK_RETURN(state, fns, func) \
{ \
    HookManager::ReturnSignal returnSignal; \
    returnSignal.connect(fsigc::mem_fun(*this, &func)); \
    fns->registerReturnSignal(state, returnSignal); \
}

#define HOOK_RETURN_A(state, fns, func, ...) \
{ \
    HookManager::ReturnSignal returnSignal; \
    returnSignal.connect(fsigc::bind(fsigc::mem_fun(*this, &func), __VA_ARGS__)); \
    fns->registerReturnSignal(state, returnSignal); \
}

} /* namespace plugins */
} /* namespace dbaf */
#endif /* X86HOOKMANAGER_H_ */
