extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"
extern CPUArchState *env;
}


#include <dbaf/DBAF.h>
#include <dbaf/ConfigFile.h>
#include "ModuleExecutionDetector.h"
#include <assert.h>
#include <sstream>

using namespace dbaf;
using namespace dbaf::plugins;

DBAF_DEFINE_PLUGIN(ModuleExecutionDetector,
                  "Plugin for monitoring module execution",
                  "ModuleExecutionDetector",
                  "Interceptor");

ModuleExecutionDetector::~ModuleExecutionDetector()
{

}

void ModuleExecutionDetector::initialize()
{
    m_Monitor = (OSMonitor*)dbaf()->getPlugin("Interceptor");
    assert(m_Monitor);

    m_Monitor->onModuleLoad.connect(
        fsigc::mem_fun(*this, &ModuleExecutionDetector::moduleLoadListener));

    m_Monitor->onModuleUnLoad.connect(
        fsigc::mem_fun(*this, &ModuleExecutionDetector::moduleUnloadListener));

    m_Monitor->onProcessExit.connect(
        fsigc::mem_fun(*this, &ModuleExecutionDetector::processUnloadListener));

    dbaf()->getCorePlugin()->onTranslateBlockStart.connect(
        fsigc::mem_fun(*this, &ModuleExecutionDetector::onTranslateBlockStart));

    dbaf()->getCorePlugin()->onTranslateBlockEnd.connect(
            fsigc::mem_fun(*this, &ModuleExecutionDetector::onTranslateBlockEnd));

    initializeConfiguration();
}

void ModuleExecutionDetector::initializeConfiguration()
{
    ConfigFile *cfg = dbaf()->getConfig();

    ConfigFile::string_list keyList = cfg->getListKeys(getConfigKey());

    if (keyList.size() == 0) {
        dbaf()->getWarningStream() <<  "ModuleExecutionDetector: no configuration keys!" << '\n';
    }

    foreachvector(it, keyList.begin(), keyList.end()) {
        if (*it == "trackAllModules"  || *it == "configureAllModules") {
            continue;
        }

        ModuleExecutionCfg d;
        std::stringstream s;
        s << getConfigKey() << "." << *it << ".";
        d.id = *it;

        bool ok = false;
        d.moduleName = cfg->getString(s.str() + "moduleName", "", &ok);
        if (!ok) {
            dbaf()->getWarningStream() << "You must specifiy " << s.str() + "moduleName" << '\n';
            exit(-1);
        }

        d.kernelMode = cfg->getBool(s.str() + "kernelMode", false, &ok);
        if (!ok) {
            dbaf()->getWarningStream() << "You must specifiy " << s.str() + "kernelMode" << '\n';
            exit(-1);
        }


        dbaf()->getDebugStream() << "ModuleExecutionDetector: " <<
                "id=" << d.id << " " <<
                "moduleName=" << d.moduleName << " " <<
                "context=" << d.context  << '\n';

        if (m_ConfiguredModulesName.find(d) != m_ConfiguredModulesName.end()) {
            dbaf()->getWarningStream() << "ModuleExecutionDetector: " <<
                    "module names must be unique!" << '\n';
            exit(-1);
        }


        if (m_ConfiguredModulesId.find(d) != m_ConfiguredModulesId.end()) {
            dbaf()->getWarningStream() << "ModuleExecutionDetector: " <<
                    "module ids must be unique!" << '\n';
            exit(-1);
        }

        m_ConfiguredModulesId.insert(d);
        m_ConfiguredModulesName.insert(d);
    }
}
/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

void ModuleExecutionDetector::moduleLoadListener(
    DBAFExecutionState* state,
    process* process, module* module)
{
    DECLARE_PLUGINSTATE(ModuleExecutionState, state);
    ModuleDescriptor d;
    d.cr3 = process->cr3;
    d.Size = module->size;
    d.Name = std::string(module->name);
    m_Monitor->VMI_find_module_by_name(module->name,d.cr3,&(d.LoadBase));
    //If module name matches the configured ones, activate.
    dbaf()->getDebugStream() << "ModuleExecutionDetector: " <<
            "Module "  << module->name << " loaded - "<< " Size=" << hexval(module->size);

    ModuleExecutionCfg cfg;
    cfg.moduleName = std::string(module->name);

    ConfiguredModulesByName::iterator it = m_ConfiguredModulesName.find(cfg);
    if (it != m_ConfiguredModulesName.end()) {
        if (plgState->exists(&d)) {
            dbaf()->getDebugStream() << " [ALREADY REGISTERED ID=" << (*it).id << "]" << '\n';
        }else {
            dbaf()->getDebugStream() << " [REGISTERING ID=" << (*it).id << "]" << '\n';
            plgState->loadDescriptor(d);
            onModuleLoad.emit(state, module);
        }
        return;
    }
    dbaf()->getDebugStream() << '\n';
}

void ModuleExecutionDetector::moduleUnloadListener(
    DBAFExecutionState* state, process* process, module* module)
{
    DECLARE_PLUGINSTATE(ModuleExecutionState, state);
    ModuleDescriptor d;
	d.cr3 = process->cr3;
	d.Size = module->size;
	d.Name = std::string(module->name);
	m_Monitor->VMI_find_module_by_name(module->name,d.cr3,&(d.LoadBase));
    dbaf()->getDebugStream() << "Module " << module->name << " is unloaded" << '\n';

    plgState->unloadDescriptor(d);
}



void ModuleExecutionDetector::processUnloadListener(
    DBAFExecutionState* state, process* process)
{
    DECLARE_PLUGINSTATE(ModuleExecutionState, state);

    dbaf()->getDebugStream() << "Process " << hexval(process->pid) << " is unloaded\n";

    plgState->unloadDescriptorsWithCr3(process->cr3);
}


//Check that the module id is valid
bool ModuleExecutionDetector::isModuleConfigured(const std::string &moduleId) const
{
    ModuleExecutionCfg cfg;
    cfg.id = moduleId;

    return m_ConfiguredModulesId.find(cfg) != m_ConfiguredModulesId.end();
}

const std::string *ModuleExecutionDetector::getModuleId(const module &desc) const
{
    ModuleExecutionCfg cfg;
    cfg.moduleName = std::string(desc.name);

    ConfiguredModulesByName::iterator it = m_ConfiguredModulesName.find(cfg);
    if (it == m_ConfiguredModulesName.end()) {
        return NULL;
    }
    return &(*it).id;
}

void ModuleExecutionDetector::onTranslateBlockStart(
    ExecutionSignal *signal,
    DBAFExecutionState *state,
    TranslationBlock *tb,
    uint64_t pc)
{
    const ModuleDescriptor *currentModule =
                getDescriptor(state, pc);

    if (currentModule) {
        onModuleTranslateBlockStart.emit(signal, state, *currentModule, tb, pc);
    }
}


void ModuleExecutionDetector::onTranslateBlockEnd(
        ExecutionSignal *signal,
        DBAFExecutionState* state,
        TranslationBlock *tb,
        uint64_t endPc,
        bool staticTarget,
        uint64_t targetPc)
{
    const ModuleDescriptor *currentModule =
            getDescriptor(state, endPc);

    if (currentModule) {
       onModuleTranslateBlockEnd.emit(signal, state, *currentModule, tb, endPc,
       staticTarget, targetPc);
    }

}

/**
 *  This returns the descriptor of the module that is currently being executed.
 *  This works only when tracking of all modules is activated.
 */
const ModuleDescriptor *ModuleExecutionDetector::getDescriptor(DBAFExecutionState* state, uint64_t pc) const
{
    DECLARE_PLUGINSTATE_CONST(ModuleExecutionState, state);
    uint64_t cr3 = m_Monitor->getCr3(pc);
    return plgState->getDescriptor(cr3, pc);
}


/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

ModuleExecutionState::ModuleExecutionState()
{
}

ModuleExecutionState::~ModuleExecutionState()
{
    foreachset(it, m_Descriptors.begin(), m_Descriptors.end()) {
        delete *it;
    }
}

ModuleExecutionState* ModuleExecutionState::clone() const
{
    ModuleExecutionState *ret = new ModuleExecutionState();

    foreachset(it, m_Descriptors.begin(), m_Descriptors.end()) {
        ret->m_Descriptors.insert(new ModuleDescriptor(**it));
    }

    return ret;
}

PluginState* ModuleExecutionState::factory(Plugin *p, DBAFExecutionState *state)
{
    ModuleExecutionState *s = new ModuleExecutionState();

    p->dbaf()->getDebugStream() << "Creating initial module execution state" << '\n';

    return s;
}

const ModuleDescriptor *ModuleExecutionState::getDescriptor(target_ulong cr3, target_ulong pc) const
{
    ModuleDescriptor d;
    d.cr3 = cr3;
    d.LoadBase = pc;
    d.Size = 1;
    DescriptorSet::iterator it = m_Descriptors.find(&d);
    if (it != m_Descriptors.end()) {
        return *it;
    }

    return NULL;
}

bool ModuleExecutionState::loadDescriptor(const ModuleDescriptor &desc)
{
    m_Descriptors.insert(new ModuleDescriptor(desc));
    return true;
}

void ModuleExecutionState::unloadDescriptor(const ModuleDescriptor &desc)
{
    ModuleDescriptor d;
    d.LoadBase = desc.LoadBase;
    d.cr3 = desc.cr3;
    d.Size = desc.Size;

    DescriptorSet::iterator it = m_Descriptors.find(&d);
    if (it != m_Descriptors.end()) {
        const ModuleDescriptor *md = *it;
        size_t s = m_Descriptors.erase(*it);
        assert(s == 1);
        delete md;
    }

}

void ModuleExecutionState::unloadDescriptorsWithCr3(target_ulong cr3)
{
    DescriptorSet::iterator it, it1;

    for (it = m_Descriptors.begin(); it != m_Descriptors.end(); ) {
        if ((*it)->cr3 != cr3) {
            ++it;
        }else {
            it1 = it;
            ++it1;

            const ModuleDescriptor *md = *it;
            m_Descriptors.erase(*it);
            delete md;

            it = it1;
        }
    }

}

bool ModuleExecutionState::exists(const ModuleDescriptor *desc) const
{
    bool ret;
    ret = m_Descriptors.find(desc) != m_Descriptors.end();
    return ret;
}
