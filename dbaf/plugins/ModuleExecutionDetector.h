#ifndef __MODULE_EXECUTION_DETECTOR_H_

#define __MODULE_EXECUTION_DETECTOR_H_

#include <dbaf/Plugin.h>
#include <dbaf/plugins/CorePlugin.h>
#include <dbaf/plugins/OSMonitor.h>

#include <inttypes.h>
#include "OSMonitor.h"


namespace dbaf {
namespace plugins {


/**
 *  Module description from configuration file
 */
struct ModuleExecutionCfg
{
    std::string id;
    std::string moduleName;
    bool kernelMode;
    std::string context;
};

struct ModuleExecCfgById
{
    bool operator()(const ModuleExecutionCfg &d1,
        const ModuleExecutionCfg &d2) const {
        //return d1.compare(d2.id) < 0;
        return d1.id < d2.id;
    }
};

struct ModuleExecCfgByName
{
    bool operator()(const ModuleExecutionCfg &d1,
        const ModuleExecutionCfg &d2) const {
        return d1.moduleName < d2.moduleName;
    }
};

typedef std::set<ModuleExecutionCfg, ModuleExecCfgById> ConfiguredModulesById;
typedef std::set<ModuleExecutionCfg, ModuleExecCfgByName> ConfiguredModulesByName;

struct ModuleDescriptor
{
  target_ulong  cr3;

  //The name of the module (eg. MYAPP.EXE or DRIVER.SYS)
  std::string Name;

  //Where the the preferred load address of the module.
  //This is defined by the linker and put into the header of the image.
  target_ulong NativeBase;

  //Where the image of the module was actually loaded by the OS.
  target_ulong LoadBase;

  //The size of the image of the module
  uint64_t Size;

  //The entry point of the module
  uint64_t EntryPoint;

  ModuleDescriptor() {
    cr3 = 0;
    NativeBase = 0;
    LoadBase = 0;
    Size = 0;
    EntryPoint = 0;
  }

  bool Contains(target_ulong RunTimeAddress) const {
	  target_ulong RVA = RunTimeAddress - LoadBase;
    return RVA < Size;
  }

  target_ulong ToRelative(target_ulong RunTimeAddress) const {
	  target_ulong RVA = RunTimeAddress - LoadBase;
    return RVA;
  }

  target_ulong ToNativeBase(target_ulong RunTimeAddress) const {
    return RunTimeAddress - LoadBase + NativeBase;
  }

  target_ulong ToRuntime(target_ulong NativeAddress) const {
    return NativeAddress - NativeBase + LoadBase;
  }

  bool EqualInsensitive(const char *Name) const{
	return strcasecmp(this->Name.c_str(), Name) == 0;
  }

  struct ModuleByLoadBase {
    bool operator()(const struct ModuleDescriptor& s1,
      const struct ModuleDescriptor& s2) const {
        if (s1.cr3 == s2.cr3) {
            return s1.LoadBase + s1.Size <= s2.LoadBase;
        }
        return s1.cr3 < s2.cr3;
    }

    bool operator()(const struct ModuleDescriptor* s1,
      const struct ModuleDescriptor* s2) const {
        if (s1->cr3 == s2->cr3) {
            return s1->LoadBase + s1->Size <= s2->LoadBase;
        }
        return s1->cr3 < s2->cr3;
    }
  };

  struct ModuleByName {
    bool operator()(const struct ModuleDescriptor& s1,
      const struct ModuleDescriptor& s2) const {
        return s1.Name < s2.Name;
    }

    bool operator()(const struct ModuleDescriptor* s1,
      const struct ModuleDescriptor* s2) const {
        return s1->Name < s2->Name;
    }
  };

  void Print(std::ostream &os) const {
    os << "Name=" << Name  <<
      " NativeBase=" << hexval(NativeBase) << " LoadBase=" << hexval(LoadBase) <<
      " Size=" << hexval(Size) <<
      " EntryPoint=" << hexval(EntryPoint) << '\n';
  }

  typedef std::set<struct ModuleDescriptor, ModuleByLoadBase> MDSet;
};

class ModuleExecutionDetector:public Plugin
{
    DBAF_PLUGIN

public:
    /** Signal that is emitted on beginning and end of code generation
        for each translation block belonging to the module.
    */
    fsigc::signal<void, ExecutionSignal*,
            DBAFExecutionState*,
            const ModuleDescriptor &,
            TranslationBlock*,
            uint64_t /* block PC */>
            onModuleTranslateBlockStart;

    /** Signal that is emitted upon end of translation block of the module */
    fsigc::signal<void, ExecutionSignal*,
            DBAFExecutionState*,
            const ModuleDescriptor &,
            TranslationBlock*,
            uint64_t /* ending instruction pc */,
            bool /* static target is valid */,
            uint64_t /* static target pc */>
            onModuleTranslateBlockEnd;

    /** This filters module loads passed by OSInterceptor */
    fsigc::signal<void,
       DBAFExecutionState*,
       module*
    >onModuleLoad;

private:
    OSMonitor *m_Monitor;

    ConfiguredModulesById m_ConfiguredModulesId;
    ConfiguredModulesByName m_ConfiguredModulesName;

    void initializeConfiguration();
    bool opAddModuleConfigEntry(DBAFExecutionState *state);

    void onCustomInstruction(
            DBAFExecutionState *state,
            uint64_t operand
            );

    void onTranslateBlockStart(ExecutionSignal *signal,
        DBAFExecutionState *state,
        TranslationBlock *tb,
        uint64_t pc);

    void onTranslateBlockEnd(
        ExecutionSignal *signal,
        DBAFExecutionState* state,
        TranslationBlock *tb,
        uint64_t endPc,
        bool staticTarget,
        uint64_t targetPc);


    void moduleLoadListener(
        DBAFExecutionState* state,
        process* process,
        module* module
    );

    void moduleUnloadListener(
        DBAFExecutionState* state,
        process* process,
        module* desc);

    void processUnloadListener(
        DBAFExecutionState* state,
        process* process);

public:
    ModuleExecutionDetector(DBAF* dbaf): Plugin(dbaf) {}
    virtual ~ModuleExecutionDetector();

    void initialize();

    const ModuleDescriptor *getDescriptor(DBAFExecutionState* state, uint64_t pc) const;
    const std::string *getModuleId(const module &desc) const;

    const ConfiguredModulesById &getConfiguredModulesById() const {
        return m_ConfiguredModulesId;
    }

    bool isModuleConfigured(const std::string &moduleId) const;

    friend class ModuleExecutionState;
};


class ModuleExecutionState:public PluginState
{
 typedef std::set<const ModuleDescriptor*, ModuleDescriptor::ModuleByLoadBase> DescriptorSet;
private:
    DescriptorSet m_Descriptors;

    const ModuleDescriptor *getDescriptor(target_ulong cr3, target_ulong pc) const;
	bool loadDescriptor(const ModuleDescriptor &desc);
	void unloadDescriptor(const ModuleDescriptor &desc);
	void unloadDescriptorsWithCr3(target_ulong cr3);
	bool exists(const ModuleDescriptor *desc) const;

public:

    ModuleExecutionState();
    virtual ~ModuleExecutionState();
    virtual ModuleExecutionState* clone() const;
    static PluginState *factory(Plugin *p, DBAFExecutionState *s);

    friend class ModuleExecutionDetector;
};

} // namespace plugins
} // namespace dbaf

#endif
