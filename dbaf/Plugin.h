/*
 * DBAF Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Currently maintained by:
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *
 * All contributors are listed in the DBAF-AUTHORS file.
 */

#ifndef DBAF_PLUGIN_H
#define DBAF_PLUGIN_H

#include <string>
#include <vector>
//#include <tr1/unordered_map>
#include <map>
#include <set>
#include <dbaf/signals/signals.h>

namespace dbaf {

class DBAF;
struct PluginInfo;
class PluginState;
class DBAFExecutionState;

class Plugin : public fsigc::trackable{
private:
	DBAF* m_dbaf;
protected:
    mutable PluginState *m_CachedPluginState;
    mutable DBAFExecutionState *m_CachedPluginDBAFState;
    bool isenabled;
public:
    Plugin(DBAF* dbaf) : m_dbaf(dbaf),m_CachedPluginState(NULL),
        m_CachedPluginDBAFState(NULL),isenabled(false) {}

    virtual ~Plugin() {}

    virtual void Enable(){
    	isenabled = true;
    }
    virtual void Disable(){
    	isenabled = false;
    }
    /** Return associated DBAF instance. */
    DBAF* dbaf() { return m_dbaf; }
    const DBAF* dbaf() const { return m_dbaf; }

    /** Initialize plugin. This function is called on initialization
        after all plugin instances have already been instantiated. */
    virtual void initialize();

    /** Return PluginInfo for this class. Defined by DBAF_PLUGIN macro */
    virtual const PluginInfo* getPluginInfo() const = 0;

    /** Return configuration key for this plugin */
    const std::string& getConfigKey() const;

    PluginState *getPluginState(DBAFExecutionState *s, PluginState* (*f)(Plugin *, DBAFExecutionState *)) const;

    void refresh() {
        m_CachedPluginDBAFState = NULL;
        m_CachedPluginState = NULL;
    }
};

#define DECLARE_PLUGINSTATE_P(plg, c, execstate) \
    c *plgState = static_cast<c*>(plg->getPluginState(execstate, &c::factory))

#define DECLARE_PLUGINSTATE(c, execstate) \
    c *plgState = static_cast<c*>(getPluginState(execstate, &c::factory))

#define DECLARE_PLUGINSTATE_N(c, name, execstate) \
    c *name = static_cast<c*>(getPluginState(execstate, &c::factory))

#define DECLARE_PLUGINSTATE_CONST(c, execstate) \
    const c *plgState = static_cast<c*>(getPluginState(execstate, &c::factory))

#define DECLARE_PLUGINSTATE_NCONST(c, name, execstate) \
    const c *name = static_cast<c*>(getPluginState(execstate, &c::factory))

class PluginState
{
public:
    virtual ~PluginState() {};
    virtual PluginState *clone() const = 0;
};


struct PluginInfo {
    /** Unique name of the plugin */
    std::string name;

    /** Human-readable description of the plugin */
    std::string description;

    /** Name of a plugin function (only one plugin is allowed for each function) */
    std::string exposedName;

    /** Dependencies of this plugin */
    std::vector<std::string> dependencies;

    /** Configuration key for this plugin */
    std::string configKey;

    /** A function to create a plugin instance */
    Plugin* (*instanceCreator)(DBAF*);
};

//typedef std::tr1::unordered_map<std::string, const PluginInfo*> PluginMap;

class PluginsFactory {
private:
    typedef std::map<std::string, const PluginInfo*> PluginsMap;
    PluginsMap m_pluginsMap;

    std::vector<const PluginInfo*> m_pluginsList;

public:
    PluginsFactory();

    void registerPlugin(const PluginInfo* pluginInfo);
    //当从单独的so文件加载后，需要调用这个方法，刷新仓库
    void refresh();
    const std::vector<const PluginInfo*> &getPluginInfoList() const;
    const PluginInfo* getPluginInfo(const std::string& name) const;

    Plugin* createPlugin(DBAF* dbaf, const std::string& name) const;
};


class CompiledPlugin {
public:
    typedef std::set<const PluginInfo *> CompiledPlugins;

private:
    static CompiledPlugins *s_compiledPlugins;

    CompiledPlugin();
public:
    CompiledPlugin(const PluginInfo *info) {
        if (!s_compiledPlugins) {
            s_compiledPlugins = new CompiledPlugins();
        }
        s_compiledPlugins->insert(info);
    }
    static void removePlugin(const PluginInfo * plg) {
    	 if (s_compiledPlugins) {
    		 if(s_compiledPlugins->find(plg) != s_compiledPlugins->end())
    		 	 s_compiledPlugins->erase(plg);
    	 }
     }
    static CompiledPlugins* getPlugins() {
        return s_compiledPlugins;
    }
};


/** Should be put at the beginning of any DBAF plugin */
#define DBAF_PLUGIN                                                                 \
    private:                                                                       \
        static const char s_pluginDeps[][64];                                      \
        static const PluginInfo s_pluginInfo;                                      \
    public:                                                                        \
        virtual const PluginInfo* getPluginInfo() const { return &s_pluginInfo; }  \
        static  const PluginInfo* getPluginInfoStatic() { return &s_pluginInfo; }  \
    private:

/** Defines an DBAF plugin. Should be put in a cpp file.
    NOTE: use DBAF_NOOP from Utils.h to pass multiple dependencies */
#define DBAF_DEFINE_PLUGIN(className, description, exposedName, ...)      \
    const char className::s_pluginDeps[][64] = { __VA_ARGS__ };                   \
    const PluginInfo className::s_pluginInfo = {                                   \
        #className, description, exposedName,                                     \
        std::vector<std::string>(className::s_pluginDeps, className::s_pluginDeps  \
            + sizeof(className::s_pluginDeps)/sizeof(className::s_pluginDeps[0])), \
         "pluginsConfig['" #className "']",                                        \
        _pluginCreatorHelper<className>                                            \
    }; \
    static CompiledPlugin s_##className(className::getPluginInfoStatic());

template<class C>
Plugin* _pluginCreatorHelper(DBAF* dbaf) { return new C(dbaf); }

inline const std::string& Plugin::getConfigKey() const {
    return getPluginInfo()->configKey;
}

} // namespace dbaf

#endif // DBAF_PLUGIN_H
