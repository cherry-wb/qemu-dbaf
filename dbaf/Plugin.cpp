#include <dbaf/Plugin.h>
#include <dbaf/DBAF.h>
#include <dbaf/DBAFExecutionState.h>

#include <algorithm>
#include <assert.h>

namespace dbaf {

using namespace std;

CompiledPlugin::CompiledPlugins* CompiledPlugin::s_compiledPlugins = NULL;

void Plugin::initialize()
{
	Enable();
}

PluginState *Plugin::getPluginState(DBAFExecutionState *s, PluginStateFactory f) const
{
    if (m_CachedPluginDBAFState == s) {
        return m_CachedPluginState;
    }
    m_CachedPluginState = s->getPluginState(const_cast<Plugin*>(this), f);
    m_CachedPluginDBAFState = s;
    return m_CachedPluginState;
}

PluginsFactory::PluginsFactory()
{
    CompiledPlugin::CompiledPlugins *plugins = CompiledPlugin::getPlugins();

    foreachset(it, plugins->begin(), plugins->end()) {
        registerPlugin(*it);
    }
}
void PluginsFactory::refresh(){
	m_pluginsList.clear();
	m_pluginsMap.clear();
    CompiledPlugin::CompiledPlugins *plugins = CompiledPlugin::getPlugins();
    foreachset(it, plugins->begin(), plugins->end()) {
        registerPlugin(*it);
    }
}
void PluginsFactory::registerPlugin(const PluginInfo* pluginInfo)
{
    if(m_pluginsMap.find(pluginInfo->name) != m_pluginsMap.end()){
    	//已存在
    }else{
		m_pluginsList.push_back(pluginInfo);
		m_pluginsMap.insert(make_pair(pluginInfo->name, pluginInfo));
    }
}

const vector<const PluginInfo*>& PluginsFactory::getPluginInfoList() const
{
    return m_pluginsList;
}

const PluginInfo* PluginsFactory::getPluginInfo(const string& name) const
{
    PluginsMap::const_iterator it = m_pluginsMap.find(name);

    if(it != m_pluginsMap.end())
        return it->second;
    else
        return NULL;
}

Plugin* PluginsFactory::createPlugin(DBAF* dbaf, const string& name) const
{
    const PluginInfo* pluginInfo = getPluginInfo(name);
    dbaf->getDebugStream() << "Creating plugin " << name << "\n";
    if(pluginInfo)
        return pluginInfo->instanceCreator(dbaf);
    else
        return NULL;
}

} // namespace dbaf
