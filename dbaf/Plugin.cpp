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
