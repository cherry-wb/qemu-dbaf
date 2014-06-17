/*
 * DBAF.cpp
 *
 *  Created on: 2014-5-16
 *      Author: wb
 */

#include "DBAF.h"
#include "DBAFExecutionState.h"
#include "Plugin.h"
#include "plugins/CorePlugin.h"
#include <stdio.h>
#include <stdlib.h>
#include <dbaf/DBAF_qemu.h>
#include <dbaf/DBAF_main.h>
#include <cstring>
#include <stddef.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sstream>
#include <string>
#include <iostream>
#include <errno.h>
#define ACCESS access
#define MKDIR(a) mkdir((a),0755)

namespace dbaf {

using namespace std;

DBAF::DBAF(int argc, char** argv,const std::string &configFileName)
{
	g_dbaf = this;
    m_configFile = new dbaf::ConfigFile(configFileName);
    initOutputDirectory();
    checkConfig();
    initPlugins();
   //
    m_annotation = new Annotation(this);
    m_annotation->initialize();
    m_annotation->invokeAnnotation("config_parsed");
}
DBAF::~DBAF() {
	delete m_configFile;
	delete m_annotation;

	debugstream->flush();
	errorstream->flush();
	warningstream->flush();

	debugstream->close();
	errorstream->close();
	warningstream->close();
	delete debugstream;
	delete errorstream;
	delete warningstream;
}

bool DBAF::checkConfig() {
	//check whether all params are setted
	ConfigFile::string_list pollingEntries = m_configFile->getListKeys("dbaf");
	if (pollingEntries.size() == 0) {
	} else {
		if (debugstream)
			*debugstream << "global config start" << endl;
		foreachvector(it, pollingEntries.begin(), pollingEntries.end())
		{
			std::stringstream ss1;
			ss1 << "dbaf" << "." << *it;
			std::string value = m_configFile->getString(ss1.str());
			if (debugstream)
				*debugstream << ss1.str().c_str() << "=" << value.c_str()
						<< endl;
		}
		if (debugstream)
			*debugstream << "global config end" << endl;
	}
	return true;
}

void DBAF::initOutputDirectory() {
	char buf[512];
	buf[511]='\0';
	char* returnbuf = NULL;
	returnbuf = getcwd(buf, sizeof(buf));
	if(returnbuf == NULL){
		perror("ERROR: could not get the current working dir");
		exit(1);
	}
	std::string cwd(buf);
	cwd = cwd+"/";
    for (int i = 0; ; i++) {
        std::ostringstream dirName;
        dirName << "dbaf-out-" << i;
        std::string dirPath(cwd);
        dirPath = dirPath + dirName.str();

        bool exists = false;
        if(access(dirPath.c_str(),F_OK) == 0)
        	exists = true;

        if(!exists) {
            m_outputDirectory = dirPath + "/";
            mkdir(dirName.str().c_str(),0755);
            break;
        }
    }
    std::cout << "DBAF: output directory = \"" << m_outputDirectory << "\"\n";
  #ifndef _WIN32
	  std::string lastpath;
	  lastpath =cwd + "dbaf-last";

	  if ((unlink(lastpath.c_str()) < 0) && (errno != ENOENT)) {
		  perror("ERROR: Cannot unlink dbaf-last");
		  exit(1);
	  }

	  if (symlink(m_outputDirectory.c_str(), lastpath.c_str()) < 0) {
		  perror("ERROR: Cannot make symlink dbaf-last");
		  exit(1);
	  }
  #endif
	debugstream = openOutputFile("debug.txt");
	errorstream = openOutputFile("error.txt");
	warningstream = openOutputFile("warning.txt");
	*debugstream << "Output dir: " << m_outputDirectory.c_str() << endl;
}

Plugin* DBAF::getPlugin(const std::string& name) const
{
    ActivePluginsMap::const_iterator it = m_activePluginsMap.find(name);
    if(it != m_activePluginsMap.end())
        return const_cast<Plugin*>(it->second);
    else
        return NULL;
}
void DBAF::initPlugins()
{
	/*
plugins = {
	"simplebundle"
}
plugins.simplebundle ={
		so_path = "/home/wb/workspace/simplebundle/simplebundle.so",--如果这个参数不为空，且文件存在，那么系统将首先将库文件加载进内存，并调用其init_bundle函数
}
	 */
    m_pluginsFactory = new PluginsFactory();
    m_corePlugin = dynamic_cast<CorePlugin*>(
            m_pluginsFactory->createPlugin(this, "CorePlugin"));
    m_activePluginsList.push_back(m_corePlugin);
    m_activePluginsMap.insert(
            make_pair(m_corePlugin->getPluginInfo()->name, m_corePlugin));
    if(!m_corePlugin->getPluginInfo()->exposedName.empty())
        m_activePluginsMap.insert(
            make_pair(m_corePlugin->getPluginInfo()->exposedName, m_corePlugin));
    vector<string> pluginNames = getConfig()->getStringList("plugins");

    //加载进内存
    foreach(const string& pluginName, pluginNames) {
    	 string pathkey("pluginsConfig."+pluginName+".so_path");
    	 string so_path = getConfig()->getString(pathkey,"");
    	 if(so_path.length() > 2){//加载进内存，如果一个多个插件放在一个so中，则只加载进内存一次
    		do_load_bundle_internal(default_mon,so_path.c_str());
    	 }
    }
    m_pluginsFactory->refresh();
    //获取描述信息，初始化
    /* Check and load plugins */
    foreach(const string& pluginName, pluginNames) {
        const PluginInfo* pluginInfo = m_pluginsFactory->getPluginInfo(pluginName);
        if(!pluginInfo) {
            std::cerr << "ERROR: plugin '" << pluginName
                      << "' does not exist in this DBAF installation" << '\n';
            exit(1);
        } else if(getPlugin(pluginInfo->name)) {
            std::cerr << "ERROR: plugin '" << pluginInfo->name
                      << "' was already loaded "
                      << "(is it enabled multiple times ?)" << '\n';
            exit(1);
        } else if(!pluginInfo->exposedName.empty() &&
                    getPlugin(pluginInfo->exposedName)) {
            std::cerr << "ERROR: plugin '" << pluginInfo->name
                      << "' with function '" << pluginInfo->exposedName
                      << "' can not be loaded because" << '\n'
                      <<  "    this function is already provided by '"
                      << getPlugin(pluginInfo->exposedName)->getPluginInfo()->name
                      << "' plugin" << '\n';
            exit(1);
        } else {
            Plugin* plugin = m_pluginsFactory->createPlugin(this, pluginName);
            m_activePluginsList.push_back(plugin);
            m_activePluginsMap.insert(
                    make_pair(plugin->getPluginInfo()->name, plugin));
            if(!plugin->getPluginInfo()->exposedName.empty())
                m_activePluginsMap.insert(
                    make_pair(plugin->getPluginInfo()->exposedName, plugin));
        }
    }
    /* Check dependencies */
    foreach(Plugin* p, m_activePluginsList) {
        foreach(const string& name, p->getPluginInfo()->dependencies) {
            if(!getPlugin(name)) {
                std::cerr << "ERROR: plugin '" << p->getPluginInfo()->name
                          << "' depends on plugin '" << name
                          << "' which is not enabled in config" << '\n';
                exit(1);
            }
        }
    }
    /* Initialize plugins */
    foreach(Plugin* p, m_activePluginsList) {
        p->initialize();
    }
}

std::ofstream* DBAF::openOutputFile(const std::string& filename) {
	return new ofstream((m_outputDirectory + filename).c_str(),std::ios::app);
}


} /* namespace dbaf */

/******************************/
/* Functions called from QEMU */

extern "C" {

DBAF* g_dbaf = NULL;
DBAFExecutionState* g_dbaf_state = NULL;

uint64_t g_selected_cr3 = 0;

DBAF* DBAF_initialize(int argc, char** argv, const char* s2e_config_file) {
	return new DBAF(argc, argv, s2e_config_file ? s2e_config_file : "");
}
DBAFExecutionState* DBAF_state_initialize() {
	return new DBAFExecutionState();
}
void DBAF_close(DBAF *dbaf) {
	delete dbaf;
}
void dbaf_tb_alloc(TranslationBlock *tb)
{
    tb->dbaf_extra = new DBAFTBExtra;
    /* Push one copy of a signal to use it as a cache */
    tb->dbaf_extra->executionSignals.push_back(new dbaf::ExecutionSignal);
}

void dbaf_tb_free(TranslationBlock *tb) {
	if (tb && tb->dbaf_extra) {
		foreach(void* s, tb->dbaf_extra->executionSignals){
			delete static_cast<dbaf::ExecutionSignal*>(s);
		}
	}
}

} // extern "C"
