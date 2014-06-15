/*
 * DBAF.h
 *
 *  Created on: 2014-5-16
 *      Author: wb
 */

#ifndef DBAF_H_
#define DBAF_H_
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "ConfigFile.h"
#include "Annotation.h"
#include <map>
template <typename T>
class _DBAFForeachContainer {
public:
    inline _DBAFForeachContainer(const T& t) : c(t), brk(0), i(c.begin()), e(c.end()) { }
    const T c; /* Compiler will remove the copying here */
    int brk;
    typename T::const_iterator i, e;
};

#define foreach(variable, container) \
for (_DBAFForeachContainer<__typeof__(container)> _container_(container); \
     !_container_.brk && _container_.i != _container_.e; \
     __extension__  ({ ++_container_.brk; ++_container_.i; })) \
    for (variable = *_container_.i;; __extension__ ({--_container_.brk; break;}))

#define foreachvector(_i, _b, _e) \
      for(typeof(_b) _i = _b, _i ## end = _e; _i != _i ## end;  ++ _i)
#define foreachset(_i, _b, _e) \
      for(typeof(_b) _i = _b, _i ## end = _e; _i != _i ## end;  ++ _i)

struct hexval {
    uint64_t value;
    int width;

    hexval(uint64_t _value, int _width=0) : value(_value), width(_width) {}
    hexval(void* _value, int _width=0): value((uint64_t)_value), width(_width) {}
};

inline std::ostream& operator<<(std::ostream& out, const hexval& h)
{
    out << std::hex << (h.value);
    return out;
}

namespace dbaf {
class ConfigFile;
class Annotation;
class PluginsFactory;
class Plugin;
class CorePlugin;
class CpuExitException
{
public:
	CpuExitException(){
		reason = 0;
		virtualAddress = 0;
	}
	CpuExitException(int _reason,uint64_t _virtualAddress){
		reason = _reason;
		virtualAddress = _virtualAddress;
	}
public:
	int reason;
	uint64_t virtualAddress;
};

class DBAF {
protected:
    ConfigFile* m_configFile;
    PluginsFactory* m_pluginsFactory;
	CorePlugin* m_corePlugin;
	std::vector<Plugin*> m_activePluginsList;
	typedef std::map<std::string, Plugin*> ActivePluginsMap;
	ActivePluginsMap m_activePluginsMap;

    Annotation* m_annotation;
    std::ofstream *debugstream;
    std::ofstream *errorstream;
    std::ofstream *warningstream;
    std::string m_outputDirectory;

public:
	virtual ~DBAF();
    explicit DBAF(int argc, char** argv,
                 const std::string& configFileName);
    /** Get output directory name */
    const std::string& getOutputDirectory() const { return m_outputDirectory; }
    void initOutputDirectory();
    std::ofstream* openOutputFile(const std::string &filename);

    /** Get configuration file */
    ConfigFile* getConfig() const { return m_configFile; }
    void initPlugins();
	/** Get plugin by name of functionName */
	Plugin* getPlugin(const std::string& name) const;
	/** Get Core plugin */
	inline CorePlugin* getCorePlugin() const {
		return m_corePlugin;
	}
    bool checkConfig();
    Annotation* getAnnotation() const { return m_annotation; }
    std::ofstream& getDebugstream() const {
		return *debugstream;
	}

    std::ofstream& getErrorstream() const {
		return *errorstream;
	}

    std::ofstream& getWarningstream() const {
		return *warningstream;
	}
    std::ofstream& getDebugStream() const {
		return *debugstream;
	}

    std::ofstream& getErrorStream() const {
		return *errorstream;
	}

    std::ofstream& getWarningStream() const {
		return *warningstream;
	}
};
struct DBAFTBExtra
{
    std::vector<void*> executionSignals;
};

} /* namespace dbaf */
#endif /* DBAF_H_ */
