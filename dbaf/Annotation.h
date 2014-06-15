#ifndef DBAF_PLUGINS_ANNOTATION_H
#define DBAF_PLUGINS_ANNOTATION_H

#include <ConfigFile.h>
#include "DBAF.h"
#include <map>
namespace dbaf {
class DBAF;
class LUAAnnotation;
class Annotation
{
protected:
	DBAF* m_dbaf;
public:
	Annotation(DBAF* dbaf);
	~Annotation();
	void initialize();
    void invokeAnnotation(const char* fname);
    friend class LUAAnnotation;
};

class LUAAnnotation
{
public:
    typedef std::map<std::string, uint64_t> Storage;

private:
    Storage m_storage;

public:
    static const char className[];
    static Lunar<LUAAnnotation>::RegType methods[];
    LUAAnnotation();
    LUAAnnotation(lua_State *lua);
    ~LUAAnnotation();

    int setValue(lua_State *L);
    int getValue(lua_State *L);

    int exit(lua_State *L);

    friend class Annotation;
};

} // namespace dbaf

#endif
