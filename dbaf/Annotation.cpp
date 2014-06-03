extern "C" {
#include <qemu-common.h>
}
extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include "Annotation.h"
#include "DBAF_qemu.h"
#include <iostream>
#include <sstream>

namespace dbaf {

Annotation::Annotation(DBAF* dbaf) {
	m_dbaf = dbaf;
}
void Annotation::initialize()
{
   Lunar<LUAAnnotation>::Register(m_dbaf->getConfig()->getState());
}

Annotation::~Annotation()
{
}

void Annotation::invokeAnnotation(const char* fname)
{

	if (m_dbaf->getConfig()->isFunctionDefined(fname)) {
		lua_State *L = m_dbaf->getConfig()->getState();
		DBAFLUAExecutionState lua_dbaf_state(L);
		LUAAnnotation luaAnnotation(L);
		lua_getfield(L, LUA_GLOBALSINDEX, fname);
		Lunar<DBAFLUAExecutionState>::push(L, &lua_dbaf_state);
		Lunar<LUAAnnotation>::push(L, &luaAnnotation);
		lua_call(L, 2, 0);
		m_dbaf->getDebugStream() << "Annotation:  " << fname << " called." << '\n';
	}else{
		m_dbaf->getDebugStream() << "Annotation:  " << fname << "not defined." << '\n';
	}
}

const char LUAAnnotation::className[] = "LUAAnnotation";
Lunar<LUAAnnotation>::RegType LUAAnnotation::methods[] = {
  LUNAR_DECLARE_METHOD(LUAAnnotation, getValue),
  LUNAR_DECLARE_METHOD(LUAAnnotation, setValue),
  LUNAR_DECLARE_METHOD(LUAAnnotation, exit),
  {0,0}
};

LUAAnnotation::LUAAnnotation()
{
}
LUAAnnotation::LUAAnnotation(lua_State *lua)
{
}
LUAAnnotation::~LUAAnnotation()
{
}
int LUAAnnotation::setValue(lua_State *L) {
	std::string key = luaL_checkstring(L, 1);
	uint64_t value = luaL_checknumber(L, 2);
	m_storage[key] = value;
	g_dbaf->getDebugStream() << "LUAAnnotation: setValue " << key << "="
			<< value << '\n';
	return 0;
}

int LUAAnnotation::getValue(lua_State *L) {
	std::string key = luaL_checkstring(L, 1);
	uint64_t value = m_storage[key];
	g_dbaf->getDebugStream() << "LUAAnnotation: getValue " << key << "="
			<< value << '\n';
	lua_pushnumber(L, value);
	return 1;
}

int LUAAnnotation::exit(lua_State *L)
{
    g_dbaf->getDebugStream() <<"LUAAnnotation requested exit from DBAF\n";
    //make sure to call the stdlib exit() function
    exit(0);
    return 0;
}

} // namespace dbaf
