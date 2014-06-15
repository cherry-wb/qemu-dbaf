/*
 * Kernel32Hooker.cpp
 *
 *  Created on: 2014-6-14
 *      Author: wb
 */

#include "Kernel32Hooker.h"
#include <dbaf/plugins/HookManager.h>
#include <dbaf/plugins/CorePlugin.h>
#include <dbaf/DBAF.h>
#include <dbaf/DBAF_qemu.h>
#include <dbaf/DBAFExecutionState.h>
#include <dbaf/DBAFSJLJ.h>
#include <vector>
#include <inttypes.h>

namespace dbaf {
namespace plugins {

using namespace std;

const Kernel32Hooker::WindowsApiHookArray Kernel32Hooker::s_hooks[] = {
	DECLARE_HOOKER_STRUC(Kernel32Hooker, kernel32.dll, CreateFileA),
	DECLARE_HOOKER_STRUC(Kernel32Hooker, kernel32.dll, GetCommandLineA),
};
DBAF_DEFINE_PLUGIN(Kernel32Hooker, "DBAF Kernel32Hooker functionality", "Kernel32Hooker", "Interceptor", "HookManager",);

Kernel32Hooker::~Kernel32Hooker() {
}

void Kernel32Hooker::initialize() {
	dbaf()->getDebugStream()<< "Kernel32Hooker::initialize" << endl;
	m_hookManager = static_cast<HookManager*>(dbaf()->getPlugin("HookManager"));
	m_Monitor =  static_cast<OSMonitor*>(dbaf()->getPlugin("Interceptor"));
	m_Monitor->onProcessCreate.connect(
            fsigc::mem_fun(*this, &Kernel32Hooker::slotProcessCreate));
	m_Monitor->onModuleLoad.connect(
            fsigc::mem_fun(*this, &Kernel32Hooker::slotModuleLoad));
}
void  Kernel32Hooker::slotModuleLoad(DBAFExecutionState* state, process* proc, module* mod){
	if (strcmp(mod->name, "kernel32.dll") == 0) {
		unsigned elemCount = sizeof(Kernel32Hooker::s_hooks)
				/ sizeof(WindowsApiHooker<CallBack> );
		for (unsigned i = 0; i < elemCount; ++i) {
			X86HookManager::CallSignal* signal =
					m_hookManager->registerApiCallSignal(state,
							s_hooks[i].modname, s_hooks[i].funcname, proc->cr3);
			signal->connect(fsigc::mem_fun(*this, s_hooks[i].function));
		}
	}
}
void Kernel32Hooker::slotProcessCreate(DBAFExecutionState* state, process* proc){

}
//if(m_hookManager){
void Kernel32Hooker::CreateFileA(DBAFExecutionState* state,
		HookManagerState *fns) {
		uint32_t lpFileName = 0;    // 指向文件名的指针
		uint32_t dwCreationDisposition = 0;    // 如何创建
		uint32_t dwFlagsAndAttributes = 0;    // 文件属性
		dbaf()->getDebugStream() << "CreateFileA called. " << '\n';
		HOOK_RETURN_A(state, fns, Kernel32Hooker::CreateFileARet,
				lpFileName, dwCreationDisposition, dwFlagsAndAttributes);
}

void Kernel32Hooker::CreateFileARet(DBAFExecutionState* state,
		uint32_t lpFileName,   // 指向文件名的指针
		uint32_t dwCreationDisposition,   // 如何创建
		uint32_t dwFlagsAndAttributes   // 文件属性
		) {
	dbaf()->getDebugStream() << "CreateFileA ret. " << '\n';
}
void Kernel32Hooker::GetCommandLineA(DBAFExecutionState* state,
		HookManagerState *fns) {
	dbaf()->getDebugStream() << "GetCommandLineA called. " << '\n';
	HOOK_RETURN(state, fns, Kernel32Hooker::GetCommandLineARet);
}

void Kernel32Hooker::GetCommandLineARet(DBAFExecutionState* state) {
	dbaf()->getDebugStream() << "GetCommandLineA ret. " << '\n';
}
} /* namespace plugins */
} /* namespace dbaf */
