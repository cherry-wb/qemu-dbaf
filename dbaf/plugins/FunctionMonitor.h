#ifndef DBAF_PLUGINS_FUNCTIONMONITOR_H
#define DBAF_PLUGINS_FUNCTIONMONITOR_H

#include <tr1/unordered_map>
#include <dbaf/Plugin.h>
#include <dbaf/plugins/CorePlugin.h>
#include <dbaf/DBAFExecutionState.h>
#include <dbaf/plugins/OSMonitor.h>

#ifdef TARGET_ARM
#include "ArmFunctionMonitor.h"
#elif defined (TARGET_I386)
#include <dbaf/plugins/X86FunctionMonitor.h>
#endif

namespace dbaf {
namespace plugins {

/**
 * Note: the FunctionMonitor is target dependent, so the actual class
 * is a compile-time alias to the arch-specific version.
 */

#ifdef TARGET_ARM
typedef ARMFunctionMonitor FunctionMonitor;
typedef ARMFunctionMonitorState FunctionMonitorState;
#elif defined (TARGET_I386)
typedef X86FunctionMonitor FunctionMonitor;
typedef X86FunctionMonitorState FunctionMonitorState;
#endif

}
}

#endif // DBAF_PLUGINS_FUNCTIONMONITOR_H
