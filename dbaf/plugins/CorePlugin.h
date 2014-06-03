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
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the DBAF-AUTHORS file.
 */

#ifndef DBAF_CORE_PLUGIN_H
#define DBAF_CORE_PLUGIN_H

#include <dbaf/Plugin.h>

#include <dbaf/signals/signals.h>
#include <vector>
#include <inttypes.h>
extern "C" {
#include <cpu.h>
}
extern "C" {
typedef struct TranslationBlock TranslationBlock;
void helper_dbaf_tcg_execution_handler(CPUArchState* env,void* signal, target_ulong pc, target_ulong nextpc);//
void helper_dbaf_tcg_custom_instruction_handler(CPUArchState* env,uint64_t arg);
}
namespace dbaf {

class DBAFExecutionState;

/** A type of a signal emitted on instruction execution. Instances of this signal
    will be dynamically created and destroyed on demand during translation. */
typedef fsigc::signal<void, DBAFExecutionState*, uint64_t /* pc */,uint64_t /* nextpc */> ExecutionSignal;


class CorePlugin : public Plugin {
    DBAF_PLUGIN

private:

public:
    CorePlugin(DBAF* dbaf): Plugin(dbaf) {
    }
    void initialize();
    /** Signal that is emitted on beginning and end of code generation
        for each QEMU translation block.
    */
    fsigc::signal<void, ExecutionSignal*,
            DBAFExecutionState*,
            TranslationBlock*,
            uint64_t /* block PC */>
            onTranslateBlockStart;

    /** Signal that is emitted upon end of translation block. it can be emitted multi-times for one block if has multi-outbranchs*/
    fsigc::signal<void, ExecutionSignal*,
            DBAFExecutionState*,
            TranslationBlock*,
            uint64_t /* ending instruction pc */,
            bool /* static target is valid */,
            uint64_t /* static target pc */>
            onTranslateBlockEnd;

    
    /** Signal that is emitted on code generation for each instruction */
    fsigc::signal<void, ExecutionSignal*,
            DBAFExecutionState*,
            TranslationBlock*,
            uint64_t /* instruction PC */>
            onTranslateInstructionStart, onTranslateInstructionEnd;

    /**
     *  Triggered *after* each instruction is translated to notify
     *  plugins of which registers are used by the instruction.
     *  Each bit of the mask corresponds to one of the registers of
     *  the architecture (e.g., R_EAX, R_ECX, etc).
     */
    fsigc::signal<void,
                 ExecutionSignal*,
                 DBAFExecutionState* /* current state */,
                 TranslationBlock*,
                 uint64_t /* program counter of the instruction */,
                 uint64_t /* registers read by the instruction */,
                 uint64_t /* registers written by the instruction */,
                 bool /* instruction accesses memory */>
          onTranslateRegisterAccessEnd;

    /** Signal that is emitted on code generation for each jump instruction */
    fsigc::signal<void, ExecutionSignal*,
            DBAFExecutionState*,
            TranslationBlock*,
            uint64_t /* instruction PC */,
            int /* jump_type */>
            onTranslateJumpStart;

    /** Signal that is emitted upon exception */
    fsigc::signal<void, DBAFExecutionState*,
            unsigned /* Exception Index */,
            uint64_t /* pc */>
            onException;

    /** Signal that is emitted when custom opcode is detected */
    fsigc::signal<void, DBAFExecutionState*,
            uint64_t  /* arg */
            >
            onCustomInstruction;

    /** Signal that is emitted upon TLB miss */
    fsigc::signal<void, DBAFExecutionState*, uint64_t, bool> onTlbMiss;

    /** Signal that is emitted upon page fault */
    fsigc::signal<void, DBAFExecutionState*, uint64_t, bool> onPageFault;

    /**
     * The current execution privilege level was changed (e.g., kernel-mode=>user-mode)
     * previous and current are privilege levels. The meaning of the value may
     * depend on the architecture.
     */
    fsigc::signal<void,
                 DBAFExecutionState* /* current state */,
                 unsigned /* previous level */,
                 unsigned /* current level */>
          onPrivilegeChange;

    /**
     * The current page directory was changed.
     * This may occur, e.g., when the OS swaps address spaces.
     * The addresses correspond to physical addresses.
     */
    fsigc::signal<void,
                 DBAFExecutionState* /* current state */,
                 uint64_t /* previous page directory base */,
                 uint64_t /* current page directory base */>
          onPageDirectoryChange;

    /**
     * DBAF completed initialization and is about to enter
     * the main execution loop for the first time.
     */
    fsigc::signal<void,
                 DBAFExecutionState* /* current state */>
          onInitializationComplete;

};

} // namespace dbaf

#endif // DBAF_CORE_PLUGIN_H
