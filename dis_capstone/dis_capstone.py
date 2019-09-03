#!/usr/bin/python

'''
Author: 
    upbit
Date:
    2014-12-02
Purpose:
    disassemble code by Capstone Engine
Usage:
    add the following line to ~/.lldbinit
    command script import ~/.lldb/dis_capstone.py
'''

import lldb
import shlex
import optparse
import ctypes
from capstone import *
from capstone.arm import *

bytes_to_hex = lambda bytes: " ".join([ "%.2X"%int(bytes[i]) for i in range(len(bytes)) ])

def __lldb_init_module (debugger, dict):
    debugger.HandleCommand('command script add -f dis_capstone.dis_capstone discs')
    print('The "discs (dis_capstone)" command has been installed')

def _is_cpsr_thumb(frame):
    """ Check Thumb flag from CPSR """
    try:
        regs = frame.GetRegisters()[0]    # general purpose registers
        cpsr = [reg for reg in regs if reg.GetName()=='cpsr'][0]
        thumb_bit = int(cpsr.GetValue(), 16) & 0x20
        return thumb_bit >> 5
    except:
        return 0

def create_command_arguments(command):
    return shlex.split(command)

def create_options_parser():
    usage = "Usage: %prog (-f) (-s <addr>) (-l <line>)(-A <arm|arm64>) (-M <arm|thumb>)"
    parser = optparse.OptionParser(prog='discs', usage=usage)
    parser.add_option('-s', '--start-addr', dest='start_addr', help='start address (default: pc)', default=None)
    parser.add_option('-A', '--arch', dest='arch', help='arch type: arm,arm64 (default: arm)', default="arm")
    parser.add_option('-M', '--mode', dest='mode', help='mode type: arm,thumb (auto select by cpsr[b:5])', default=None)
    parser.add_option('-f', '--full', action="store_true", dest="full", help='show full outputs', default=False)
    parser.add_option('-c', '--count', dest='count', help='Number of instructions to display.', default=None)
    return parser

# from http://www.opensource.apple.com/source/lldb/lldb-69/test/lldbutil.py
def get_module_names(thread):
    """ Returns a sequence of module names from the stack frames of this thread. """
    def GetModuleName(i):
        return thread.GetFrameAtIndex(i).GetModule().GetFileSpec().GetFilename()
    return map(GetModuleName, range(thread.GetNumFrames()))

def get_function_names(thread):
    """ Returns a sequence of function names from the stack frames of this thread. """
    def GetFuncName(i):
        return thread.GetFrameAtIndex(i).GetFunctionName()
    return map(GetFuncName, range(thread.GetNumFrames()))

def get_symbol_names(thread):
    """ Returns a sequence of symbols for this thread. """
    def GetSymbol(i):
        return thread.GetFrameAtIndex(i).GetSymbol().GetName()
    return map(GetSymbol, range(thread.GetNumFrames()))

def get_filenames(thread):
    """ Returns a sequence of file names from the stack frames of this thread. """
    def GetFilename(i):
        return thread.GetFrameAtIndex(i).GetLineEntry().GetFileSpec().GetFilename()
    return map(GetFilename, range(thread.GetNumFrames()))

def get_line_numbers(thread):
    """ Returns a sequence of line numbers from the stack frames of this thread. """
    def GetLineNumber(i):
        return thread.GetFrameAtIndex(i).GetLineEntry().GetLine()
    return map(GetLineNumber, range(thread.GetNumFrames()))

def get_pc_addresses(thread):
    """ Returns a sequence of pc addresses for this thread. """
    def GetPCAddress(i):
        return thread.GetFrameAtIndex(i).GetPCAddress()
    return map(GetPCAddress, range(thread.GetNumFrames()))

def back_stacktrace(target, thread):
    mods = get_module_names(thread)
    functions = get_function_names(thread)
    symbols = get_symbol_names(thread)
    files = get_filenames(thread)
    lines = get_line_numbers(thread)
    addrs = get_pc_addresses(thread)

    for i in range(thread.GetNumFrames()):
        frame = thread.GetFrameAtIndex(i)
        function = frame.GetFunction()

        load_addr = addrs[i].GetLoadAddress(target)
        if not function:
            file_addr = addrs[i].GetFileAddress()
            start_addr = frame.GetSymbol().GetStartAddress().GetFileAddress()
            symbol_offset = file_addr - start_addr
            if (symbol_offset < 0):
                symbol_offset = 0
            print("  frame #{num}: {addr:#016x} {mod}`{symbol} + {offset}".format(
                num=i, addr=load_addr, mod=mods[i], symbol=symbols[i], offset=symbol_offset))
        else:
            print("  frame #{num}: {addr:#016x} {mod}`{func} at {file}:{line} {args}".format(
                num=i, addr=load_addr, mod=mods[i],
                func='%s [inlined]' % funcs[i] if frame.IsInlined() else funcs[i],
                file=files[i], line=lines[i], args=get_args_as_string(frame, showFuncName=False)))


def image_lookup_addr(addr):
    res = lldb.SBCommandReturnObject()
    lldb.debugger.GetCommandInterpreter().HandleCommand("image lookup --address 0x%x" % addr, res)
    return res.GetOutput()

def exec_disassemble(disasm_arch, disasm_mode, bytes, start_addr, target):
    linesList = []
    lineCount = 0

    md = Cs(disasm_arch, disasm_mode)
    md.detail = True
    disasm = md.disasm(bytes, start_addr)
    for insn in disasm:
        line = "   0x%x:  %-16s %-8s %-16s" % (
            insn.address, bytes_to_hex(insn.bytes), insn.mnemonic, insn.op_str)

        for op in insn.operands:
            if op.type == CS_OP_IMM:  # or op.type == capstone.CS_OP_MEM:
                # print("op: %s, imm: %s, type: %s" % (insn.op_str, op.imm, op.type))

                # need convert to unsigned, otherwise OverflowError
                sbAddr: lldb.SBAddress = target.ResolveLoadAddress(ctypes.c_ulong(int(op.imm)).value)
                # print("sbAddr: " + str(sbAddr))

                if sbAddr.GetModule().IsValid():
                    sbAddrStr = str(sbAddr)
                    # if sbAddrStr.count('symbol stub for:') > 0:
                    #     sbAddrStr = sbAddrStr[sbAddrStr.find('symbol stub for:') + len('symbol stub for:') + 1:]
                    line += ("; " + sbAddrStr)

                    if sbAddrStr == '':  # append lib offset  ->  xxx.so[yyy]
                        libName = sbAddr.GetModule().GetFileSpec().GetFilename()
                        offset = sbAddr.offset + sbAddr.GetSection().GetFileOffset()
                        line += ("%s[0x%x]" % (libName, offset))

        linesList.append(line)
        lineCount += 1

    return lineCount, linesList

def get_disassemble(debugger, start_addr, disasm_arch, disasm_mode):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()
    linesList = []
    lineCount = 0

    # read bytes
    error = lldb.SBError()
    disasm_length = 32
    bytes = process.ReadMemory(start_addr, disasm_length, error)

    if error.Success():
        # decode with capstone
        lineCount, linesList = exec_disassemble(disasm_arch, disasm_mode, bytes, start_addr, target)

        # maybe disasm_mode error, change to thumb or arm, maybe occur when cpsr flag is different with disassembly position
        if lineCount == 0 and disasm_arch != CS_ARCH_ARM64:
            disasm_mode = CS_MODE_ARM if (disasm_mode == CS_MODE_THUMB) else CS_MODE_THUMB
            lineCount, linesList = exec_disassemble(disasm_arch, disasm_mode, bytes, start_addr, target)

    else:
        print("[ERROR] ReadMemory(0x%x): %s" % (start_addr, error))

    return lineCount, linesList

def real_disassemble(debugger, start_addr, disasm_count, disasm_arch, disasm_mode):
    """ Disassemble code with target arch/mode """

    totalLineCount = 0
    totalLinesList = []

    # line
    disasm_count = int(disasm_count) if (disasm_count is not None) else 4

    while totalLineCount < disasm_count:
        curLineCount, curLines = get_disassemble(debugger, start_addr, disasm_arch, disasm_mode)
        start_addr += 32

        if curLineCount == 0:
            break
        else:
            totalLineCount += curLineCount
            totalLinesList.extend(curLines)

    if len(totalLinesList) > 0:
        totalLinesList[0] = "->" + totalLinesList[0][2:]

    for line in totalLinesList[0:disasm_count]:
        print(line)


def dis_capstone(debugger, command, result, dict):
    """ command entry: dis_capstone """

    cmd_args = create_command_arguments(command)
    parser = create_options_parser()

    try:
        (options, args) = parser.parse_args(cmd_args)
    except:
        return

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # start_addr
    try:
        start_addr = int(options.start_addr, 0)
    except:
        start_addr = frame.GetPCAddress().GetLoadAddress(target)
    # length
    disasm_count = options.count

    # arch
    disasm_arch = CS_ARCH_ARM
    if (options.arch == "arm64"):
        disasm_arch = CS_ARCH_ARM64

    # auto select mode by cpsr
    if _is_cpsr_thumb(frame):
        disasm_mode = CS_MODE_THUMB
    else:
        disasm_mode = CS_MODE_ARM


    # force apply --mode options
    if (options.mode == "arm"):
        disasm_mode = CS_MODE_ARM
    elif (options.mode == "thumb"):
        disasm_mode = CS_MODE_THUMB

    # force arm64 use arm mode
    if (options.arch == "arm64"):
        disasm_mode = CS_MODE_ARM

    # show frame and addr info
    if (options.full):
        print("  %s, %s" % (thread, frame))
        print(image_lookup_addr(start_addr))

    ##
    real_disassemble(debugger, start_addr, disasm_count, disasm_arch, disasm_mode)

