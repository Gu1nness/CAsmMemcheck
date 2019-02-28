#!/usr/bin/python3
"""
DWARF validator:
    This project aims at validating the DWARF debugging information by interpreting
    in parallel the C code and the generated assembly code and comparing
    the memory state at each link point. A link point is defined in the DWARF
    standard as a line number information, which links a program counter to
    a line and column of the source file
"""

import threading
from argparse import ArgumentParser
from copy import deepcopy

from AsmInterpreter.interpreter.lexical_analysis.lexer import Lexer as AsmLexer
from AsmInterpreter.interpreter.syntax_analysis.parser import Parser as AsmParser
from AsmInterpreter.interpreter.semantic_analysis.analyzer import SemanticAnalyzer as AsmAnalyzer
from AsmInterpreter.interpreter.interpreter.interpreter import Interpreter as AsmInterpreter
from AsmInterpreter.interpreter.interpreter.interpreter import AsmQueue
from CInterpreter.interpreter.lexical_analysis.lexer import Lexer as CLexer
from CInterpreter.interpreter.syntax_analysis.tree import FunctionDecl
from CInterpreter.interpreter.syntax_analysis.parser import Parser as CParser
from CInterpreter.interpreter.semantic_analysis.analyzer import SemanticAnalyzer as CAnalyzer
from CInterpreter.interpreter.interpreter.interpreter import Interpreter as CInterpreter
from CInterpreter.interpreter.interpreter.interpreter import CQueue

from dwarf_handler import DInfo, DWARF_VALUES

def asm_tree(file, functions):
    text = open(file, 'r').readlines()
    lexer = AsmLexer(text, functions)
    parser = AsmParser(lexer)
    tree = parser.parse()
    semantic = AsmAnalyzer.analyze(tree)
    return tree

def asm_worker(tree, bpoints):
    """ The thread worker for the assembly interpreter
    """
    interpreter = AsmInterpreter(bpoints)
    interpreter.interpret(tree)

def c_worker(tree, b_points):
    """ The thread worker for the C interpreter.
    """
    interpreter = CInterpreter(b_points)
    interpreter.interpret(tree)

def c_tree(file):
    text = open(file, 'r').read()
    lexer = CLexer(text)
    parser = CParser(lexer)
    tree = parser.parse()
    semantic = CAnalyzer.analyze(tree)
    return tree

def getter(queue, thread):
    """ The getter for a queue
    """
    if queue.empty():
        return
    else:
        mem = queue.get(block=True)
        return mem

def parse_loc_expr(locexpr, asm_mem):
    res = []
    current = -1
    local_locexpr = deepcopy(locexpr)
    while True:
        if local_locexpr:
            value = local_locexpr.pop(0)
            if value in [0x10, 0x11]:
                current = local_locexpr.pop(0)
            elif value == 0x93:
                res.append(current)
                _ = local_locexpr.pop(0)
            elif value == 0x91:
                offset = local_locexpr.pop(0) - 128
                addr = asm_mem.registers[DWARF_VALUES[0x91]] + offset
                res.append(asm_mem.stack[addr])
            elif value == 0x9f:
                continue
            elif 0x50 <= value and value <= 0x6f:
                current= asm_mem.registers[DWARF_VALUES[value]]
        else:
            break
    return res


def compare_mems(addr, c_mem, asm_mem, dwarf_info, functions):
    """ Compares the two memory state.
    """
    res = True
    variables = c_mem.keys()
    variables = [var for var in variables if var not in functions]
    function = c_mem.stack.current_frame.frame_name
    start = asm_mem[function]
    c_values = {key : c_mem[key] for key in variables}
    variables = dwarf_info.get_variables(function)
    for (variable, value) in c_values.items():
        if "." in variable:
            sub_var = variables.split(".")[0]
        variable_expr = variables[variable]
        locexpr = variable_expr.find_entry(addr, start)
        if locexpr:
            value = parse_loc_expr(locexpr, asm_mem)
        else:
            res = False
    return res

def check_bpoint(addr, line, column, bpoints):
    for bpoint in bpoints:
        if bpoint.address == addr and bpoint.line == line and bpoint.column == column:
            return True
    return False

def main(file_c, file_asm, file_compiled):
    result = True
    dwarf_info = DInfo(file_compiled)
    break_points = dwarf_info.link_points
    asm_bpoints = [link_point.address for link_point in break_points]
    c_bpoints = [(link_point.line, link_point.column) for link_point in break_points]
    ctree = c_tree(file_c)
    thread_c = threading.Thread(target=c_worker, args=(ctree, c_bpoints,))
    functions = []
    for var in filter(lambda o: isinstance(o , FunctionDecl), ctree.children):
        functions.append(var.func_name)
    asmtree = asm_tree(file_asm, functions)
    thread_asm = threading.Thread(target=asm_worker, args=(asmtree, asm_bpoints))

    thread_asm.daemon = True
    thread_c.daemon = True

    thread_asm.start()
    thread_c.start()

    while True:
        asm_ret = getter(AsmQueue, thread_asm)
        if asm_ret:
            (asm_bpoint, asm_mem) = asm_ret
            c_ret = getter(CQueue, thread_c)
            if c_ret:
                (c_bpoint, c_mem) = c_ret
                if check_bpoint(asm_bpoint, c_bpoint[0], c_bpoint[1],
                                break_points):
                    result &= compare_mems(asm_bpoint, c_mem, asm_mem, dwarf_info, functions)
                    if not result:
                        print(asm_bpoint)
                        print()
                        print("C Memory")
                        print(c_mem)
                        print()
                        print("ASM Memory")
                        print(asm_mem)
        if not thread_c.is_alive() and not thread_asm.is_alive() and CQueue.empty() and AsmQueue.empty():
            break
    return result

if __name__ == "__main__":
    PARSER = ArgumentParser("C and Asm Memcheck")
    PARSER.add_argument("file_c", help="The C source file")
    PARSER.add_argument("file_asm", help="The asm file, obtained with objdump")
    PARSER.add_argument("file_compiled", help="The compiled file")

    ARGS = PARSER.parse_args()
    if main(ARGS.file_c, ARGS.file_asm, ARGS.file_compiled):
        exit(0)
    else:
        exit(255)
