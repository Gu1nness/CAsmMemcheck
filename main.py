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
from CInterpreter.interpreter.syntax_analysis.tree import StructVar
from CInterpreter.interpreter.syntax_analysis.parser import Parser as CParser
from CInterpreter.interpreter.semantic_analysis.analyzer import SemanticAnalyzer as CAnalyzer
from CInterpreter.interpreter.interpreter.interpreter import Interpreter as CInterpreter
from CInterpreter.interpreter.interpreter.interpreter import CQueue

from dwarf_handler import DInfo, DWARF_VALUES

def asm_tree(file, functions):
    """ Parses the *.nasm file and returns the AST tree.
    """
    text = open(file, 'r').readlines()
    lexer = AsmLexer(text, functions)
    parser = AsmParser(lexer)
    tree = parser.parse()
    AsmAnalyzer.analyze(tree)
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
    return CQueue

def c_tree(file):
    """ Parses the *.c file and returns the C tree.
    """
    text = open(file, 'r').read()
    lexer = CLexer(text)
    parser = CParser(lexer)
    tree = parser.parse()
    CAnalyzer.analyze(tree)
    return tree

def getter(queue):
    """ The getter for a queue
    """
    if queue.empty():
        return None
    mem = queue.get(block=True)
    return mem

def parse_loc_expr(locexpr, asm_mem, dwarf_info, function, address, size=1):
    """ Parse a locexpr expression in order to return the values stored.
    """
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
                base_offset = local_locexpr.pop(0) - 128
                for i in range(size):
                    offset =  base_offset + 4*(i)
                    function = dwarf_info.get_subprog(function)
                    frame_base = function.frame_base.value[0]
                    if 0x50 <= frame_base <= 0x60:
                        addr = asm_mem.registers[DWARF_VALUES[frame_base]] + offset
                    elif frame_base == 0x9c:
                        _res = dwarf_info.cfa_entries.interpret(address)
                        if isinstance(_res, tuple):
                            addr = asm_mem.registers[_res[0]] + _res[1] + offset
                        else:
                            raise Exception("Unsupported expression")
                    else:
                        raise Exception("Unsupported expression")
                    res.append(asm_mem.stack[addr])
            elif value == 0x9f:
                continue
            elif 0x50 <= value <= 0x6f:
                current = asm_mem.registers[DWARF_VALUES[value]]
        else:
            break
    return res


def compare_mems(addr, c_mem, asm_mem, dwarf_info, functions):
    """ Compares the two memory state.
    """
    res = True
    asm_value = None
    locexpr = None
    variables = c_mem.keys()
    variables = [var for var in variables if var not in functions]
    function = c_mem.stack.current_frame.frame_name
    start = asm_mem[function]
    c_values = {key : c_mem[key] for key in variables}
    variables = dwarf_info.get_variables(function)
    for (variable, value) in c_values.items():
        variable_expr = variables[variable]
        struct = dwarf_info.get_structs(function)
        struct = struct.get(variable_expr.type, None)
        type_offsets = dwarf_info.get_type()
        if variable_expr.type not in type_offsets:
            size = struct.size
        else:
            size = 1
        locexpr = variable_expr.find_entry(addr, start._start)
        if locexpr:
            asm_value = parse_loc_expr(locexpr, asm_mem, dwarf_info, function, addr, size)
            if isinstance(value, dict):
                i = 0
                for val in sorted(value.keys()):
                    if isinstance(value[val], int):
                        res &= value[val] == asm_value[i]
                    else:
                        res &= value[val].val == asm_value[i]
                    i += 1
            else:
                if isinstance(value, int):
                    res &= (asm_value[0] == value)
                else:
                    res &= (asm_value[0] == value.val)
        else:
            res = False
        if not res:
            print("Error at 0x%08x" % addr)
            if not locexpr:
                print("No location information for variable %s" % variable)
            else:
                print("Invalid values for variable %s :" % (variable))
                print(" Assembly : %s" % asm_value)
                if isinstance(value, int):
                    print(" C        : %s" % value)
                elif isinstance(value, dict):
                    print(" c        : %s" % value)
                else:
                    print(" c        : %s" % value.val)
            return False
            break
    return res

def check_bpoint(addr, line, column, bpoints):
    """ Checks if (addr, (line, column)) is a link point in the DWARF
    information.
    """
    for bpoint in bpoints:
        if bpoint.address == addr and bpoint.line == line and bpoint.column == column:
            return True
    return False

def main(file_c, file_asm, file_compiled):
    """ The main validation function.
    It parses all the given files, interprets both codes in parallel,
    and checks the memory states at the link points.
    """
    result = True
    dwarf_info = DInfo(file_compiled)
    break_points = dwarf_info.link_points[1:]
    asm_bpoints = [link_point.address for link_point in break_points]
    c_bpoints = [(link_point.line, link_point.column) for link_point in break_points]
    ctree = c_tree(file_c)
    thread_c = threading.Thread(target=c_worker, args=(ctree, c_bpoints,))
    functions = []
    for var in filter(lambda o: isinstance(o, FunctionDecl), ctree.children):
        functions.append(var.func_name)
    asmtree = asm_tree(file_asm, functions)
    thread_asm = threading.Thread(target=asm_worker, args=(asmtree, asm_bpoints))

    thread_asm.daemon = True
    thread_c.daemon = True

    thread_asm.start()
    thread_c.start()

    while True:
        asm_ret = getter(AsmQueue)
        if asm_ret:
            (asm_bpoint, asm_mem) = asm_ret
            c_ret = getter(CQueue)
            if c_ret:
                (c_bpoint, c_mem) = c_ret
                if check_bpoint(asm_bpoint, c_bpoint[0], c_bpoint[1],
                                break_points):
                    result &= compare_mems(asm_bpoint, c_mem, asm_mem, dwarf_info, functions)
                    if not result:
                        print("Error at location %08x" % asm_bpoint)
                        print()
                        print("C Memory")
                        print(c_mem)
                        print()
                        print("ASM Memory")
                        print(asm_mem)
                        break
        #print("C Queue %s" % CQueue.empty())
        #print("Asm Queue %s" % AsmQueue.empty())
        if (not thread_c.is_alive()) and (not thread_asm.is_alive())\
           and CQueue.empty() and AsmQueue.empty():
            print(CQueue)
            print(AsmQueue)
            break
    return result

if __name__ == "__main__":
    PARSER = ArgumentParser("C and Asm Memcheck")
    PARSER.add_argument("file_c", help="The C source file")
    PARSER.add_argument("file_asm", help="The asm file, obtained with objdump")
    PARSER.add_argument("file_compiled", help="The compiled file")

    ARGS = PARSER.parse_args()
    if main(ARGS.file_c, ARGS.file_asm, ARGS.file_compiled):
        print("%s OK" % ARGS.file_c)
        exit(0)
    else:
        print("%s BAD" % ARGS.file_c)
        exit(255)
