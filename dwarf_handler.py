# -*- coding : utf-8 -*-
"""
author : Rémi Oudin <oudin@crans.org>
license : GPLv3
"""

import sys

from elftools.common.py3compat import itervalues
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_DWARF_expr
from elftools.dwarf.descriptions import _EXTRA_INFO_DESCRIPTION_MAP
from elftools.dwarf.descriptions import set_global_machine_arch
from elftools.dwarf.locationlists import LocationEntry

DWARF_VALUES = {
    0x91 : "rbp",
    0x93 : "DW_OP_piece",
    0x10 : "DW_OP_constu",
    0x11 : "DW_OP_consts",
    0x9f : "DW_OP_stack_value",
    0x50 : "rax",
    0x51 : "rbx",
    0x52 : "rcx",
    0x53 : "rdx",
    0x54 : "rdi",
    0x55 : "rsi",
    0x56 : "rbp",
    0x57 : "rsp",
    0x58 : "r8",
    0x59 : "r9",
    0x5a : "r10",
    0x5b : "r11",
    0x5c : "r12",
    0x5d : "r13",
    0x5e : "r14",
    0x5f : "r15",
    0x60 : "rip",
    0x61 : "rflags",
    0x62 : "cs",
    0x63 : "orig_rax",
    0x64 : "fs_base",
    0x65 : "gs_base",
    0x66 : "fs",
    0x67 : "gs",
    0x68 : "ss",
    0x69 : "ds",
    0x6a : "es",
}

def create_variables(file):
    """ Creates all the variables of the DWARF info.
    """
    compile_units = []
    with open(file, 'rb') as file_d:
        elffile = ELFFile(file_d)

        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            raise Exception

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()

        # This is required for the descriptions module to correctly decode
        # register names contained in DWARF expressions.
        set_global_machine_arch(elffile.get_machine_arch())

        for compile_unit in dwarfinfo.iter_CUs():
            # A CU provides a simple API to iterate over all the DIEs in it.
            compile_units.append(CompileUnitTree(compile_unit, dwarfinfo))
    return compile_units


class Tag():
    """The base class defining a DW_TAG_* structure, with a simple
    representation method.
    """
    def __init__():
        return

    def __repr__(self):
        string = 'DIE %s\n' % self.tag
        for key in self.__dict__:
            if key != 'tag':
                string += "\t|DW_AT_%-22s:   %s\n" % (key, self.__dict__[key])
        return string

    def __str__(self):
        return self.__repr__()


class CompileUnitTree():
    """ A compile unit, described as a tree. Should contain all the necessary
    information : subprograms, structures, etc.
    Provides many public methods in order to perform IP lookup, variable
    location computation, etc.
    """
    def __init__(self, compile_unit, dwarfinfo):
        self.tag = "DW_TAG_compile_unit"
        self.structures = []
        self.subprograms = {}
        self.res_start = {}
        self.res_end = {}
        cu = compile_unit.get_top_DIE()
        for die in cu.iter_children():
            # Go over all attributes of the DIE. Each attribute is an
            # AttributeValue object (from elftools.dwarf.die), which we
            # can examine.
            if die.tag == "DW_TAG_subprogram":
                subprog = SubProgram(die)
                self.subprograms[subprog] = {}
                for children in die.iter_children():
                    if children.tag == "DW_TAG_variable":
                        variable = Variable(children,
                                            dwarfinfo,
                                            compile_unit['version'])
                        self.subprograms[subprog][variable.name] = variable
            elif die.tag == "DW_TAG_structure_type":
                self.structures.append(Structure(die))
        for prog in self.subprograms:
            self._compile_locations_changes(prog)


    def __repr__(self):
        string = "DIE %s\n" % self.tag
        for struct in self.structures:
            string += struct.__repr__()
        for subprogram in self.subprograms:
            string += subprogram.__repr__()
            sub_prog_vars = self.subprograms[subprogram]
            for key in sub_prog_vars:
                string += sub_prog_vars[key].__repr__()
        return string

    def _get_variables_locations(self, subprogram):
        """ Gets the locations or location lists of the variables of a
        subprogram.
        """
        if self.subprograms.get(subprogram, None):
            var_list = self.subprograms[subprogram]
            return {variable : var_list[variable].lookup_location_updates() for
                    variable in var_list}


    def _compile_locations_changes(self, subprogram):
        """ Compiles the variable locations for a subprogram.
        """
        def __update_res(res, val, var):
            if res.get(val, None):
                res[val].append(var)
            else:
                res[val] = [var]
        self.res_start.clear()
        self.res_start.clear()
        subprog = self.subprograms[subprogram]
        variables = self._get_variables_locations(subprogram)
        low_pc = subprogram.low_pc
        for variable in variables:
            answer, dynamic = variables[variable]
            if dynamic:
                for var in answer:
                    low = low_pc.value + var.begin_offset
                    __update_res(self.res_start, low, subprog[variable])
                    high = low_pc.value + var.end_offset
                    __update_res(self.res_end, high, subprog[variable])


class SubProgram(Tag):
    """ Describes a DW_TAB_subprogram.
    """
    def __init__(self, die):
        self.tag = die.tag
        for attr in itervalues(die.attributes):
            if attr.name == "DW_AT_name":
                self.name = attr.value.decode('utf-8')
            if attr.name == "DW_AT_frame_base":
                self.frame_base = attr
            elif attr.name == "DW_AT_low_pc":
                self.low_pc = attr
            elif attr.name == "DW_AT_high_pc":
                self.high_pc = attr
            elif attr.name == "DW_AT_decl_line":
                self.decl_line = attr.value
        self._variables = {}

    @property
    def variables(self):
        return self._variables

class Variable(Tag):
    """ Describes a DW_TAG_variable.
    """
    def __init__(self, die, dwarfinfo, version):
        self.tag = die.tag
        loc_lists = dwarfinfo.location_lists()
        for attr in itervalues(die.attributes):
            if attr.name == "DW_AT_name":
                self.name = attr.value.decode('utf-8')
            if attribute_has_location_list(attr,
                                           version):
                self.at_location = loc_lists.get_location_list_at_offset(attr.value)
                self.form = 'sec_offset'
            elif attr.name == "DW_AT_location":
                self.at_location = attr
                self.form = 'exprloc'
            elif attr.name == "DW_AT_decl_line":
                self.decl_line = attr.value

    def lookup_location_updates(self):
        return self.at_location, self.form == 'sec_offset'

    def find_entry(self, addr, start):
        if isinstance(self.at_location, list):
            for location in self.at_location:
                sys.stderr.write("%s\n" % self)
                if start + location.begin_offset <= addr and start + location.end_offset >= addr:
                    return location
        else:
            return self.at_location.value
        return None


class Member(Tag):
    """ Describes a DW_TAG_member.
    """
    def __init__(self, die):
        self.tag = die.tag
        for attr in itervalues(die.attributes):
            if attr.name == "DW_AT_name":
                self.name = attr.value.decode('utf-8')
            elif attr.name == "DW_AT_decl_line":
                self.decl_line = attr.value
            elif attr.name == "DW_AT_data_member_location":
                self.data_member_location = attr.value


class Structure(Tag):
    """ Describes a DW_TAG_structure.
    """
    def __init__(self, die):
        self.tag = die.tag
        self.members = []
        for attr in itervalues(die.attributes):
            if attr.name == "DW_AT_name":
                self.name = attr.value.decode('utf-8')
            elif attr.name == "DW_AT_decl_line":
                self.decl_line = attr.value
        for member in die.iter_children():
            self.__add_member(member)

    def __add_member(self, member):
        self.members.append(Member(member))

    def __repr__(self):
        string = 'DIE %s\n' % self.tag
        for key in self.__dict__:
            if key != 'tag' and key != "members":
                string += "\t|DW_AT_%-22s:   %s\n" % (key, self.__dict__[key])
        for member in self.members:
            string += member.__repr__()
        return string

    def __str__(self):
        return self.__repr__()

class LineEntry():
    def __init__(self, line_program):
        self.address = line_program.state.address
        self.file = line_program.state.file
        self.line = line_program.state.line
        self.column = line_program.state.column
        self.is_stmt = line_program.state.is_stmt
        self.basic = line_program.state.basic_block
        self.end = line_program.state.end_sequence
        self.prologue = line_program.state.prologue_end
        self.epilogue = line_program.state.epilogue_begin
        self.isa = line_program.state.isa

    def __repr__(self):
        string = "Link Point 0x%x:\n" % id(self.address)
        string += '\t|%-22s:    0x%x\n' % ('address', self.address)
        for i in ['file', 'line', 'column']:
            string += '\t|%-22s:    %s\n' % (i, self.__dict__[i])
        return string

    def __str__(self):
        return self.__repr__()

    def get_info(self):
        return (self.address, (self.line, self.column))

class DInfo():
    def __init__(self, file):
        self.compile_units = {}
        self._link_points = {}
        with open(file, 'rb') as file_d:
            elffile = ELFFile(file_d)

            if not elffile.has_dwarf_info():
                print('  file has no DWARF info')
                raise Exception

            # get_dwarf_info returns a DWARFInfo context object, which is the
            # starting point for all DWARF-based processing in pyelftools.
            self.dwarfinfo = elffile.get_dwarf_info()

            # This is required for the descriptions module to correctly decode
            # register names contained in DWARF expressions.
            set_global_machine_arch(elffile.get_machine_arch())

            for compile_unit in self.dwarfinfo.iter_CUs():
                # A CU provides a simple API to iterate over all the DIEs in it.
                self.compile_units[compile_unit] = CompileUnitTree(compile_unit,
                                                                   self.dwarfinfo)
                self._link_points[compile_unit] = self.__get_lines(compile_unit)
                sorted(self._link_points[compile_unit],
                       key=lambda x: x.address)

    def __repr__(self):
        string = ""
        for cu in self.compile_units:
            string += self.compile_units[cu].__repr__()
        for cu_link in self._link_points:
            for link_point in self._link_points[cu_link]:
                string += link_point.__repr__()
        return string

    def get_variables(self, subprogram):
        for cu_tree in self.compile_units:
            for subprog in self.compile_units[cu_tree].subprograms:
                if subprogram == subprog.name:
                    return self.compile_units[cu_tree].subprograms[subprog]


    def __get_lines(self, compile_unit):
        """ Gets the link points for the provided compile unit, and returns it
        into a list.
        """
        tmp = self.dwarfinfo.line_program_for_CU(compile_unit).get_entries()
        return [LineEntry(line_p) for line_p in tmp if line_p.state]

    @property
    def link_points(self):
        ret_list = []
        for cu in self._link_points:
            ret_list.extend(self._link_points[cu])
        return ret_list

def attribute_has_location_list(attr, version):
    """ Only some attributes can have location list values, if they have the
        required DW_FORM (loclistptr "class" in DWARF spec v3)
    """
    #print("Attr %s: %s" % (attr.name, attr.form))
    if (attr.name in ('DW_AT_location', 'DW_AT_string_length',
                      'DW_AT_const_value', 'DW_AT_return_addr',
                      'DW_AT_data_member_location', 'DW_AT_frame_base',
                      'DW_AT_segment', 'DW_AT_static_link',
                      'DW_AT_use_location', 'DW_AT_vtable_elem_location')):
        if 2 <= version < 4:
            if attr.form in ('DW_FORM_data4', 'DW_FORM_data8'):
                return True
        elif version == 4:
            if attr.form is 'DW_FORM_sec_offset':
                return True
    return False
