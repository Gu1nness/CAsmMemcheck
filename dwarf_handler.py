# -*- coding : utf-8 -*-
"""
author : Rémi Oudin <oudin@crans.org>
license : GPLv3
"""

from elftools.common.py3compat import itervalues
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import CIE, FDE, ZERO
from elftools.dwarf.descriptions import set_global_machine_arch

DWARF_VALUES = {
    0x91 : "at_frame",
    0x93 : "DW_OP_piece",
    0x9c : "DW_OP_call_frame_cfa",
    0x10 : "DW_OP_constu",
    0x11 : "DW_OP_consts",
    0x9f : "DW_OP_stack_value",
    0x50 : "rax",
    0x51 : "rdx",
    0x52 : "rcx",
    0x53 : "rbx",
    0x54 : "rsi",
    0x55 : "rdi",
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
    def __init__(self):
        self.tag = ""

    def __repr__(self):
        """ Representation of a Tag.
        """
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
        cu_root = compile_unit.get_top_DIE()
        for attr in cu_root.attributes.values():
            if attr.name == "DW_AT_low_pc":
                self.low_pc = attr.value
        for die in cu_root.iter_children():
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
                                            compile_unit['version'],
                                            self.low_pc)
                        self.subprograms[subprog][variable.name] = variable
            elif die.tag == "DW_TAG_structure_type":
                self.structures.append(Structure(die))
            elif die.tag == "DW_TAG_base_type":
                self.base_type = die.offset


    @property
    def get_structs(self):
        return {struct.type : struct for struct in self.structures}

    def get_type_offset(self):
        return self.base_type

    def get_subprog(self, function):
        for subprog in self.subprograms:
            if isinstance(function, str):
                if subprog.name == function:
                    return subprog
            else:
                if subprog.name == function.name:
                    return subprog
        return None

    def __repr__(self):
        """ Representation of a CompileUnitTree.
        """
        string = "DIE %s\n" % self.tag
        for struct in self.structures:
            string += struct.__repr__()
        for subprogram in self.subprograms:
            string += subprogram.__repr__()
            sub_prog_vars = self.subprograms[subprogram]
            for key in sub_prog_vars:
                string += sub_prog_vars[key].__repr__()
        return string




class SubProgram(Tag):
    """ Describes a DW_TAB_subprogram.
    """
    def __init__(self, die):
        Tag.__init__(self)
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
        """ Returns the variables of the current subprogram object.
        """
        return self._variables

class Variable(Tag):
    """ Describes a DW_TAG_variable.
    """
    def __init__(self, die, dwarfinfo, version, low_pc):
        Tag.__init__(self)
        self.tag = die.tag
        self.low_pc = low_pc
        loc_lists = dwarfinfo.location_lists()
        self.at_location = False
        for attr in itervalues(die.attributes):
            if attr.name == "DW_AT_name":
                self.name = attr.value.decode('utf-8')
            if attribute_has_location_list(attr,
                                           version):
                self.at_location = loc_lists.get_location_list_at_offset(attr.value)
                tmp = ['0x%04x' % i.begin_offset for i in self.at_location]
                self.form = 'sec_offset'
            elif attr.name == "DW_AT_location":
                self.at_location = attr
                self.form = 'exprloc'
            elif attr.name == "DW_AT_decl_line":
                self.decl_line = attr.value
            elif attr.name == "DW_AT_type":
                self.type = attr.value
            elif attr.name == "DW_AT_const_value":
                self.const_value = attr.value

    def lookup_location_updates(self):
        """ Lookup for a location update.
        """
        return self.at_location, self.form == 'sec_offset'

    def find_entry(self, addr, start):
        """ Find the location list entry corresponding to the address.
        """
        if isinstance(self.at_location, list):
            for location in self.at_location:
                if self.low_pc + location.begin_offset <= addr < self.low_pc + location.end_offset:
                    return location.loc_expr
            return None
        elif "const_value" in self.__dict__:
            return self.const_value
        else:
            if not isinstance(self.at_location, bool):
                return self.at_location.value
        return None


class Member(Tag):
    """ Describes a DW_TAG_member.
    """
    def __init__(self, die):
        Tag.__init__(self)
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
        Tag.__init__(self)
        self.tag = die.tag
        self.members = []
        self.type = die.offset
        for attr in itervalues(die.attributes):
            if attr.name == "DW_AT_name":
                self.name = attr.value.decode('utf-8')
            elif attr.name == "DW_AT_decl_line":
                self.decl_line = attr.value
            elif attr.name == "DW_AT_byte_size":
                self.size = attr.value // 4
        for member in die.iter_children():
            self.__add_member(member)

    def __add_member(self, member):
        self.members.append(Member(member))

    def __repr__(self):
        string = 'DIE %s\n' % self.tag
        for key in self.__dict__:
            if key not in ('tag', "members",):
                string += "\t|DW_AT_%-22s:   %s\n" % (key, self.__dict__[key])
        for member in self.members:
            string += member.__repr__()
        return string

    def __str__(self):
        return self.__repr__()

class CFAEntries():
    """Lists all the CFA entries along with the offsets"""

    _registers = {
        0 : "rax",
        1 : "rbx",
        2 : "rcx",
        3 : "rdx",
        4 : "rsi",
        5 : "rdi",
        6 : "rsp",
        7 : "rbp",
    }

    def __init__(self, cfi):
        self.cfa = {}
        for item in cfi:
            if isinstance(item, (ZERO, CIE)):
                continue
            else:
                decoded = item.get_decoded()
                for val in decoded.table:
                    self.cfa[val['pc']] = val['cfa']

    def interpret(self, entry):
        current = 0
        item = None
        for pc in sorted(self.cfa.keys()):
            if self.cfa.get(entry, False):
                item = self.cfa[entry]
                break
            elif entry < pc:
                item = self.cfa[current]
                break
            current = pc
        if not(item.expr):
            return (CFAEntries._registers.get(item.reg, None), item.offset)
        else:
            return item.expr

    def __str__(self):
        tplt = "0x%08x : %s, offset %s"
        res = "\n".join([tplt % (key, CFAEntries._registers[item.reg], item.offset) \
                         for (key, item) in self.cfa.items()])
        return res


class LineEntry():
    """ Describes a line entry of the DWARF information.
    It contains inter alia the line, column, and file corresponding to a
    program counter.
    """
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
        """ Representation of a line entry.
        """
        string = "Link Point 0x%x:\n" % id(self.address)
        string += '\t|%-22s:    0x%x\n' % ('address', self.address)
        for i in ['file', 'line', 'column']:
            string += '\t|%-22s:    %s\n' % (i, self.__dict__[i])
        return string

    def __str__(self):
        """ Str representation of a line entry.
        """
        return self.__repr__()

    def get_info(self):
        """ Returns a tuple containing a program counter and the corresponding
        tuple (line, column).
        """
        return (self.address, (self.line, self.column))

class DInfo():
    """ The main class. It contains all the debug info for a file.
    """
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

            if self.dwarfinfo.has_EH_CFI():
                self.cfa_entries = CFAEntries(self.dwarfinfo.EH_CFI_entries())

            for compile_unit in self.dwarfinfo.iter_CUs():
                # A CU provides a simple API to iterate over all the DIEs in it.
                self.compile_units[compile_unit] = CompileUnitTree(compile_unit,
                                                                   self.dwarfinfo)
                self._link_points[compile_unit] = self.__get_lines(compile_unit)
                sorted(self._link_points[compile_unit],
                       key=lambda x: x.address)

    def __repr__(self):
        """ Representation of the DInfo class.
        """
        string = ""
        for compile_unit in self.compile_units:
            string += self.compile_units[compile_unit].__repr__()
        for cu_link in self._link_points:
            for link_point in self._link_points[cu_link]:
                string += link_point.__repr__()
        return string

    def get_variables(self, subprogram):
        """ Gets the variables linked to a subprogram.
        """
        for cu_tree in self.compile_units:
            for subprog in self.compile_units[cu_tree].subprograms:
                if subprogram == subprog.name:
                    return self.compile_units[cu_tree].subprograms[subprog]
        return None

    def get_structs(self, subprogram):
        """ Gets the structs linked to a subprogram.
        """
        res = {}
        for cu_tree in self.compile_units:
            res.update(self.compile_units[cu_tree].get_structs)
        return res

    def get_subprog(self, function):
        #print(self.compile_units.values())
        for cu_tree in self.compile_units.values():
            res = cu_tree.get_subprog(function)
            if res:
                return res

    def get_type(self):
        """ Get the type offset
        """
        res = []
        for cu_tree in self.compile_units:
            res.append(self.compile_units[cu_tree].get_type_offset())
        return res


    def __get_lines(self, compile_unit):
        """ Gets the link points for the provided compile unit, and returns it
        into a list.
        """
        tmp = self.dwarfinfo.line_program_for_CU(compile_unit).get_entries()
        return [LineEntry(line_p) for line_p in tmp if line_p.state and not
                line_p.state.end_sequence]

    @property
    def link_points(self):
        """ Property method that returns all the link points.
        """
        ret_list = []
        for compile_unit in self._link_points:
            ret_list.extend(self._link_points[compile_unit])
        return ret_list

def attribute_has_location_list(attr, version):
    """ Only some attributes can have location list values, if they have the
        required DW_FORM (loclistptr "class" in DWARF spec v3)
    """
    if (attr.name in ('DW_AT_location', 'DW_AT_string_length',
                      'DW_AT_const_value', 'DW_AT_return_addr',
                      'DW_AT_data_member_location', 'DW_AT_frame_base',
                      'DW_AT_segment', 'DW_AT_static_link',
                      'DW_AT_use_location', 'DW_AT_vtable_elem_location')):
        if 2 <= version < 4:
            if attr.form in ('DW_FORM_data4', 'DW_FORM_data8'):
                return True
        elif version == 4:
            if attr.form == 'DW_FORM_sec_offset':
                return True
    return False
