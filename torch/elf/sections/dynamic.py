# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from ...base import *
from .section import *

DT_NULL =           0x00
DT_NEEDED =         0x01
DT_PLTRELSZ =       0x02
DT_PLTGOT =         0x03
DT_HASH =           0x04
DT_STRTAB =         0x05
DT_SYMTAB =         0x06
DT_RELA =           0x07
DT_RELASZ =         0x08
DT_RELAENT =        0x09
DT_STRSZ =          0x0a
DT_SYMENT =         0x0b
DT_INIT =           0x0c
DT_FINI =           0x0d
DT_SONAME =         0x0e
DT_RPATH =          0x0f
DT_SYMBOLIC =       0x10
DT_REL =            0x11
DT_RELSZ =          0x12
DT_RELENT =         0x13
DT_PLTREL =         0x14
DT_DEBUG =          0x15
DT_TEXTREL =        0x16
DT_JMPREL =         0x17
DT_BIND_NOW =       0x18
DT_INIT_ARRAY =     0x19
DT_FINI_ARRAY =     0x1a
DT_INIT_ARRAYSZ =   0x1b
DT_FINI_ARRAYSZ =   0x1c
DT_RUNPATH =        0x1d
DT_FLAGS =          0x1e
DT_ENCODING =       0x1f
DT_PREINIT_ARRAY =  0x20
DT_PREINIT_ARRAYSZ = 0x21
DT_SYMTAB_SHNDX =   0x22
DT_NUM =            0x23
DT_GNU_HASH =       0x6ffffef5
DT_VERSYM =         0x6ffffff0
DT_RELACOUNT =      0x6ffffff9
DT_RELCOUNT =       0x6ffffffa
DT_FLAGS_1 =        0x6ffffffb
DT_VERDEF =         0x6ffffffc
DT_VERDEFNUM =      0x6ffffffd
DT_VERNEED =        0x6ffffffe
DT_VERNEEDNUM =     0x6fffffff

dt_strings = { v: k for (k, v) in filter(lambda x: x[0].startswith("DT_"), globals().items()) }
dt_vals = { k: v for (k, v) in filter(lambda x: x[0].startswith("DT_"), globals().items()) }


class ELFDynamicEntry(ItemUnderlay,
                      ReferenceUnderlay,
                      PPrintUnderlay,
                      StructUnderlay,
                      BaseObject):

    @classmethod
    def static_init(cls):
        super(ELFDynamicEntry, cls).static_init(config_path='dynamic.tsf')
        cls.add_option_handler("tag_match", cls.tag_match)
        cls.add_alt_handler("alt_tag", cls.alt_tag)
        cls.add_alt_handler("alt_section", cls.alt_section)
        cls.add_alt_handler("get_referenced_object", cls.get_referenced_object)
        cls.add_table_lookup("dynstr_ref", cls.dynstr_ref)
        cls.add_table_lookup("get_sheaders", cls.get_sheaders)
        cls.add_table_lookup("get_previous_tag", cls.get_previous_tag)
        cls.add_table_lookup("get_strtab", cls.get_strtab)
        cls.parse_config()

 
    def __init__(self, idx, offset, parent):
        super().__init__(idx=idx, offset=offset, parent=parent, byteorder=parent.byteorder, wordsize=parent.wordsize)
        self.sheader = parent.sheader
        self.dynamic = parent
    
    def tag_match(self, name):
        if self.d_tag not in dt_strings:
            return False
        expected = dt_strings[self.d_tag].replace('DT_', '')
        actual = name.replace('d_val_', '').replace('d_ptr_', '').upper()
        return expected == actual

    def alt_val(self, name):
        return "{:08x}".format(getattr(self, name))

    def alt_tag(self, name):
        if self.d_tag in dt_strings:
            return dt_strings[self.d_tag]
        else:
            return "{:08x}".format(self.d_tag)

    def alt_section(self, name):
        sheader = self.get_referenced_object(name)
        return "{!s} [ 0x{:016x} ]".format(sheader.get_referenced_object('sh_name'), sheader.sh_addr)

    def dynstr_ref(self, elffile):
        return self.parent.find_section_by_ptr_tag(DT_STRTAB).section

    def get_sheaders(self, elffile):
        return self.sheader.parent

    def get_previous_tag(self, elffile):
        return self.parent.find_section_by_ptr_tag(self.d_tag - 1)

    def get_strtab(self, elffile):
        return self.parent.find_section_by_ptr_tag(DT_STRTAB)

    def verify(self, elffile):
        # As long as our references hold, this section should be valid.
        return True



ELFDynamicEntry.static_init()

class ELFDynamicSection(TableUnderlay,
                        BaseObject,
                        ELFSection):
    types = frozenset([ 'DYNAMIC' ])
    @classmethod
    def static_init(cls):
        super(ELFDynamicSection, cls).static_init(config_path='dynamic_table.tsf')
        cls.parse_config()

    def __init__(self, sheader=None, byteorder='little', wordsize=4):
        super().__init__()
        self.sheader = sheader
        self.byteorder = byteorder
        self.wordsize = wordsize

    def organize(self, *args):
        self.clean()

    def get_tags_by_id(self, tag_id):
        out = list()
        for item in self.items:
            if item.d_tag == tag_id:
                out.append(item)
        return out
    
    def find_section_by_ptr_tag(self, tag_id):
        for item in self.items:
            if item.d_tag == tag_id:
                section_tag = item

        if section_tag is None:
            self.l.error("Could not find a tag number {:d} in the dynamic section.".format(tag_id))
            raise AttributeError("No tag identified")

        field_name = dt_strings[tag_id].replace('DT_', 'd_ptr_').lower()
 
        for sect in self.sheader.parent:
            if sect.sh_addr == getattr(section_tag, field_name):
                return sect

        self.l.error("Could not find a section matching address {:x}".format(section_tag.d_ptr))
        raise ValueError("No section matching pointer")

ELFDynamicSection.static_init()
