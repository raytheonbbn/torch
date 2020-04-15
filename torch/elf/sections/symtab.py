# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from ...base import *
from .section import *

bindings = {
    0: "LOCAL",
    1: "GLOBAL",
    2: "WEAK"
}

types = {
    0: "NONE",
    1: "OBJECT",
    2: "FUNC",
    3: "SECTION",
    4: "FILE",
    5: "COMMON",
    6: "TLS"
}

class ELFSymbol(ItemUnderlay,
                ReferenceUnderlay,
                PPrintUnderlay,
                StructUnderlay,
                BaseObject):
    @classmethod
    def static_init(cls):
        super(ELFSymbol, cls).static_init(config_path='symbol.tsf')
        cls.add_table_lookup('get_section_list', cls.get_section_list)
        cls.add_table_lookup('get_strtab', cls.get_strtab)
        cls.add_alt_handler('get_referenced_object', cls.get_referenced_object)
        cls.add_alt_handler('print_info', cls.print_info)
        cls.add_alt_handler('get_shndx_name', cls.get_shndx_name)
        cls.parse_config()

    def __init__(self, idx, offset, parent):
        byteorder = parent.byteorder
        wordsize = parent.wordsize
        super().__init__(idx=idx, offset=offset, parent=parent, byteorder=byteorder, wordsize=wordsize)
        self.strtab=parent.strtab

    def print_info(self, *args):
        # Info defines two values in the upper and lower nibbles.
        # I can't specify a field as half a byte.
        (t, b) = self.get_info()
        return "{!s}, {!s}".format(t, b)

    def get_info(self):
        t = self.st_info & 0xF
        b = (self.st_info >> 4) & 0xF
        if b in bindings:
            b = bindings[b]
        if t in types:
            t = types[t]
        return (t, b)
        

    def verify(self, root):
        return True

    def organize(self):
        pass

    def get_section_list(self, elffile):
        return elffile.sect_headers

    def get_strtab(self, elffile):
        return elffile.sect_headers[self.strtab].section

    def get_shndx_name(self, *args):
        # Special flag: absolute symbol
        if self.st_shndx == 0xFFF1:
            return '*ABS*'
        # References to the null section are undefined symbols
        if self.st_shndx == 0x00:
            return '*UND*'
        sheader = self.get_referenced_object('st_shndx')
        if sheader is None:
            return 'ERROR{:x}'.format(self.st_shndx)
        else:
            return sheader.get_referenced_object('sh_name')

    def __str__(self):
        return str(self.get_referenced_object('st_name'))

ELFSymbol.static_init()

class ELFSymTab(ELFSection,
                TableUnderlay,
                BaseObject):
    types = frozenset([ 'SYMTAB', 'DYNSYM' ])

    @classmethod
    def static_init(cls):
        super(ELFSymTab, cls).static_init(config_path='symtab.tsf')
        cls.parse_config()

    def __init__(self, sheader=None, byteorder='little', wordsize=4):
        self.strtab = sheader.sh_link
        self.byteorder = byteorder
        self.wordsize = wordsize
        super().__init__(byteorder=byteorder, wordsize=wordsize)

    def organize(self, *args):
        self.clean()

ELFSymTab.static_init()
