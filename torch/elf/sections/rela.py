# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from ...base import *
from .section import *

class ELFRelaEntry(ItemUnderlay,
                   ReferenceUnderlay,
                   PPrintUnderlay,
                   StructUnderlay,
                   BaseObject):
    @classmethod
    def static_init(cls):
        super(ELFRelaEntry, cls).static_init(config_path='rela.tsf')
        cls.add_table_lookup('get_symtab', cls.get_symtab)
        cls.add_alt_handler('get_referenced_object', cls.get_referenced_object)
        cls.parse_config()

    def __init__(self, idx, offset, parent):
        byteorder = parent.byteorder
        wordsize = parent.wordsize
        super().__init__(idx=idx, offset=offset, parent=parent, byteorder=byteorder, wordsize=wordsize)

    def get_symtab(self, elffile):
        return elffile.sect_headers[self.parent.sheader.sh_link].section

    def verify(self, *args):
        # I think references should take care of everything...
        return True

    def organize(self, *args):
        pass

ELFRelaEntry.static_init()

class ELFRelaSection(TableUnderlay,
                     BaseObject,
                     ELFSection):
    types=frozenset({'RELA'})
    @classmethod
    def static_init(cls):
        super(ELFRelaSection, cls).static_init(config_path='rela_table.tsf')
        cls.parse_config()

    def __init__(self, sheader=None, byteorder='little', wordsize=4):
        self.sheader = sheader
        self.byteorder = byteorder
        self.wordsize = wordsize
        super().__init__(byteorder=byteorder, wordsize=wordsize)
    
    def organize(self, *args):
        self.clean()
        return True

ELFRelaSection.static_init()
