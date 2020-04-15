# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from ...base import *
from .section import *

class ELFVerNeed(ReferenceUnderlay,
                 PPrintUnderlay,
                 StructUnderlay,
                 BaseObject):
    @classmethod
    def static_init(cls):
        super(ELFVerNeed, cls).static_init(config_path='verneed.tsf')
        cls.add_table_lookup('get_strtab', cls.get_strtab)
        cls.add_alt_handler('get_referenced_object', cls.get_referenced_object)
        cls.parse_config()

    def __init__(self, sheader, byteorder='little', wordsize=4):
        super().__init__(byteorder=byteorder, wordsize=wordsize)
        self.sheader = sheader

    def get_strtab(self, elffile):
        return elffile.sect_headers[self.sheader.sh_link].section

    def verify(self, *args):
        out = True
        # Check that aux is somewhere sensical.
        if not self.vn_aux == 0x10:
            self.l.error('Veraux offset is weird: 0x{:08x}'.format(self.vn_aux))
            out = False
        else:
            self.pprint()
        return out

ELFVerNeed.static_init()

class ELFVerNeedAux(ItemUnderlay,
                ReferenceUnderlay,
                PPrintUnderlay,
                StructUnderlay,
                BaseObject):
    @classmethod
    def static_init(cls):
        super(ELFVerNeedAux, cls).static_init(config_path='verneedaux.tsf')
        cls.add_table_lookup('get_strtab', cls.get_strtab)
        cls.add_alt_handler('get_referenced_object', cls.get_referenced_object)
        cls.parse_config()

    def __init__(self, idx, offset, parent):
        super().__init__(idx=idx, offset=offset, parent=parent, byteorder=parent.byteorder, wordsize=parent.wordsize)
        self.sheader = parent.sheader
    
    def get_strtab(self, elffile):
        return elffile.sect_headers[self.sheader.sh_link].section

    def verify(self, *args):
        # TODO: Think about what we need to verify here.
        return True

ELFVerNeedAux.static_init()

class ELFVerNeedAuxList(TableUnderlay, 
                    BaseObject):
    @classmethod
    def static_init(cls):
        super(ELFVerNeedAuxList, cls).static_init(config_path='verneedaux_table.tsf')
        cls.parse_config()

    def __init__(self, sheader=None, byteorder='little', wordsize=4):
        super().__init__()
        self.sheader = sheader
        self.byteorder = byteorder
        self.wordsize = wordsize

ELFVerNeedAuxList.static_init()

class ELFVerNeedEntry(ItemUnderlay,
                  BaseObject):
    @classmethod
    def static_init(cls):
        super(ELFVerNeedEntry, cls).static_init()

    def __init__(self, idx, offset, parent):
        super().__init__(idx=idx, offset=offset, parent=parent)
        self.need = ELFVerNeed(parent.sheader)
        self.aux = ELFVerNeedAuxList(sheader=parent.sheader, byteorder=parent.byteorder, wordsize=parent.wordsize)

    def from_bytes(self, data):
        self.need.from_bytes(data)
        # FIXME: HUGE HACK!
        # Usually, the aux entries are all in a row after
        # the verneed struct, so we can compute
        # the end of the array directly.
        # 
        # If this isn't the case, we need to be more clever
        # than the table struct will allow.
        aux_end = self.need.size + (self.need.vn_cnt * 0x10)
        self.aux.from_bytes(data[self.need.size:aux_end])

    def to_bytes(self, write=None):
        out = 0
        out += self.need.to_bytes(write=write)
        out += self.aux.to_bytes(write=write)
        return out

    def resolve_references(self, root):
        self.need.resolve_references(root)
        self.aux.resolve_references(root)

    def organize(self, *args):
        return True

    def verify(self, *args):
        out = self.need.verify(*args)
        out &= self.aux.verify(*args)
        return out

    @property
    def size(self):
        return self.need.size + self.aux.size

    def pprint(self):
        print("Main:")
        self.need.pprint()
        print("Aux:")
        self.aux.pprint()

ELFVerNeedEntry.static_init()

class ELFVerNeedTable(TableUnderlay,
                      BaseObject,
                      ELFSection):
    types = frozenset({ 'VERNEED' })
    @classmethod
    def static_init(cls):
        super(ELFVerNeedTable, cls).static_init(config_path='verneed_table.tsf')
        cls.parse_config()

    @classmethod
    def get_record(cls, data, idx, offset, parent):
        # Version entries are variable length; let them determine their own size.
        obj = ELFVerNeedEntry(idx, offset, parent)
        obj.from_bytes(data[offset:])
        return obj

    def __init__(self, sheader=None, byteorder='little', wordsize=4):
        super().__init__()
        self.sheader = sheader
        self.byteorder = byteorder
        self.wordsize = wordsize

ELFVerNeedTable.static_init()
