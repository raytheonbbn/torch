# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from ...base import *
from .section import ELFSection

class ELFVerSym(ItemUnderlay,
                ReferenceUnderlay,
                PPrintUnderlay,
                StructUnderlay,
                BaseObject):
    @classmethod
    def static_init(cls):
        super(ELFVerSym, cls).static_init(config_path='versym.tsf')
        cls.add_alt_handler('get_ver_string', cls.get_ver_string)
        cls.parse_config()

    def __init__(self, idx, offset, parent):
        byteorder = parent.byteorder
        wordsize = parent.wordsize
        super().__init__(idx=idx, offset=offset, parent=parent, byteorder=byteorder, wordsize=wordsize)
        self.sheader = parent.sheader

    def assign(self, val):
        self.versym = val

    def get_ver_string(self, *args):
        symtab = self.parent.get_symtab()
        if self.idx >= len(symtab):
            symbol = "OUT OF BOUNDS"
        else:
            symbol = str(symtab[self.idx])
        if self.versym == 0:
            return "{!s}:\t0 (*local*)".format(symbol)
        elif self.versym == 1:
            return "{!s}:\t1 (*global*)".format(symbol)
        else:
            verneed = self.parent.get_verneed()
            for entry in verneed:
                for aux in entry.aux:
                    # Looks GNU-specific; vna_other is used instead of vnd_idx
                    if aux.vna_other == self.versym:
                        return "{!s}:\t{:d} ({!s})".format(symbol, self.versym, aux.get_referenced_object('vna_name'))
            return "{!s}:\t{:d} ( UNKNOWN!!! )".format(symbol, self.versym)

    def verify(self, root):
        # All verification is done by the table.
        return True
        
    def organize(self):
        pass


ELFVerSym.static_init()
        

class ELFVerSymTable(TableUnderlay,
                     BaseObject,
                     ELFSection):

    types = frozenset([ 'VERSYM' ])
    @classmethod
    def static_init(cls):
        super(ELFVerSymTable, cls).static_init(config_path='versym_table.tsf')
        cls.parse_config()

    def __init__(self, sheader=None, byteorder='little', wordsize=4):
        super().__init__()
        self.sheader = sheader
        self.byteorder=byteorder
        self.wordsize=wordsize

    def get_symtab(self):
        return self.sheader.parent[self.sheader.sh_link].section
    
    def get_verneed(self):
        # TODO: I don't think this is actually how this gets looked up.
        # The location off verneed only seems to be defined in the .dynamic section.
        # Problem is, it's defined by absolute address.
        # Not a terrible way to look it up, now that we're looking it up.
        for sheader in self.sheader.parent:
            sh_type = sheader.sh_type
            if sheader.get_enum('sh_type', sh_type) == 'VERNEED':
                return sheader.section

    def verify(self, root):
        out = super().verify(root)
        versions = set()
        symtab = self.get_symtab()
        # Check that our length matches the symtab length
        if len(self) != len(symtab):
            self.l.error("Table size mismatch; expected {:d} entries, but found {:d}".format(len(symtab), len(self)))
            out = False
        # Check that every versym is a valid version reference.
        verneed = self.get_verneed()

        # Add default versions
        versions.add(0)
        versions.add(1)

        # Load versions from the VERNEED section.
        for entry in verneed:
            for aux in entry.aux:
                versions.add(aux.vna_other)
        for i in range(0, len(self.items)): 
            if i >= len(symtab):
                symbol = "OUT OF BOUNDS"
            else:
                symbol = str(symtab[i])
            if self[i].versym not in versions:
                self.l.error("Unknown version for symbol {:d} ({:s}): {:d}".format(i, symbol, self[i].versym))
                out = False
        return out

    def organize(self, *args):
        self.clean()
        # FIXME Hack to avoid using verdef sections.
        # We just set all unknown versions to global.
        # This is only in place to get results.
        versions = set()
        verneed = self.get_verneed()

        for entry in verneed:
            for aux in entry.aux:
                versions.add(aux.vna_other)

        for i in range(0, len(self.items)):
            if self[i].versym not in versions:
                self[i].versym = 1 
            


ELFVerSymTable.static_init()
