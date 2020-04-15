# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from .table import TableUnderlay
from .struct import StructUnderlay

class ReferenceUnderlay:
  
    @classmethod
    def static_init(cls, **kwargs):
        super(ReferenceUnderlay, cls).static_init(**kwargs)
        cls.table_lookups = dict()
        cls.idx_ref_handlers = dict()
        cls.off_ref_handlers = dict()
        cls.field_ref_handlers = dict()
        cls.field_ref_fields = dict()
        cls.field_ref_search = dict()
        cls.field_ignore_vals = dict()
    
    @classmethod
    def parse_config_line(cls, key, entry):
        if key == "REFERENCE" and len(entry) == 3:
            if entry[1] == 'idx':
                cls.add_idx_ref(entry[0], entry[2])
            elif entry[1] == 'off':
                cls.add_off_ref(entry[0], entry[2])
            else:
                cls.l.error("Unknown reference type: {:s}".format(entry[1]))
                raise ValueError("Unknown reference type")
        elif key == "REFERENCE" and len(entry) == 5:
            if entry[1] == "field":
                if entry[4] == 'no_search':
                    cls.add_field_ref(entry[0], entry[2], entry[3], search=False)
                else:
                    cls.add_field_ref(entry[0], entry[2], entry[3])
            else:
                cls.l.error("Unknown reference type: {:s}".format(entry[1]))
                raise ValueError("Unknown reference type")
        elif key == "IGNORE" and len(entry) == 3:
            cls.add_ignore_val(entry[0], entry[1], entry[2])
        else:
            super(ReferenceUnderlay, cls).parse_config_line(key, entry)
   
    @classmethod
    def add_table_lookup(cls, name, lookup):
        if name in cls.table_lookups:
            cls.l.error("Table lookup {:s} already exists".format(name))
            raise AttributeError("Duplicate table lookup")
        cls.table_lookups[name] = lookup

    @classmethod
    def add_idx_ref(cls, name, l_name):
        if l_name not in cls.table_lookups:
            cls.l.error("Missing table lookup {:s} for field {:s}".format(l_name, name))
            raise AttributeError("Missing table lookup")
        cls.idx_ref_handlers[name] = cls.table_lookups[l_name]

    @classmethod
    def add_off_ref(cls, name, l_name):
        if l_name not in cls.table_lookups:
            cls.l.error("Missing table lookup {:s} for field {:s}".format(l_name, name))
            raise AttributeError("Missing table lookup")
        cls.off_ref_handlers[name] = cls.table_lookups[l_name]

    @classmethod
    def add_field_ref(cls, name, field, l_name, search=True):
        if l_name not in cls.table_lookups:
            cls.l.error("Missing table lookup {:s} for field {:s}".format(l_name, name))
            raise AttributeError("Missing table lookup")
        cls.field_ref_handlers[name] = cls.table_lookups[l_name]
        cls.field_ref_fields[name] = field
        cls.field_ref_search[name] = search
    
    @classmethod
    def add_ignore_val(cls, name, val, kind):
        if kind == 'str':
            # Value is already a string.
            pass
        elif kind == 'dec':
            # Value is a decimal int.
            val = int(val, 10)
        elif kind == 'hex':
            # Value is a hex int.
            val = int(val, 16)
        else:
            # No idea what value is.
            cls.l.error("Unknown ignore kind: {:s} for field {:s}, value {:s}".format(kind, name, val))
            raise ValueError("Unknown ignore kind")
        cls.field_ignore_vals.setdefault(name, set()).add(val)

    def __init__(self, **kwargs):
        self.idx_references = dict()
        self.off_references = dict()
        self.field_references = dict()
        super().__init__(**kwargs)

    def resolve_references(self, root):
        for (name, handler) in self.idx_ref_handlers.items():
            if isinstance(self, StructUnderlay) and name not in self.enabled_field_set:
                continue

            table = handler(self, root)
            if table is not None and not isinstance(table, TableUnderlay):
                self.l.error("Tried assigning {:s} as a reference to something that's not a table: {!s}".format(name, type(table)))
                raise TypeError("Referenced into a non-table object")
            if table is not None:
                self.resolve_idx_reference(name, table)

        for (name, handler) in self.off_ref_handlers.items():
            if isinstance(self, StructUnderlay) and name not in self.enabled_field_set:
                continue

            table = handler(self, root)
            if table is not None and not isinstance(table, TableUnderlay):
                self.l.error("Tried assigning {:s} as a reference to something that's not a table: {!s}".format(name, type(table)))
                raise TypeError("Referenced into a non-table object")
            if table is not None:
                self.resolve_off_reference(name, table)

        for (name, handler) in self.field_ref_handlers.items():
            if isinstance(self, StructUnderlay) and name not in self.enabled_field_set:
                continue

            table = handler(self, root)
            field = self.field_ref_fields[name]
            search = self.field_ref_search[name]
            if table is not None and not isinstance(table, TableUnderlay) and search:
                self.l.error("Tried assigning {:s} as a reference to something that's not a table: {!s}".format(name, type(table)))
            if table is not None:
                self.resolve_field_reference(name, field, table, search=search)

    def resolve_idx_reference(self, name, table):
        idx = getattr(self, name)

        # If the value is one we've beem told to ignore, ignore it.
        if name in self.field_ignore_vals and idx in self.field_ignore_vals[name]:
            return

        # If the value is out of bounds for the table's indexes, warn.
        if len(table) <= idx:
            self.l.warn("Requested index for {:s} {:d} is out of bounds (0, {:d})".format(name, idx, len(table)))
            return
        self.idx_references[name] = table[idx]
        delattr(self, name)

    def resolve_off_reference(self, name, table):
        off = getattr(self, name)
        
        # If the value is one we've beem told to ignore, ignore it.
        if name in self.field_ignore_vals and off in self.field_ignore_vals[name]:
            return

        self.off_references[name] = table.get_item_by_offset(off)
        delattr(self, name)

    def resolve_field_reference(self, name, field, table, search=True):
        item = None
        if search:
            val = getattr(self, name)
            # If the value is one we've beem told to ignore, ignore it.
            if name in self.field_ignore_vals and off in self.field_ignore_vals[name]:
                return

            for i in table:
                if getattr(i, field) == val:
                    item = i
                    break
            if item is None:
                self.l.error("Could not find an item with value {!s} for field {:s}".format(val, field))
                raise ValueError("Unknown field referecne")
        else:
            item = table
        self.field_references[name] = (item, field)
        delattr(self, name)

    def __getattr__(self, name):
        if name in self.idx_references:
            return self.idx_references[name].idx
        elif name in self.off_references:
            return self.off_references[name].offset
        elif name in self.field_references:
            (item, field) = self.field_references[name]
            return getattr(item, field)
        else:
            super().__getattr__(name)

    def get_referenced_object(self, name):
        if name in self.idx_references:
            return self.idx_references[name]
        elif name in self.off_references:
            return self.off_references[name]
        elif name in self.field_references:
            return self.field_references[name][0]
        else:
            self.l.error("No reference for {:s}: {!s}, {!s}".format(name, self.idx_references.keys(), self.off_references.keys()))
            raise AttributeError("Unknown reference")

