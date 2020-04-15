# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
import sys
from collections.abc import MutableSequence

class ItemUnderlay:
    def __init__(self, idx=None, offset=None, parent=None, **kwargs):

        if idx is None or offset is None or parent is None:
            self.l.error("Missing kwargs for a table item.  Check your constructor call.")
            raise KeyError("Missing kwargs keys")

        if not isinstance(parent, TableUnderlay):
            self.l.error("Table isn't actually a table: {!s}".format(type(parent)))
            raise TypeError("Invalid table object")

        self._idx = idx
        self._offset = offset
        self.parent = parent
        super().__init__(**kwargs)

    def clean(self):
        self.parent.clean()

    @property
    def offset(self):
        return self._offset

    @property
    def idx(self):
        return self._idx

class TableUnderlay(MutableSequence):
    @classmethod
    def static_init(cls, **kwargs):
        super(TableUnderlay, cls).static_init(**kwargs)
        cls.allowed_types = set()
        cls.primary_class = None

    @classmethod
    def parse_config_line(cls, key, entry):
        if key == 'ALLOWED_CLASS' and len(entry) == 1:
            cls.add_allowed_class(entry[0])
        elif key == 'ALLOWED_CLASS' and len(entry) == 2:
            cls.add_allowed_class(entry[0], tag=entry[1])
        else:
            super(TableUnderlay, cls).parse_config_line(key, entry)

    @classmethod
    def add_allowed_class(cls, classname, tag=None):
        name_array = classname.rsplit('.', 1)
        if len(name_array) != 2:
            cls.l.error("I don't know how to parse classname {:s}".format(classname))
            raise ValueError("Invalid class name")

        module_name = name_array[0]
        base_name = name_array[1]

        if module_name not in sys.modules:
            cls.l.error("I can't find module {:s}".format(module_name))
            raise ValueError("Unknown module")

        module = sys.modules[module_name]
        if not hasattr(module, base_name):
            cls.l.error("Module {:s} doesn't have an attribute named {:s}: {!s}".format(module_name, base_name, dir(module)))
            raise ValueError("Unknown module member")

        allowed_type = getattr(module, base_name)
        cls.allowed_types.add(allowed_type)


        if not issubclass(allowed_type, ItemUnderlay):
            cls.l.error("Allowed class {:s} is not a table item.".format(classname))
            raise TypeError("Invalid allowed type")

        if tag == "PRIMARY":
            cls.primary_class = allowed_type
        elif tag is not None:
            cls.l.error("Unknown tag for allowed class {:s}: {:s}".format(classname, tag))

    @classmethod
    def get_record(cls, data, idx, offset, parent, **kwargs):
        if cls.primary_class is None:
            cls.l.info("No primary class specified.  Either specify one, or consider a custom parser.")
            raise AttributeError("No primary class")
        obj = cls.primary_class(idx, offset, parent, **kwargs)
        obj.from_bytes(data[offset:])
        return obj

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.items = list()
        self.offset_to_item = dict()

    def __getitem__(self, idx):
        return self.items[idx]

    def __setitem__(self, idx, val):
        if type(val) not in self.allowed_types:
            self.l.error("Cannot accept item of type {!s}, only one of {!s}".format(type(val), self.allowed_types))
            raise TypeError("Item was not of allowed type.")
        self.items[idx] = val
        self.clean()

    def __delitem__(self, idx):
        del self.items[idx]
        self.clean()
 
    def __len__(self):
        return len(self.items)

    @property
    def length(self):
        return len(self.items)

    def insert(self, idx, val):
        if type(val) not in self.allowed_types:
            self.l.error("Cannot accept item of type {!s}, only one of {!s}".format(type(val), self.allowed_types))
        self.items.insert(idx, val)
        self.clean()

    def verify(self, root):
        out = True
        last_item = None
        offset = 0
        for i in range(0, len(self.items)):
            item = self.items[i]
            if item.idx != i:
                self.l.error("Index mismatch: expected {:d} but found {:d}".format(i, item.idx))
                out = False
            if item.offset != offset:
                self.l.error("Offset mismatch: expected {:d} but found {:d}".format(offset, item.offset))
                out = False
            elif offset not in self.offset_to_item or self.offset_to_item[offset] != item:
                self.l.error("Bad offset table: item {:d} was not available under offset {:d}".format(i, offset))
                out = False
            offset += item.size
        for item in self.items:
            out &= item.verify(root)
        return out

    def clean(self):
        offset = 0
        self.offset_to_item.clear()
        for idx in range(0, len(self.items)):
            item = self.items[idx]
            item._idx = idx
            item._offset = offset
            self.offset_to_item[offset] = item
            offset += item.size

    def from_bytes(self, data):
        offset = 0
        idx = 0
        while offset < len(data):
            item = self.get_record(data, idx, offset, self)
            self.items.append(item)
            self.offset_to_item[offset] = item
            offset += item.size
            idx += 1

    def to_bytes(self, write):
        out = 0
        for item in self.items:
            try:
                out += item.to_bytes(write)
            except Exception as e:
                raise Exception("Failed trying to write {!s}".format(type(item)), e)
        return out

    @property
    def size(self):
        out = 0
        for item in self.items:
            out += item.size
        return out

    def __getattr__(self, name):
        good = True
        for t in self.allowed_types:
            if not hasattr(t, name) or not callable(getattr(t, name)):
                self.l.debug("{:s} is missing a method named {:s}".format(t.__name__, name))
                good = False
        if not good:
            self.l.debug("Cannot call {:s} on this table; it's not a method of all items.".format(name))
            raise AttributeError("Invalid method reference")
        def func(*args, **kwargs):
            for item in self.items:
                getattr(item, name)(*args, **kwargs)
        return func

    def pprint(self):
        for item in self.items:
            print("{:d}[{:x}]: ".format(item.idx, item.offset))
            item.pprint()
