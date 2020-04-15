# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from ..util import *

class PPrintUnderlay:
    @classmethod
    def static_init(cls, **kwargs):
        super(PPrintUnderlay, cls).static_init(**kwargs)
        cls.enums = dict()
        cls.bitmasks = dict()
        cls.alts = dict()
        cls.alt_handlers = dict()


    @classmethod
    def parse_config_line(cls, key, entry):
        if key == 'ENUM' and len(entry) == 3:
            cls.add_enum(entry[0], atoi(entry[1]), entry[2])
        elif key == 'BITMASK' and len(entry) == 3:
            cls.add_bitmask(entry[0], atoi(entry[1]), entry[2])
        elif key == 'ALT' and len(entry) == 2:
            cls.add_alt(entry[0], entry[1])
        else:
            super(PPrintUnderlay, cls).parse_config_line(key, entry)

    @classmethod
    def add_enum(cls, name, val, display):
        cls.enums.setdefault(name, dict())[val] = display

    @classmethod
    def get_enum(cls, name, val):
        if name not in cls.enums:
            cls.l.error("{:s} doesn't appear to be an enum field")
            raise AttributeError("Invalid enum field")
        if val in cls.enums[name]:
            return cls.enums[name][val]
        else:
            return None

    @classmethod
    def add_bitmask(cls, name, val, display):
        cls.bitmasks.setdefault(name, dict())[val] = display
    
    @classmethod
    def get_bitmasks(cls, name, val):
        out = set()
        if name not in cls.bitmasks:
            cls.l.error("{:s} doesn't appear to be a bitmask field.")
            raise AttributeError("Invalid bitmask field")
        for mask in cls.bitmasks[name]:
            if mask & val != 0:
                out.add(cls.bitmasks[name][mask])
                val &= ~mask
        if val != 0:
            out.add("UNKNOWN ({:d})".format(val))
        return out

    @classmethod
    def add_alt_handler(cls, h_name, handler):
        cls.alt_handlers[h_name] = handler

    @classmethod
    def add_alt(cls, name, h_name):
        if h_name not in cls.alt_handlers:
            cls.l.error("Missing alt handler {:s} for field {:s}".format(h_name, name))
            raise AttributeError("Invalid alt handler")
        cls.alts[name] = cls.alt_handlers[h_name]

    def field_to_pstring(self, name, idx, val):
        if name in self.enums:
            enum = self.get_enum(name, val)
            if enum is not None:
                return enum
        elif name in self.bitmasks:
            return " | ".join(self.get_bitmasks(name, val))
        elif name in self.alts:
            return "{!s}".format(self.alts[name](self, name))
        return super().field_to_pstring(name, idx, val) 
