# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from ..util import *
class StructUnderlay:
    """
    Record underlay for defining struct parsing.

    This allows developers to define a binary structure
    in a config file, and have the program load such a struct
    into a python class from a byte stream.
    """

    @classmethod
    def static_init(cls, **kwargs):
        super(StructUnderlay, cls).static_init(**kwargs)
        cls.field_handlers = dict()
        cls.opt_handlers = dict()
        cls.names_32 = list()
        cls.names_64 = list()
        cls.names = {
            4: cls.names_32,
            8: cls.names_64
        }

        cls.parse_handlers_32 = list()
        cls.parse_handlers_64 = list()
        cls.parse_handlers = {
            4: cls.parse_handlers_32,
            8: cls.parse_handlers_64
        }

        cls.sizes_32 = list()
        cls.sizes_64 = list()
        cls.sizes = {
            4: cls.sizes_32,
            8: cls.sizes_64
        }
        
        cls.optional_fields = dict()

        cls.add_field_handler("as_is", lambda self, x, idx: x, lambda self, x, idx: x)
        cls.add_field_handler("as_int", cls.to_int, cls.from_int)

    @classmethod
    def to_int(cls, self, val, idx):
        return int.from_bytes(val, byteorder=self.byteorder)

    @classmethod
    def from_int(cls, self, val, idx):
        return val.to_bytes(cls.sizes[self.wordsize][idx], byteorder=self.byteorder)

    @classmethod
    def add_field(cls, name, handler, size_32=None, size_64=None):
        """
        Add a field definition to this struct.

        Fields are defined by their name,
        a loader method, and a size.

        Fields are read from the byte stream in the order in which
        they are defined using this method.

        Because some fields appear in a different order
        in 32-bit vs 64-bit formats, specifying
        only one size will add that field only for
        that one format.
        """
        if size_32 is not None:
            cls.names_32.append(name)
            cls.parse_handlers_32.append(handler)
            cls.sizes_32.append(size_32)

        if size_64 is not None:
            cls.names_64.append(name)
            cls.parse_handlers_64.append(handler)
            cls.sizes_64.append(size_64)

    @classmethod
    def add_optional(cls, name, handler):
        if name in cls.optional_fields:
            cls.l.error("Optional field {:s} already exists")
            raise AttributeError("Duplicate optional field registered.")
        cls.optional_fields[name] = handler


    @classmethod
    def add_field_handler(cls, name, to_handler, from_handler):
        """
        Add a field handler to this struct.

        Field handlers are a pair of functions;
        one translates a byte stream to the field value,
        the other translate that field value back into
        a byte stream.

        The signature should be as follows:
        - handler(data, field_idx): value
        """
        if name in cls.field_handlers:
            cls.l.error("Field handler {:s} already exists")
            raise AttributeErrror("Duplicate field handler registered.")
        cls.field_handlers[name] = (to_handler, from_handler)
   
    @classmethod
    def add_option_handler(cls, name, handler):
        if name in cls.opt_handlers:
            cls.l.error("Optional handler {:s} already exists".format(name))
            raise AttributeError("Duplicate optional handler registered.")
        cls.opt_handlers[name] = handler

    @classmethod
    def parse_config_line(cls, key, entry):
        if key == 'FIELD' and len(entry) == 4: 
            name = entry[0]
            
            if entry[1] not in cls.field_handlers:
                cls.l.error("Unknown field handler {:s}".format(entry[1]))
                raise ValueError("Invalid field handler")

            action = cls.field_handlers[entry[1]]
            
            if entry[2] == '':
                size_32=None
            else:
                size_32 = atoi(entry[2])

            if entry[3] == '':
                size_64=None
            else:
                size_64 = atoi(entry[3])
            cls.add_field(name, action, size_32=size_32, size_64=size_64)
        elif key == 'OPTION' and len(entry) == 2:
            name = entry[0]
            
            if entry[1] not in cls.opt_handlers:
                cls.l.error("Unknown option handler {:s}".format(entry[1]))
                raise ValueError("Invalid option handler")
            action = cls.opt_handlers[entry[1]]
            cls.add_optional(name, action)
        else:
            super(StructUnderlay, cls).parse_config_line(key, entry)

    def __init__(self, byteorder='big', wordsize=4, **kwargs):
        
        self.byteorder = byteorder
        self.wordsize = wordsize
        self.enabled_fields = []
        self.enabled_field_set = set()
        
        super().__init__(**kwargs)
     
    def from_bytes(self, data):
        off = 0
        for i in range(0, len(self.names[self.wordsize])):
            name = self.names[self.wordsize][i]

            # Check if this field is optional, and if we should read it.
            if name in self.optional_fields and not self.optional_fields[name](self, name):
                self.enabled_fields.append(False)
                continue
            else:
                self.enabled_fields.append(True)
                self.enabled_field_set.add(name)

            end = off + self.sizes[self.wordsize][i]
            bits = data[off:end]
            val = self.parse_handlers[self.wordsize][i][0](self, bits, i)
            setattr(self, name, val)
            off = end
        if len(self.enabled_fields) != len(self.names[self.wordsize]):
            self.l.error("Enabled fields can't account for all fields: expected {:d} records, got {:d}".format(len(self.enabled_fields), len(self.names[self.wordsize])))
            raise IndexError("Mismatched enabled fields and field names")

    def from_dict(self, data):
        for i in range(0, len(self.names[self.wordsize])):
            name = self.names[self.wordsize][i]
            if name in self.optional_fields and not self.optional_fields[name](self, name):
                self.enabled_fields.append(False)
                continue
            else:
                self.enabled_fields.append(True)
                self.enabled_field_set.add(name)

            if name not in data:
                raise AttributeError('Field {:s} is enabled, but not present in input: {!s}'.format(name, data.keys()))

            setattr(self, name, data[name])
        
        if len(self.enabled_fields) != len(self.names[self.wordsize]):
            self.l.error("Enabled fields can't account for all fields: expected {:d} records, got {:d}".format(len(self.enabled_fields), len(self.names[self.wordsize])))
            raise IndexError("Mismatched enabled fields and field names")

    def to_bytes(self, write):
        out = 0
        for i in range(0, len(self.names[self.wordsize])):
            if self.enabled_fields[i]:
                val = getattr(self, self.names[self.wordsize][i])
                data = self.parse_handlers[self.wordsize][i][1](self, val, i)
                write(data)
                out += len(data)
        return out

    @property
    def size(self):
        out = 0
        for i in range(0, len(self.sizes[self.wordsize])):
            if self.enabled_fields[i]:
                out += self.sizes[self.wordsize][i]
        return out

    def pprint(self):
        print(type(self).__name__)
        for i in range(0, len(self.names[self.wordsize])):
            if self.enabled_fields[i]:
                name = self.names[self.wordsize][i]
                val = getattr(self, name)
                txt = self.field_to_pstring(name, i, val)
                print("\t{:15s}\t{:s}".format(name, txt))

    def field_to_pstring(self, name, idx, val):
        if isinstance(val, int):
            length = self.sizes[self.wordsize][idx] * 2
            fmt = "0x{{:0{:d}x}}".format(length)
            return fmt.format(val)
        else:
            return str(val)
