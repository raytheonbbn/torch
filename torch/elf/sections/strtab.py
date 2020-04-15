# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from ...base import *
from .section import *
from collections.abc import ByteString

class ELFStrItem(ByteString,
                 ItemUnderlay):
    def __init__(self, data, idx, offset, parent):
        super().__init__(idx=idx, offset=offset, parent=parent)
        self.data = data

    def __getitem__(self, idx):
        return self.data[idx]
    
    def __len__(self, idx):
        return len(self.data)

    def __str__(self):
        return str(self.data)

    def __eq__(self, other):
        if isinstance(other, bytes):
            return self.data == other
        elif isinstance(other, str):
            other = other.encode('ascii')
            other += b'\x00'
            return self.data == other
        elif isinstance(other, ELFStrItem):
            return self.data == other.data
        else:
            return False

    def from_string(self, new_val):
        if isinstance(new_val, str):
            new_val = new_val.encode('ascii')
            new_val += b'\x00'
        if not isinstance(new_val, bytes):
            raise TypeError('Cannot assign ELF string from {!s}'.format(type(new_val)))
        self.data = new_val
        self.clean()

    def to_bytes(self, write):
        write(self.data)
        return len(self.data)

    @property
    def size(self):
        return len(self.data)

    def verify(self, root):
        if not self.data[-1] == 0:
            self.l.error("String entry {!s} was not null-terminated.".format(self))
            return False
        return True

    def pprint(self):
        print(self.data)

class ELFStrTab(TableUnderlay,
                BaseObject,
                ELFSection):
    types = frozenset([ 'STRTAB' ])

    @classmethod
    def static_init(cls):
        super(ELFStrTab, cls).static_init(config_path='strtab.tsf')
        cls.parse_config()

    @classmethod
    def get_record(cls, data, idx, offset, parent):
        end = data.index(0, offset)
        bits = data[offset:end + 1]
        return ELFStrItem(bits, idx, offset, parent)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def get_item_by_offset(self, off):
        """
        Get a string by its offset.

        strtab structures do a nasty where they overlap strings by suffix.
        For example, it won't store 'vfprintf', 'fprintf', and 'printf'
        as separate strings; it will just store 'vfprintf', and reference
        the three as offset, offset + 1, and offset + 2 respectively.

        If we run into this, deduplicate the string.
        """
        if off not in self.offset_to_item:
            closest_off = -1
            for k in self.offset_to_item:
                if k < off and k > closest_off:
                    closest_off = k
            diff = off - closest_off
            new_str = self.offset_to_item[closest_off][diff:]
            item = ELFStrItem(new_str, 0, 0, self)
            self.append(item)
            off = item.offset
        return self.offset_to_item[off]

    def organize(self, *args):
        self.clean()

ELFStrTab.static_init()
