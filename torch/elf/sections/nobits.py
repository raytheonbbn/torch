# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from ...base import *
from .section import *

class ELFNoBits(BaseObject,
                ELFSection):
    types = frozenset([ 'NOBITS', 'NULL' ])
    @classmethod
    def static_init(cls):
        super(ELFNoBits, cls).static_init()

    def __init__(self, *args, **kwargs):
        self._size = 0

    def from_bytes(self, data):
        self._size = len(data)

    def verify(self, *args):
        return True

    def organize(self, *args):
        pass

    def resolve_references(self, *args):
        pass

    def to_bytes(self, write):
        return 0

    @property
    def size(self):
        return self._size

    def pprint(self):
        print("ELFNoBits[ {:d} bytes ]".format(self._size))
