# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from ...base import *

class ELFProgBits(BaseObject):
    @classmethod
    def static_init(cls):
        super(ELFProgBits, cls).static_init()

    def __init__(self, *args, **kwargs):
        self.data = None

    def from_bytes(self, data):
        self.data = data

    def to_bytes(self, write):
        write(self.data)
        return len(self.data)

    def verify(self, *args):
        return True

    def organize(self, *args):
        pass

    def resolve_references(self):
        pass

    @property
    def size(self):
        return len(self.data)

    def pprint(self):
        print("ELFProgBits[ {:d} bytes ]".format(len(self.data)))

ELFProgBits.static_init()
