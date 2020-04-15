# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from .dynamic import *
from .gnu_hash import *
from .nobits import *
from .progbits import *
from .rela import *
from .section import *
from .strtab import *
from .symtab import *
from .versym import *
from .verneed import *

types_to_sections = dict()
def all_subclasses(cls):
    return set(cls.__subclasses__()).union(
        [ s for c in cls.__subclasses__() for s in all_subclasses(c) ]
    )

for cls in all_subclasses(ELFSection):
    for t in cls.types:
        types_to_sections[t] = cls
