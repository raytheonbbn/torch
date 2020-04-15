# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
import inspect
import logging
from .help import HelpObj

def command(f):
    f.torch_cmd = True
    return f

def help(*helps, args=[], errors=[]):
    def make_type(f):
        f.torch_help = HelpObj(f.__name__.upper(), *helps, args=args, errors=errors)
        return f
    return make_type

class Loader:
    @classmethod
    def static_init(cls, name):
        cls.name = name
        cls.cmd_table = dict()
        cls.help_table = list()
        cls.l = logging.getLogger('torch.{:s}'.format(name))
        for (name, f) in inspect.getmembers(cls, predicate=inspect.isfunction):
            if hasattr(f, 'torch_cmd'):
                cls.cmd_table[name.upper()] = f 
            if hasattr(f, 'torch_help'):
                cls.help_table.append(f.torch_help)

    def load(self, data):
        raise AttributeError("load is not defined for {!s}".format(type(self)))
