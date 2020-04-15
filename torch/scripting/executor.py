# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
import logging
import pathlib
from .loader import Loader

class Executor:
    def __init__(self):
        self.l = logging.getLogger('torch')
        self.cmd_table = {
            "LOAD": self.load
        }

        self.help_table = []

        self.loader_table = dict()
        for subclass in Loader.__subclasses__():
            self.loader_table[subclass.name] = subclass
        self.binary = None

    def load(self, unused, loader, path):
        # DO NOT remove 'unused'.
        # Loader subclasses have a problem where
        # the entires in their command tables are functions,
        # not methods.  As such, we need to pass in 'self'
        # manually.  Since load() is a proper method,
        # we wind up passing in 'self' twice.
        if loader not in self.loader_table:
            return "Unknown loader: {:s}".format(loader)
        else:
            loader = self.loader_table[loader]

        if isinstance(path, str):
            path = pathlib.Path(path)

        if not path.exists():
            return "Cannot find file {!s}".format(path)

        self.binary = loader()
        self.cmd_table.update(self.binary.cmd_table)
        self.help_table = self.binary.help_table

        with open(path, 'rb') as f:
            data = f.read()
            self.binary.load(data)

        return None

    def execute(self, path):
        with open(path, 'r') as f:
            line = f.readline().strip()
            i = 0
            while line != '':
                if not line.startswith('#') and not line == '':
                    if not self.execute_line(line, i):
                        return 1
                i += 1
                line = f.readline().strip()
            return 0

    def execute_line(self, line, idx):
        cmd_arr = line.split(',')
        cmd = cmd_arr[0]
        if len(cmd_arr) > 1:
            args = cmd_arr[1:]
        else:
            args = []

        if cmd not in self.cmd_table:
            self.l.error("Unknown command on line {:d}: {:s}\n\t{:s}".format(idx, cmd, line))
            return False

        try:
            msg = self.cmd_table[cmd](self.binary, *args)
            if msg is not None:
                self.l.error("Command error on line {:d}: {:s}\n\t{:s}".format(idx, msg, line))
                return False
        except Exception as e:
            self.l.exception('Command error on line {:d}: {:s}\n\t{:s}'.format(idx, e.args[0], line))
            return False
        return True
        

