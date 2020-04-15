# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
class HelpObj:
    def __init__(self, cmd, *helps, args=[], errors=[]):
        self.cmd = cmd
        self.args = args
        self.helps = helps
        self.errors = errors

    def __str__(self):
        out = '{:s}'.format(self.cmd)
        if len(self.args) != 0:
            out += ',{:s}'.format(','.join(self.args))

        out += '\n\nDESCRIPTION:'
        for line in self.helps:
            out += '\n\t{:s}'.format(line)

        out += '\n\nErrors:'
        for error in self.errors:
            out += '\n\t{:s}'.format(error)

