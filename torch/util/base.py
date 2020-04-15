# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration

class TorchBase:
    def __init__(self, util):
        # Torch services are designed to run alone,
        # and to interface with other systems.
        # Util represents a class containing some basic services
        # that all torch services require; how it gets provided
        # depends on what's using Torch.
        self.args = util.args
        self.exec = util.exec
        self.l = util.l
        self.working_dir = util.working_dir
