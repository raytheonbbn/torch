# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
import logging
import pathlib
import sys

class BaseObject:
    """
    Base class representing a structured data object.

    The job of this class is to serve as a backbone
    for all of the data processing underlay classes.
    As such, it just defines the mechanics for
    parsing a CSV config file that the underlays
    can use to configure themselves.

    It also defines functions that are present
    across all data structures; these must be implemented
    in at least one underlay extended by a final class.
    
    """

    @classmethod
    def static_init(cls, config_path=None):
        cls.l = logging.getLogger('torch.{:s}'.format(cls.__name__))
        if config_path is not None:
            source = sys.modules[cls.__module__].__file__
            cls.config_path = pathlib.Path(source).parent / config_path

    @classmethod
    def parse_config(cls):
        """
        Define this record's structure from a config file.

        Config files are CSV files containing several types of entries
        defined by the underlay classes combined with this module.
        """
        with open(cls.config_path, 'r') as f:
            val = f.readline().strip()
            while val != '':
                if not val.startswith('#'):
                    split = val.split(',', 1)
                    key = split[0]
                    entry = split[1].split(',')
                    cls.parse_config_line(key, entry)
                val = f.readline().strip()


    @classmethod
    def parse_config_line(cls, key, entry):
        if not key.startswith('#'): 
            cls.l.error("Invalid config line: {:s}: {!s}".format(key, entry))
            raise ValueError("Invalid config line")

    def __init__(self, **kwargs):
        """
        Constructor
        """

    @property
    def size(self):
        self.l.error("The 'size' property is not implemented.")
        raise NotImplementedError("Missing the size property")

    def from_bytes(self, data):
        self.l.error("The from_bytes method is not implemented.")
        raise NotImplementedError("Missing the from_bytes method")

    def verify(self, root):
        self.l.warn("The verify method is not implemented.")
        return False

    def organize(self, root):
        self.l.warn("The organize method is not implemented.")

    def to_bytes(self, write=None):
        self.l.error("The to_bytes method is not implemented.")
        raise NotImplementedError("Missing the to_bytes method")

    def __getattr__(self, name):
        raise AttributeError("No attribute '{:s}' on {!s}: {!s}".format(name, type(self), dir(self)))
