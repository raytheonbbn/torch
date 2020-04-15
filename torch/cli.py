# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
import argparse
import logging
import pathlib
import subprocess
import sys
from .scripting.executor import Executor
from .elf import ELFLoader

class CLI:
    def __init__(self):
        self.args = self.parse_args()
        self.executor = Executor()

    def parse_args(self):
        parser = argparse.ArgumentParser('torch - carving objects out of binaries')
        parser.add_argument('-v', '--verbose', action='store_true',
                            help='Log all the things.')
        parser.add_argument('-l', '--log-file', action='store',
                            help='Write log data to a file.')
        parser.add_argument('script', help='Script path from which to read commands.')
        return parser.parse_args()

    def run(self):
        root_logger = logging.getLogger('torch')
        root_logger.setLevel('DEBUG')

        stream_handler = logging.StreamHandler(stream=sys.stdout)
        stream_handler.setLevel('DEBUG')
        root_logger.addHandler(stream_handler)

        file_handler = logging.FileHandler(self.args.script.replace('.tcf', '.log'), mode='w')
        file_handler.setLevel('DEBUG')
        root_logger.addHandler(file_handler)

        return self.executor.execute(self.args.script)


def main():
    cli = CLI()
    exit(cli.run())

if __name__ == "__main__":
    main()
