# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
import pathlib
from ..scripting.loader import *
from .elffile import ELFFile
from .elfmanipulation import *

class ELFLoader(Loader):
    @classmethod
    def static_init(cls):
        super(ELFLoader, cls).static_init('ELF')

    def __init__(self):
        self.binary = ELFFile()
        self.loaded = False

    def load(self, data):
        if self.loaded:
            return "Loader already contains a binary."
        self.binary.from_bytes(data)
        self.loaded = True

    ##############
    #### SAVE ####
    ##############

    @command
    @help('Save the image to <path>', args=['path'], errors=[
        'Fails if the path already exists.',
        'Fails if there is no image loaded.',
        'Fails if the image fails verification.'])
    def save(self, path, overwrite):
        overwrite = (overwrite == "OVERWRITE")
        path = pathlib.Path(path)
        if path.exists() and not overwrite:
            return "Destination {!s} exists.".format(path)

        if not self.loaded:
            return "No binary loaded."

        self.l.info('Path: "{!s}"'.format(path))

        self.binary.organize()
        if not self.binary.verify():
            return "Binary failed verification."

        with open(path, 'wb+') as f:
            self.binary.to_bytes(f)
        path.chmod(0o744)

    @command
    @help('Pretty print <section>', args=['section'], errors=[
        'Fails if there is no section matching the name.'])
    def print(self, section):
        find_section_by_name(self.binary, section, False).pprint()

    @command
    @help('Rename <old_name> to <new_name>.',
            'Can target the .symtab and/or .dynsym tables,',
            'depending on if <which> is "STATIC", "DYNAMIC", or "BOTH".',
            '<permissive> arg can be set to "STRICT" to guarantee a swap,',
            'or "PERMISSIVE" to accept it if the symbol is not present.',
            args=['old_name', 'new_name', 'which', 'permissive'],
            errors=[
                'Fail if passed an unexpected argument to <which> or <permissive>'
                'Fail if a symbol is not present in the table and set to STRICT'
            ])
    def rename_symbol(self, old_name, new_name, which, permissive):
        if which not in { 'STATIC', 'DYNAMIC', 'BOTH' }:
            return "Unknown value for 'which': {:s}".format(which)
        if permissive not in { 'PERMISSIVE', 'STRICT' }:
            return "Unknown value for 'permissive': {:s}".format(permissive)

        rename_static = ( which == 'STATIC' or which == 'BOTH')
        rename_dynamic = (which == 'DYNAMIC' or which == 'BOTH')
        permissive = ( permissive != 'STRICT' )
        if rename_static:
            if rename_symbol_in_table(self.binary, old_name, new_name, '.symtab', permissive):
                self.l.info("Renamed {:s} to {:s} in the static symbol table".format(old_name, new_name))

        if rename_dynamic:
            if rename_symbol_in_table(self.binary, old_name, new_name, '.dynsym', permissive):
                self.l.info("Renamed {:s} to {:s} in the dynamic symbol table".format(old_name, new_name))

    @command
    @help("Set dynamic symbol <symbol_name>'s library version to <version>",
            "This is especially useful when overriding standard libaries.",
            "Generally, you will want to use the value 1, which defines",
            "a generic global symbol.  Other possible values are 0,",
            "which defines a local symbol, or other positive ints",
            "specifying a specific version of a particular library.",
            "use readelf -V on the original binary to determine valid values.",
            args=['symbol_name', 'version'],
            errors=[
                'Fails if <symbol_name> does not exist in .dynsym',
                'Fails if <version> is not a 16-bit positive int.',
                'Fails if <version> does not match a valid library version.',
                'Fails if there is no .dynamic section in the binary.',
                'Fails if the .dynamic section does not contain expected version data.' ])
    def set_symbol_version(self, symbol_name, version, permissive):
        version = int(version)
        permissive = (permissive == 'PERMISSIVE')
        if set_symbol_library_version(self.binary, symbol_name, version, permissive):
            self.l.info("Reset library version for {:s} to {:d}".format(symbol_name, version))


    @command
    def move_section(self, section_name, alignment):
        if move_section_to_end(self.binary, section_name, alignment):
            self.l.info("Moved section {:s} to the end of the program.".format(section_name))

    @command
    def make_segment(self, segment_type, segment_flags, segment_align, start_name, end_name):
        if add_segment_for_sections(self.binary, segment_type, segment_flags, segment_align, start_name, end_name):
            self.l.info("Added a segment covering {:s} to {:s}".format(start_name, end_name))
    @command
    def move_segment(self, segment_idx, start_name, end_name):
        if move_segment_for_sections(self.binary, segment_idx, start_name, end_name):
            self.l.info('Moved segment {:s} to cover {:s} to {:s}'.format(segment_idx, start_name, end_name))

    @command
    def make_dyn_tag(self, tag_name, val_str):
        if add_dynamic_tag(self.binary, tag_name, val_str):
            self.l.info('Added a dynamic tag {:s}: {:s}'.format(tag_name, val_str))

ELFLoader.static_init()
