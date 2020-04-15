# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from .elfheader import *
from .pheader import *
from .sheader import *

class ELFFile:
    def __init__(self):
        self.e_header = ELFFileHeader()
        self.byteorder = 'little'
        self.wordsize = 4
        self.prog_headers = None
        self.sect_headers = None

    def from_bytes(self, data):
        # Load the file header
        self.e_header.from_bytes(data)
        self.byteorder = self.e_header.byteorder
        self.wordsize = self.e_header.wordsize

        # Find and load the program headers
        self.prog_headers = ELFProgramTable(byteorder=self.byteorder, wordsize=self.wordsize)
        ph_start = self.e_header.e_phoff
        ph_end = ph_start + (self.e_header.e_phentsize * self.e_header.e_phnum)
        ph_data = data[ph_start:ph_end]
        self.prog_headers.from_bytes(ph_data)
        
        # Find and load the section headers
        self.sect_headers = ELFSectionTable(byteorder=self.byteorder, wordsize=self.wordsize)
        sh_start = self.e_header.e_shoff
        sh_end = sh_start + (self.e_header.e_shentsize * self.e_header.e_shnum)
        sh_data = data[sh_start:sh_end]
        self.sect_headers.from_bytes(sh_data)
        
        self.sect_headers.load_sections(data)

        # Resolve everyone's references.
        self.e_header.resolve_references(self)
        self.sect_headers.resolve_references(self)

    def object_to_bytes(self, f, obj, offset, filesize):
        if offset > filesize:
            diff = offset - filesize
            f.seek(0, 2)
            f.write(b'\x00' * diff)
        f.seek(offset)
        size = obj.to_bytes(f.write)
        if offset + size > filesize:
            return offset + size
        else:
            return filesize

    def to_bytes(self, f):
        file_size = 0
        file_size = self.object_to_bytes(f, self.e_header, 0, file_size)
        file_size = self.object_to_bytes(f, self.prog_headers, self.e_header.e_phoff, file_size)
        file_size = self.object_to_bytes(f, self.sect_headers, self.e_header.e_shoff, file_size)
        
        for sect_header in self.sect_headers:
            file_size = self.object_to_bytes(f, sect_header.section, sect_header.sh_offset, file_size)

    def verify(self):
        out = self.e_header.verify(self)
        out &= self.prog_headers.verify(self)
        out &= self.sect_headers.verify(self)
        for sect in map(lambda x: x.section, self.sect_headers):
            out &= sect.verify(self)
        return out

    def organize(self):
        self.e_header.organize(self)
        for sect in map(lambda x: x.section, self.sect_headers):
            sect.organize(self)
        self.sect_headers.organize(self)
        self.prog_headers.organize(self)
        
    def pprint(self):
        self.e_header.pprint()
        self.prog_headers.pprint()
        self.sect_headers.pprint()
        for sheader in self.sect_headers:
            print("SECTION {!s}:".format(sheader.get_referenced_object('sh_name')))
            sheader.section.pprint()
            print()
