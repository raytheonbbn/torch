# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
import pathlib
from ..base import *
from ..base.util import *
from .sheader import SHT_STRTAB

class ELFFileHeader(ReferenceUnderlay,
                    PPrintUnderlay,
                    StructUnderlay,
                    BaseObject):
    @classmethod
    def static_init(cls):
        super(ELFFileHeader, cls).static_init(config_path='elfheader.tsf')
        cls.add_field_handler('get_byteorder', cls.get_byteorder, cls.from_int)
        cls.add_field_handler('get_wordsize', cls.get_wordsize, cls.from_int)
        cls.add_table_lookup('get_segment_list', cls.get_segment_list)
        cls.add_table_lookup('get_section_list', cls.get_section_list)
        cls.parse_config()
    
    def __init__(self):
        super().__init__()

    @classmethod
    def get_byteorder(cls, self, bits, idx):
        val = self.to_int(self, bits, idx)
        if val == 1:
            self.byteorder = 'little'
        elif val == 2:
            self.byteorder = 'big'
        else:
            raise ValueError('Unexpected value for ei_class: {:x}'.format(val))
        return val

    @classmethod
    def get_wordsize(cls, self, bits, idx):
        val = self.to_int(self, bits, idx)
        if val == 1:
            self.wordsize = 4
        elif val == 2:
            self.wordsize = 8
        else:
            raise ValueError('Unexpected value for ei_data: {:x}'.format(val))
        return val

    def get_section_list(self, elffile):
        return elffile.sect_headers

    def get_segment_list(self, elffile):
        return elffile.prog_headers

    def range_overlap(self, x, y):
        return x[0] < y[1] and y[0] < x[1]

    def range_string(self, start, end):
        return "[ {:x}, {:x} ]".format(start, end)


    def verify(self, elffile):
        out = True
        # Verify the value of ei_class (wordsize indicator)
        if self.ei_class > 2 or self.ei_class < 1:
            self.l.error("Invalid ei_class value: {:d}".format(self.ei_class))
            out = False
        if self.ei_class == 1 and self.wordsize != 4:
            self.l.error("ei_class specified for 4-byte words, but struct says {:d} bytes".format(self.wordsize))
            out = False
        if self.ei_class == 2 and self.wordsize != 8:
            self.l.error("ei_class specified for 8-byte words, but struct says {:d} bytes".format(self.wordsize))
            out = False

        # Verify the value of ei_data (byteorder indicator)
        if self.ei_data > 2 or self.ei_class < 1:
            self.l.error("Invaid ei_data value: {:d}".format(self.ei_class))
            out = False
        if self.ei_data == 1 and self.byteorder != 'little':
            self.l.error("ei_data specified little endian, but struct says {!s} endian".format(self.byteorder))
            out = False
        if self.ei_data == 2 and self.byteorder != 'big':
            self.l.error("ei_data specified big endian, but struct says {!s} endian".format(self.byteorder))
            out = False

        # Verify that we have the same number of program headers as expected.
        if len(elffile.prog_headers) != self.e_phnum:
            self.l.error("Recorded {:d} program headers, but table contains {:d}".format(self.e_phnum, len(elffile.prog_headers)))
            out = False

        # Verify that the size of a program table entry is correct.
        if self.e_phnum != 0 and elffile.prog_headers[0].size != self.e_phentsize:
            self.l.error("Recorded program header size is {:d}, but structs are of size {:d}".format(elffile.prog_headers[0].size != self.e_phentsize))
            out = False

        # Verify that we have the same number of section headers as expected.
        if len(elffile.sect_headers) != self.e_shnum:
            self.l.error("Recorded {:d} section headers, but table contains {:d}".format(self.e_shnum, len(elffile.sect_headers)))
            out = False
        # Verify that the size of a section table entry is correct.
        if self.e_shnum != 0 and elffile.sect_headers[0].size != self.e_shentsize:
            self.l.error("Recorded section header size is {:d}, but structs are of size {:d}".format(elffile.sect_headers[0].size, self.e_shentsize))
            out = False

        ph_start = self.e_phoff
        ph_end = ph_start + self.e_phnum * self.e_phentsize
        ph_range = (ph_start, ph_end)
        ph_str = self.range_string(ph_start, ph_end)

        sh_start = self.e_shoff
        sh_end = sh_start + self.e_shnum * self.e_shentsize
        sh_range = (sh_start, sh_end)
        sh_str = self.range_string(sh_start, sh_end)

        eh_range = (0, self.size)
        eh_str = self.range_string(0, self.size)
        
        # Verify that the program headers and the elf header don't overlap
        if self.range_overlap(ph_range, eh_range):
            self.l.error("Program headers overlap elf header: {:s} vs {:s}".format(ph_str, eh_str))
            out = False

        # Verify that the section headers and the elf header don't overlap
        if self.range_overlap(sh_range, eh_range):
            self.l.error("Section headers overlap elf header: {:s} vs {:s}".format(sh_str, eh_str))
            out = False

        # Verify that the program headers and section headers don't overlap
        if self.range_overlap(ph_range, sh_range):
            self.l.error("Program headers overlap section headers: {:s} vs {:s}".format(ph_str, sh_str))
            out = False

        # Verify that the program headers and section headers don't overlap a section.
        for sheader in elffile.sect_headers:
            sect_range = (sheader.sh_offset, sheader.sh_offset + sheader.sh_size)
            sect_str = self.range_string(sect_range[0], sect_range[1])
            if self.range_overlap(ph_range, sect_range):
                self.l.error("Program headers overlap section {!s}: {:s} vs {:s}".format(sheader, ph_str, sect_str))
                out = False
            if self.range_overlap(sh_range, sect_range):
                self.l.error("Section headers overlap section {!s}: {:s} vs {:s}".format(sheader, sh_str, sect_str))
                out = False


        # Verify that the program headers fit in their segment, if any.

        # Verify that e_shstrndx specifies a string table section.
        shstrtab_type = self.get_referenced_object('e_shstrndx').sh_type
        if shstrtab_type != SHT_STRTAB:
            self.l.error("Section {:d}, specified as the section header string table, is not a string table: type {:d}".format(self.e_shstrndx, shstrtab_type))
            out = False
        return out

    def organize(self, elffile):
        elffile.sect_headers.organize(elffile)
        # Hack; put the section headers after the last section.
        # Unhack; the last section isn't always the last one in the list :p
        last_off = 0
        for sect in elffile.sect_headers:
            end = sect.sh_offset + sect.sh_size
            if end > last_off:
                last_off = end

        self.e_shoff = last_off
        

ELFFileHeader.static_init()
