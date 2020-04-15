# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from ..base import *
from .sections import types_to_sections, ELFProgBits

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8

class ELFSectionTable(TableUnderlay,
                      BaseObject):
    @classmethod
    def static_init(cls):
        super(ELFSectionTable, cls).static_init(config_path='sheader_table.tsf')
        cls.parse_config()

    @classmethod
    def get_sect_headers(cls, elffile):
        return elffile.sect_headers

    def __init__(self, byteorder='little', wordsize=4):
        super().__init__()
        self.byteorder = byteorder
        self.wordsize = wordsize

    def load_sections(self, data):
        for sheader in self.items:
            sheader.load_section(data)
    
    def get_sect_header_by_name(self, name):
        if isinstance(name, str):
            name = name.encode('ascii')
            name += b'\x00'
        for item in self.items:
            if item.get_referenced_object('sh_name') == name:
                return item
        self.l.error("Could not find section {!s}".format(name))
        raise Exception("Could not find section {!s}".format(name))

    def verify(self, elffile):
        out = True
        # Verify the section-to-segment map.
        in_a_segment = set()
        for segment in elffile.prog_headers:
            off_start = segment.p_offset
            off_end = off_start + segment.p_filesz

            for section in self:
                sect_start = section.sh_offset
                sect_end = sect_start + section.sh_size

                if sect_start >= off_start and sect_start < off_end:
                    in_a_segment.add(section)
                    # Verify that the section is inside the segment.
                    if sect_end > off_end:
                        self.l.error("Section {!s} ends outside its segment!!! Segment [{:x}, {:x}] vs Section [{:x}, {:x}]".format(section, off_start, off_end, sect_start, sect_end))
                        out = False

        # Verify offset integrity, memory integrity, and size integrity.
        off_sorted_items = list(self.items)
        off_sorted_items.sort(key=lambda x: x.sh_offset)
        for i in range(1, len(self.items)):

            item_a = off_sorted_items[i - 1]
            item_b = off_sorted_items[i]
            
            # Test if the two segmets overlap in the file.
            # Unless a segment is marked "NOBITS", it can't overlap
            # with another section.

            item_a_off_end = item_a.sh_offset + item_a.sh_size
            item_b_off_end = item_b.sh_offset + item_b.sh_size
            if item_a.sh_type == SHT_NOBITS or item_b.sh_type == SHT_NOBITS:
                pass
            elif item_a_off_end > item_b.sh_offset and item_b_off_end > item_a.sh_offset:
                self.l.error("Sections {!s} and {!s} OVERLAP in the file: 0x{:x} to 0x{:x} (size 0x{:x}) vs {:x}".format(item_a, item_b, item_a.sh_offset, item_a_off_end, item_a.sh_size, item_b.sh_offset))
                out = False
            
            # Check if either section is NOT part of a mapped segment.
            # Sections in the file can take up space, but 

            item_a_mem_end = item_a.sh_addr + item_a.sh_size
            item_b_mem_end = item_b.sh_addr + item_b.sh_size

            if not item_a in in_a_segment or not item_b in in_a_segment:
                # One of the sections isn't in a segment.
                # In that case, it doesn't make it into memory,
                # and we don't care about overlapping addresses.
                pass
            elif item_a_mem_end > item_b.sh_addr and item_b_mem_end > item_a.sh_addr:
                self.l.error("Sections {!s} and {!s} OVERLAP in the image: 0x{:x} to 0x{:x} (size 0x{:x}) vs {:x}".format(item_a, item_b, item_a.sh_addr, item_a_mem_end, item_a.sh_size, item_b.sh_addr))
                out = False

        # Verify alignment integrity
        for item in self.items:
            if item.sh_addralign != 0:
                addr_align = item.sh_addr % item.sh_addralign
                if addr_align != 0:
                    self.l.error("Section {!s} is out of alignment: {:x} mod {:d} == {:x}".format(item, item.sh_addr, item.sh_addralign, addr_align))
                    out = False


        return out

    def compute_diff(self, item_a_start, item_a_size, item_b_start, item_b_size, item_b_align):
        item_a_end = item_a_start + item_a_size
        item_b_end = item_b_start + item_b_size
        diff = 0
        # Only move if we need to, i.e.: the two sections overlap.
        if item_b_start < item_a_end:
            # Compute the difference to move.
            # Make sure that the difference will put the section
            # on an aligned address.
            diff = item_a_end - item_b_start
            if item_b_align != 0:
                mod = diff % item_b_align
                if mod != 0:
                    diff += (item_b_align - mod)
        return diff


    def organize(self, elffile):
        self.clean()
        # Deconflict overlaps between sections.
        off_sorted_items = list(self.items)
        off_sorted_items.sort(key=lambda x: x.sh_offset)

        # Check if our first section overlaps the program headers.
        item_b = off_sorted_items[0]
        diff = self.compute_diff(elffile.e_header.e_phoff, elffile.e_header.e_phentsize * elffile.e_header.e_phnum, item_b.sh_offset, item_b.sh_size, item_b.sh_addralign)
        if diff != 0:
            if item_b.sh_type == SHT_PROGBITS:
                self.l.error("Tried to move progbits section {!s}".format(item_b.get_referenced_object('sh_name')))
                raise Exception("Illegal Section Move")
            # Actually move the section.
            item_b.sh_offset += diff
            item_b.sh_addr += diff


        for i in range(1, len(self.items)):
            item_a = off_sorted_items[i - 1]
            item_b = off_sorted_items[i]
            # Ignore nobits sections.  They don't take up space in the object.
            if item_a.sh_type == SHT_NOBITS or item_b.sh_type == SHT_NOBITS:
                continue
            diff = self.compute_diff(item_a.sh_offset, item_a.sh_size, item_b.sh_offset, item_b.sh_size, item_b.sh_addralign)
            if diff != 0:
                if item_b.sh_type == SHT_PROGBITS:
                    self.l.error("Tried to move progbits section {!s}".format(item_b.get_referenced_object('sh_name')))
                    raise Exception("Illegal Section Move")

                # Actually move the section.
                item_b.sh_offset += diff
                item_b.sh_addr += diff



class ELFSectionHeader(ItemUnderlay,
                       ReferenceUnderlay,
                       PPrintUnderlay,
                       StructUnderlay,
                       BaseObject):
    @classmethod 
    def static_init(cls):
        super(ELFSectionHeader, cls).static_init(config_path='sheader.tsf')
        cls.add_alt_handler('get_referenced_object', cls.get_referenced_object)
        cls.add_table_lookup('get_shstrtab', cls.get_shstrtab)
        cls.add_table_lookup('get_section', cls.get_section)
        cls.add_table_lookup('get_sect_headers', cls.get_sect_headers)
        cls.parse_config()

    def __init__(self, idx, offset, parent):
        byteorder = parent.byteorder
        wordsize = parent.wordsize
        super().__init__(idx=idx, offset=offset, parent=parent, config_path='sheader.tsf', byteorder=byteorder, wordsize=wordsize)
        self.section = None

    def get_shstrtab(self, elffile):
        return elffile.sect_headers[elffile.e_header.e_shstrndx].section

    def get_section(self, *args):
        return self.section

    def get_sect_headers(self, elffile):
        return elffile.sect_headers

    def load_section(self, data):
        start = self.sh_offset
        end = self.sh_offset + self.sh_size
        bits = data[ start : end ]
        section_type = self.get_enum("sh_type", self.sh_type)
        if section_type in types_to_sections:
            out = types_to_sections[section_type](sheader=self, byteorder=self.byteorder, wordsize=self.wordsize)
            out.from_bytes(bits)
            self.section = out
        else:
            out = ELFProgBits()
            out.from_bytes(bits)
            self.section = out

    def resolve_references(self, root):
        super().resolve_references(root)
        if not isinstance(self.section, ELFProgBits):
            try:
                self.section.resolve_references(root)
            except AttributeError as e:
                pass

    def __str__(self):
        return str(self.get_referenced_object('sh_name'))

ELFSectionHeader.static_init()
ELFSectionTable.static_init()
