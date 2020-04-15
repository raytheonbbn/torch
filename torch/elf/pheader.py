# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from ..base import *

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6

class ELFProgramTable(TableUnderlay,
                      BaseObject):
    @classmethod
    def static_init(cls):
        super(ELFProgramTable, cls).static_init(config_path='pheader_table.tsf')
        cls.parse_config()

    def __init__(self, byteorder='little', wordsize=4):
        super().__init__()
        self.byteorder = byteorder
        self.wordsize = wordsize

    def verify(self, *args):
        out = True
        prev_segment = None
        sorted_items = list(self.items)
        sorted_items.sort(key=lambda x: x.p_vaddr)
        for segment in filter(lambda x: x.p_type == PT_LOAD, sorted_items):
            if prev_segment is not None:
                # Verify the overlap of the loadable segments.
                # I _THINK_ these can't overlap.
                prev_off_end = prev_segment.p_offset + prev_segment.p_filesz
                if prev_off_end > segment.p_offset:
                    self.l.error("Segments {:d} and {:d} overlap: {:x} vs {:x}".format(prev_segment.idx, segment.idx, prev_off_end, segment.p_offset))
                    out = False
            prev_segment = segment

        for segment in self.items:
            # Verify size agreement
            if segment.p_memsz < segment.p_filesz:
                self.l.error("Segment {:d} has to little memory for its contents: File Size {:d} vs Memory Size {:d}".format(segment.idx, segment.p_filesz, segment.p_memsz))
            # Verify address alignment
            if segment.p_align != 0:
                addr_align = segment.p_vaddr % segment.p_align
                off_align = segment.p_offset % segment.p_align
                if addr_align != off_align:
                    self.l.error("Segment {:d} was not properly aligned mod {:x}: addr {:x} -> {:x} != offset {:x} -> {:x}".format(segment.idx, segment.p_align, segment.p_vaddr, addr_align, segment.p_offset, off_align))
                    out = False

        return out


    def organize(self, elffile):
        # For every segment, ensure it's big enough for the data inside it.
        for segment in self.items:
            off_start = segment.p_offset
            off_end = off_start + segment.p_filesz

            # The DYNAMIC section needs special handling.
            # It must contain only and exactly the .dynamic section.
            if segment.p_type == PT_DYNAMIC:
                dyn_sect = elffile.sect_headers.get_sect_header_by_name('.dynamic')
                segment.p_offset = dyn_sect.sh_offset
                segment.p_vaddr = dyn_sect.sh_addr
                segment.p_paddr = dyn_sect.sh_addr
                segment.p_filesz = dyn_sect.sh_size
                segment.p_memsz = dyn_sect.sh_size

            else:
                for section in elffile.sect_headers:
                    sect_start = section.sh_offset
                    sect_end = sect_start + section.sh_size

                    if sect_start >= off_start and sect_start < off_end:
                        # If the section laps off the end of our segment, give it more room.
                        if sect_end > off_end:
                            diff = sect_end - off_end
                            self.l.info('Extending segment {:d} from 0x{:x} to 0x{:x} to give section {!s} more room.'.format(segment.idx, off_end, off_end + diff, section))
                            segment.p_filesz += diff
                            segment.p_memsz += diff 
                    elif sect_end >= off_start and sect_end < off_end:
                        if sect_start < off_start:
                            diff = sect_end - off_start
                            mod_diff = diff % 0x8
                            if mod_diff != 0:
                                diff += 0x8 - mod_diff

                            self.l.info("Shrinking segment {:d} from 0x{:x} to 0x{:x} to avoid section {!s}".format(segment.idx, off_start, off_start + diff, section))
                            segment.p_offset += diff
                            segment.p_vaddr += diff
                            segment.p_paddr += diff
                            segment.p_filesz -= diff
                            segment.p_memsz -= diff
            
                

class ELFProgramHeader(ItemUnderlay,
                       PPrintUnderlay,
                       StructUnderlay,
                       BaseObject):

    @classmethod
    def static_init(cls):
        super(ELFProgramHeader, cls).static_init(config_path='pheader.tsf')
        cls.parse_config()

    def __init__(self, idx, offset, parent):
        byteorder = parent.byteorder
        wordsize = parent.wordsize
        super().__init__(idx=idx, offset=offset, parent=parent, byteorder=byteorder, wordsize=wordsize)

ELFProgramHeader.static_init()
ELFProgramTable.static_init()
