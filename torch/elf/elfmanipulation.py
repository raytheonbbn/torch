# Copyright (c) 2020 Raytheon BBN Technologies, Inc.  All Rights Reserved.
# This document does not contain technology or Technical Data controlled under either
# the  U.S. International Traffic in Arms Regulations or the U.S. Export Administration
from .sections.dynamic import *
from .sections.strtab import ELFStrItem
from .pheader import ELFProgramHeader
from functools import reduce

def find_section_by_name(elffile, section_name, permissive):
    section = None
    for item in elffile.sect_headers:
        if item.get_referenced_object('sh_name') == section_name:
            section = item.section
            break
    if section is None:
        if not permissive:
            raise ValueError('Missing section named {:s}'.format(section_name))
        else:
            return None
    return section

def get_symbol_from_table(elffile, symbol_name, table_name, permissive):
    symtab = find_section_by_name(elffile, table_name, permissive)
    if symtab is None:
        return None
    for symbol in symtab:
        name = symbol.get_referenced_object('st_name')
        if name == symbol_name:
            return symbol
    if not permissive:
        raise ValueError('Missing symbol {:s} in {:s}'.format(symbol_name, table_name))
    else:
        return None

def rename_symbol_in_table(elffile, old_name, new_name, table_name, permissive):
    symbol = get_symbol_from_table(elffile, old_name, table_name, permissive)
    if symbol is None:
        return False
    symbol.get_referenced_object('st_name').from_string(new_name) 
    return True

def set_symbol_library_version(elffile, symbol_name, version, permissive):
    if version < 0 or version >= 2**16:
        raise ValueError('Version is outside allowed range (16-bit positive int): {:d}'.format(version))

    # Find the symbol
    symbol = get_symbol_from_table(elffile, symbol_name, '.dynsym', permissive)
    if symbol is None:
        return False

    # Find the versym and verneed sections from the .dynamic section
    dynamic = find_section_by_name(elffile, '.dynamic', False)
    verneed_tags = dynamic.get_tags_by_id(DT_VERNEED)
    versym_tags = dynamic.get_tags_by_id(DT_VERSYM)

    if len(verneed_tags) != 1:
        raise ValueError("Unexpected number of verneed tags: {:d}".format(len(verneed_tags)))
    if len(versym_tags) != 1:
        raise ValueError("Unexpected number of verneed tags: {:d}".format(len(versym_tags)))

    (verneed_tag,) = verneed_tags
    (versym_tag,) = versym_tags

    verneed = verneed_tag.get_referenced_object('d_ptr_verneed').section
    versym = versym_tag.get_referenced_object('d_ptr_versym').section

    # Check that the new version ID is valid.
    good = False
    if version != 0 and version != 1:
        for entry in verneed:
            for aux in entry.aux:
                if aux.vna_other == version:
                    good = True
                    break
        if not good:
            raise ValueError('Unknown version id: {:d}'.format(version))

    versym[symbol.idx].assign(version)
    return True

def move_section_to_end(elffile, section_name, alignment):
    # For now, this is the only sane way I can think to move a section.

    # Recover the alignment
    alignment = int(alignment, 16)

    # Find the relevant sections
    section = elffile.sect_headers.get_sect_header_by_name(section_name)

    # Find the last loaded address and offset
    far_off = 0
    far_addr = 0
    for item in elffile.sect_headers:
        end_off = item.sh_offset + item.sh_size
        end_addr = item.sh_addr + item.sh_size
        if far_off < end_off:
            far_off = end_off
        if far_addr < end_addr:
            far_addr = far_off = end_off
        if far_addr < end_addr:
            far_addr = end_addr

    # Make sure the new offset and address align.
    # This is done according to the rules for segment memory alignment
    # AND section memory alignment, so that mapping this section
    # into memory can go smoothly.

    # Ensure section alignment
    # Both the address and offset must be 0 mod sh_addralign.
    mod_addr = far_addr % section.sh_addralign
    mod_off = far_off % section.sh_addralign

    if mod_addr != 0:
        far_addr -= mod_addr
        far_addr += section.sh_addralign
    if mod_off != 0:
        far_off -= mod_off
        far_off += section.sh_addralign

    # Ensure segment alignment
    # The address and offset must be equal mod p_align
    # Since we don't know what the segment is,
    # the user has to provide p_align.
    mod_addr = far_addr % alignment
    mod_off = far_off % alignment

    if mod_addr < mod_off:
        far_addr -= mod_addr
        far_addr += mod_off

    if mod_addr > mod_off:
        far_addr -= mod_addr
        far_addr += alignment
        far_addr += mod_off

    print("Moving {:s} from {:x}/{:x} to {:x}/{:x}".format(section_name, section.sh_offset, section.sh_addr, far_off, far_addr))
   
    # Move the section to that address and offset
    old_index = section.idx
    section.sh_offset = far_off
    section.sh_addr = far_addr

    # Relocate it within the section list.
    elffile.sect_headers.items.pop(section.idx)
    elffile.sect_headers.items.append(section)
    elffile.sect_headers.clean()
    print("\t{:s} moved from index {:d} to {:d}".format(section_name, old_index, section.idx))
    return True

def move_segment_for_sections(elffile, segment_idx, start_name, end_name):
    segment_idx = int(segment_idx)
    start_sect = elffile.sect_headers.get_sect_header_by_name(start_name)
    end_sect = elffile.sect_headers.get_sect_header_by_name(end_name)

    if start_sect.sh_offset > end_sect.sh_offset:
        raise ValueError('Start section {:s} started after end section {:s}: {:x} vs {:x}'.format(start_name, end_name, start_sect.sh_offset, end_sect.sh_offset))
    
    segment = elffile.prog_headers.items[segment_idx]

    old_start = segment.p_vaddr
    old_end = old_start + segment.p_memsz

    segment.p_offset = start_sect.sh_offset
    segment.p_vaddr = start_sect.sh_addr
    segment.p_paddr = start_sect.sh_addr
    segment.p_filesz = end_sect.sh_offset + end_sect.sh_size - start_sect.sh_offset
    segment.p_memsz = end_sect.sh_addr + end_sect.sh_size - start_sect.sh_addr
    
    print('Moving segment {:d} from 0x{:x}/0x{:x} to 0x{:x}/0x{:x}'.format(segment_idx, old_start, old_end, segment.p_vaddr, segment.p_vaddr + segment.p_memsz))

    return True

def add_segment_for_sections(elffile, segment_type, segment_flags, segment_align, start_name, end_name):
    # Lookup table for segment types.  Really, loadable is the only valid one for now.
    ptypes = {
        'PT_LOAD': 1,
    }
    
    # Lookup table for segment flags
    pflags = {
        'E': 0x1,
        'W': 0x2,
        'R': 0x4
    }

    if segment_type not in ptypes:
        raise ValueError('Unknown segment type: {:s}'.format(segment_type))
    segment_type = ptypes[segment_type]

    segment_flags = set(segment_flags.split('|'))
    missing_flags = segment_flags - pflags.keys()
    if len(missing_flags) != 0:
        raise ValueError('Unknown segment flags: {!s}'.format(missing_flags))

    segment_flags = reduce(lambda x, y: x | y, map(lambda x: pflags[x], segment_flags), 0)
    
    segment_align = int(segment_align, 16)

    start_sect = elffile.sect_headers.get_sect_header_by_name(start_name)
    end_sect = elffile.sect_headers.get_sect_header_by_name(end_name)

    if start_sect.sh_offset > end_sect.sh_offset:
        raise ValueError('Start section {:s} started after end section {:s}: {:x} vs {:x}'.format(start_name, end_name, start_sect.sh_offset, end_sect.sh_offset))

    p_data = {
        'p_offset': start_sect.sh_offset,
        'p_vaddr':start_sect.sh_addr,
        'p_paddr': start_sect.sh_addr,
        'p_filesz': end_sect.sh_offset + end_sect.sh_size - start_sect.sh_offset,
        'p_memsz': end_sect.sh_addr + end_sect.sh_size - start_sect.sh_addr,
        'p_type': segment_type,
        'p_flags': segment_flags,
        'p_align': segment_align
    }
    
    idx = -1
    for i in map(lambda x: x.idx if x.p_type == 1 else -1, elffile.prog_headers):
        if i > idx:
            idx = i
    idx += 1
    pheader = ELFProgramHeader(0, 0, elffile.prog_headers)
    pheader.from_dict(p_data)

    elffile.prog_headers.insert(idx, pheader)
    elffile.prog_headers.clean()

def add_dynamic_tag(elffile, tag_name, val_str):
    # Get the dynamic metadata section
    sect_header = elffile.sect_headers.get_sect_header_by_name('.dynamic')
    dynamic = sect_header.section
    dynstr = dynamic.find_section_by_ptr_tag(DT_STRTAB).section

    if tag_name not in dt_vals:
        raise ValueError('Unknown dynamic tag {:s}'.format(tag_name))

    val_field_name = 'd_val_{:s}'.format(tag_name.lower().replace('dt_', ''))
    ptr_field_name = 'd_ptr_{:s}'.format(tag_name.lower().replace('dt_', ''))
    if val_field_name in ELFDynamicEntry.names[elffile.wordsize]:
        field_name = val_field_name
    elif ptr_field_name in ELFDynamicEntry.names[elffile.wordsize]:
        field_name = ptr_field_name
    else:
        raise ValueError('Could not reconstruct a field name for {:s}: tried {:s} and {:s}'.format(tag_name, val_field_name, ptr_field_name))

    str_offset = None
    for item in dynstr:
        if item == val_str:
            str_offset = item.offset
            break

    if str_offset is None:
        new_str = ELFStrItem(b'\x00', 0, 0, dynstr)
        dynstr.items.append(new_str)
        new_str.from_string(val_str)
        str_offset = new_str.offset

    tag_data = {
        'd_tag': dt_vals[tag_name],
        field_name: str_offset
    }
    new_tag = ELFDynamicEntry(0, 0, dynamic)
    new_tag.from_dict(tag_data)
    dynamic.items.insert(0, new_tag)
    dynamic.clean()
