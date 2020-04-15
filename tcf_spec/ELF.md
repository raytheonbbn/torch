# Torch Command Format: GNU Linux ELF

## `PRINT`

Pretty-print the contents of a section.

**Arguments:**

- `section`: The name of the section to print.

## `RENAME_SYMBOL`

Rename a linker symbol.  This is capable of renaming
static and dynamic symbols.

**Arguments:**

- `old_name`: The current name of the symbol
- `new_name`: The new name for the symbol
- `which`: Specify which symbol table to modify.  Can be `STATIC`, `DYNAMIC`, or `BOTH`.
- `permissive`: Can be `PERMISSIVE` or `STRICT`.  If `STRICT`, this command will throw an error if the named symbol does not exist in one or more of the tables being modified.

**Errors:**

- Fails if `which` or `permissive` are set to invalid values.
- Fails if `permissive` is set to `STRICT`, and `old_name` is not found in one of the tables asked to modify.

## `SET_SYMBOL_VERSION`

Change the library version reference number for a dynamic symbol.  This is especially useful when overriding standard libraries; you can change the version of a symbol's definition and reference to ensure that your copy gets linked against.

Generally, you will want to use `1`, which is the "global" version.  Other possible values are `0`, which means the symbol is local and shouldn't be exported, and other positive 16-bit integers, which specify versions defined by specific libraries.  Use `readelf -V` to view the current library versions defined by the binary, used by it, and what their reference numbers are.

**Arguments:**
- `symbol`: The name of the symbol to modify.
- `version`: The new version reference number.
- `permissive`: Can be `PERMISSIVE` or `STRICT`.  If not permissive, this will throw an error if the symbol is not present in the table. 

**Errors:**

- Fails if `symbol` does not exist in the dynamic symbol section of the binary.
- Fails if `version` is not a 16-bit non-negative integer.
- Fails if `version` is not a version reference number present in the binary.
- Fails if there is no `.dynamic` section in the binary.
- Fails if the `.dynamic` section does not reference symbol version tables.

## `MOVE_SECTION`

Move the specified section to the end of the program image.

This is currently the only way to handle sections that have grown beyond their original size without space to accommodate them.  Generally, it's a good idea to use this if you're editing a section.

**Arguments:**
- `section`: Name of the section to move.
- `alignment`: The address alignment value to use.  Must be a positive power of two.

**Errors:**

- Fails if `section` is not the name of a section.
- Fails if `section` is marked `PROGBITS`.  These sections contain information not controlled by the ELF format, so Torch can't update their data or anything that references them to account for their change in position.  This may be relaxed in the future as understanding of specific sections gets added.

## `MAKE_SEGMENT`

Create a new program segment covering a range of sections.  Section names are used in place of addresses, since concrete addresses of sections may change.

This needs to be used after `MOVE_SECTION` to ensure that the relocated sections are loaded.

Note that the start and end sections may be the same, so the new segment will cover just that section.

**Arguments:**

- `segment_type`: The type of segment to create.  See the ELF program header spec for possible values.
- `segment_flags`: A `|` delimited series of flag names to use.  See the ELF program header spec for possible values.
- `segment_align`: The alignment value for the segment.  Must be a non-negative power of two.  Use `readelf -l` to look at the existing sections in the binary to determine an appropriate value for the type you want to create; it's different for different types of ELF object.
- `start_section`: The lowest-addressed program section to cover.
- `end_section`: The highest-addressed program section to cover.

**Errors:**

- Fails if `segment_type`, `segment_flags`, or `segment_align` are invalid.
- Fails if `start_section` or `end_section` don't exist.
- Fails if `start_section` appears after `end_section` in the address space.

## `MOVE_SEGMENT`

Moves a segment to cover a range of sections.  Section names are used instead of addresses, since concrete addresses of sections may change.

This is useful to guarantee that a section that must reside in a specific segment does so.

Note that the start and end sections may be the same, meaning the segment will cover only that section.

**Arguments:**

- `segment_idx`: The index of the segment in the program header table.  Note that, since loadable segments must be presented in address order, your moved segment may appear at a different index after the image is verified and saved.
- `start_section`: The lowest-addressed program section to cover.
- `end_section`: The highest-addressed program section to cover.

**Errors:**

- Fails if `segment_idx` is outside the range of the program header list.
- Fails if `start_section` begins after `end_section`.

## `MAKE_DYN_TAG`

Add a tag to the `.dynamic` section of the binary.  This allows you to update the dynamic linking metadata.  It's especially useful to add required libraries or alter the file-specific runtime linker search path.

**Arguments:**

- `tag_name`: The type of tag to add.
- `val_str`: The string value of the tag.  Dynamic tags can take multiple values depending on their type, but Torch can currently only modify those that take a text string.  (Most of the rest are reference metadata to other sections, and should not be manually altered.)

**Errors:**

- Fails if `tag_name` is not a recognized tag.
- Fails if `tag_name` does not take a string value.