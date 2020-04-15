# Torch Command Format: Overview

The Torch command language is a very simple batch scripting language.  The idea is that the user has already used tools like readelf, objdump, IDA pro, or Ghidra to figure out what they want to do with a binary, and now they just need a way to tell Torch to do it.

## File Format

Torch command files (extension `.tcf`, if you want) are lists of lines containing one of the following:

- Nothing
- A comment, begun with `#`
- A command.

Commands are comma-separated lists of strings, starting with the command name:

	COMMAND,arg1,arg2

Arguments are formatted specific to the command; see the references for specifics.  Some arguments may be null.  Null arguments are represented as an empty string; if the final argument of a command is null, leave a trailing comma:

	COMMAND,,arg2

	COMMAND,arg1,

## Universal Commands

## `LOAD`

Load a binary file.

**Arguments:**

- `format`: The object file format to expect.  Currently, the only valid value is `ELF`
- `path` The object file to load.

##`SAVE` 

Clean and verify the image, and save it to the specified file.

**Arguments:**

- `path`: Location to save the file.  Parent directory must exist.
- `overwrite`: String; may be `OVERWRITE` or empty.  If empty, torch will raise an error if `path` already exists.



