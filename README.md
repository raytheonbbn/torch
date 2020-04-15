# Torch

## Overview

Torch is a tool for making major modifications to binary object files.

Most existing tools, such as objcopy or Ghidra, can make minor changes to an object, but they lack the ability to update the file in the wake of major changes to memory layout or internal structure.  The result is a corrupted object; your changes may be present, but the old header information is now invalid.

Torch solves this problem by encoding a much deeper knowledge of the object file format into its representation.  This way, when you make an explicit change to the data stored in Torch structures, the program knows how to make any implicit changes required to keep the object file valid.

## Installation

### Compatibility

Torch is purely a Python program, so it should be runnable on any platform with the right interpreter.

It has only been tested on Fedora 29 and CentOS 7, so any other platform support is hypothetical.

It can currently only process GNU Linux ELF files; you can run it on windows, but it cannot parse windows executable files.

### Before you begin

Torch needs Python 3.7 or later to run, and a compatible version of pip to install.

- **Fedora:** `sudo dnf install python3 pip3`
- **Ubuntu:** `sudo apt install python3 python3-pip`
- **CentOS 7:** Python 3.7 is not available from yum.  Install manually. 

Currently, the torch package is only set up for a development installation.  It is strongly recommended that you install it within a python virtual environment: 

[https://docs.python-guide.org/dev/virtualenvs/](https://docs.python-guide.org/dev/virtualenvs/)

### Installation Process

The only step to installing Torch is to execute the setup script:

- **In a Python 3 virtualenv:** `python setup.py develop`
- **Bare Metal (NOT TESTED):** `sudo python3 setup.py develop`

You're done!  Edit object files at will!

## Using Torch

Torch exposes the following command line interface:

`torch [options] script`

The `script` argument is a path to a command script that tells torch which file to load, what to do with it, and where to save the results.  Documentation of the command language for each supported format can be found in the directory `tcf_spec`.

----------
Copyright (c) Raytheon BBN Technologies 2020, All Rights Reserved



