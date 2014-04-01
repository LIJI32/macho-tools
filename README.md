macho-tools
===========

Various Python tools for modifying Mach-O binaries.

macho-unsign
------------

macho-unsign can temporarily disable code signing for a Mach-O binary by replacing all code signing load commands with an invalid (and ignored) load command. It can later revert this change by replacing the invalid load command with the original load command. Tested on Intel binaries (32- and 64- bit, as well as fat binaries), but should also work with PPC and ARM binaries.
