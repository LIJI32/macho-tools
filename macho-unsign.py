#!/usr/bin/python

#
# This program can disable and restore  code signing in Mach-O binary files.  It
# is done by replacing every LC_CODE_SIGNATURE load command with an invalid load
# command  that is ignored  by the operating  system.  This allows safe and easy
# restoration  of the code  signature  without  having  to worry  about creating
# backups.
#
# It supports 32 and 64 bit Mach-O files on big and little endian platforms, but
# it was only tested on 64-bit OS X Intel binaries.  It should theortically work
# with iOS binaries as well.
#
# Exit codes:
# 0 - OK
# 1 - Invalid usages
# 2 - Read error
# 3 - Not a Mach-O
# 4 - File state does not match operation mode
# 5 - Write error
# 6 - Operation failed on some files.
# 7 - Mach-O is corrupted
import sys

MH_MAGIC_BIG_32 = "feedface".decode("hex")
MH_MAGIC_LITTLE_32 = MH_MAGIC_BIG_32[::-1]
MH_MAGIC_BIG_64 = "feedfacf".decode("hex")
MH_MAGIC_LITTLE_64 = MH_MAGIC_BIG_64[::-1]
FAT_MAGIC = "cafebabe".decode("hex")

# Mach-O
NCMDS_OFFSET = 16
HEADER_SIZE_32 = 28
HEADER_SIZE_64 = 32

# Fat Container
NFAT_ARCH_OFFSET = 4
FAT_HEADER_SIZE = 8
FAT_ARCH_OFFSET_OFFSET = 8
FAT_ARCH_SIZE = 20

LC_CODE_SIGNATURE = 0x1d
UNSIGN_MAGIC = 0x1337c0de

def parse_int(data):
    global is_little_endian
    if is_little_endian:
        data = data[::-1]

    return int(data.encode("hex"), 16)
    
def encode_int(number, size):
    global is_little_endian
    data = ("%%0%dx" % (size * 2, ) % (number, )).decode("hex")
    
    if is_little_endian:
        data = data[::-1]
    
    return data

def replace_chunk(data, offset, new_data):
    return data[:offset] + new_data + data[offset+len(new_data):]

def unsign(mode, input, options=[]):
    global is_little_endian
    
    is_little_endian = False
    
    verbose = 'v' in options
    force = 'f' in options
    
    message_prefix = "%s: " % (input)
    
    if verbose:
        if mode == "state":
            print message_prefix
        else:
            print >> sys.stderr, message_prefix
        message_prefix = ""
    
    try:
        with open(input) as f:
            data = f.read()
    except Exception as e:
        print >> sys.stderr, "%sCould not read file (%s)" % (message_prefix, e)
        return 2
        
    try:
        if data[0:4] == FAT_MAGIC:
            nfat_arch = parse_int(data[NFAT_ARCH_OFFSET:NFAT_ARCH_OFFSET + 4])
            archs = []
            arch_offsets = []
            
            for i in xrange(0, nfat_arch):
                archs += [parse_int(data[FAT_HEADER_SIZE + FAT_ARCH_SIZE * i + FAT_ARCH_OFFSET_OFFSET:
                                         FAT_HEADER_SIZE + FAT_ARCH_SIZE * i + FAT_ARCH_OFFSET_OFFSET + 4])]
    
            if verbose:
                print >> sys.stderr, "File is a fat binary with %d architechtures" % (nfat_arch)
        else:
            archs = [0]
            
        for base_offset in archs:
            
            if base_offset != 0 and verbose:
                print >> sys.stderr, "Sub-file at %08x:" % (base_offset,)
        
            if data[base_offset:base_offset + 4] == MH_MAGIC_LITTLE_32:
                if verbose:
                    print >> sys.stderr, "File is a 32-bit little endian Mach-O"
                is_little_endian = True
                header_size = HEADER_SIZE_32
                
            elif data[base_offset:base_offset + 4] == MH_MAGIC_LITTLE_64:
                if verbose:
                    print >> sys.stderr, "File is a 64-bit little endian Mach-O"
                is_little_endian = True
                header_size = HEADER_SIZE_64
                        
            elif data[base_offset:base_offset + 4] == MH_MAGIC_BIG_32:
                if verbose:
                    print >> sys.stderr, "File is a 32-bit big endian Mach-O"
                is_little_endian = False
                header_size = HEADER_SIZE_32
                
            elif data[base_offset:base_offset + 4] == MH_MAGIC_BIG_64:
                if verbose:
                    print >> sys.stderr, "File is a 64-bit big endian Mach-O"
                is_little_endian = False
                header_size = HEADER_SIZE_64
                
            else:
                print >> sys.stderr, message_prefix + "File is not a valid Mach-O"
                return 3
            
            ncmds = parse_int(data[base_offset + NCMDS_OFFSET:base_offset + NCMDS_OFFSET + 4])
            
            if verbose:
                print >> sys.stderr, "File has %d load commands" % (ncmds,)
            
            current_offset = base_offset + header_size;
            found_sig = False
            found_magic = False
            
            for i in xrange(0, ncmds):
                command = parse_int(data[current_offset:current_offset+4])
                size = parse_int(data[current_offset + 4:current_offset+8])
                
                if size < 8: # Avoid infinite loops
                    print >> sys.stderr, message_prefix + "Mach-O is corrupted"
                    return 7
                
                if command == LC_CODE_SIGNATURE:
                    if verbose:
                        print >> sys.stderr, "Found code signature"
                        
                    found_sig = True
                    
                    if mode == "disable":
                        data = replace_chunk(data, current_offset, encode_int(UNSIGN_MAGIC, 4))
                        
                elif command == UNSIGN_MAGIC:
                    if verbose:
                        print >> sys.stderr, "Found disabled code signature"
                        
                    found_magic = True
                    
                    if mode == "restore":
                        data = replace_chunk(data, current_offset, encode_int(LC_CODE_SIGNATURE, 4))
                
                current_offset += size

    except: # Corrupted files will cause out-of-bound access
        print >> sys.stderr, message_prefix + "Mach-O is corrupted"
        return 7
    
    if mode == "disable":
        if found_sig:
            message = "Successfully disabled code signing"
            rc = 0
            
            if found_magic:
                print >> sys.stderr, message_prefix + "File is in a mixed state."
                if not force:
                    rc = 8
                    message = "File not modifyed, used -f to force."
            
        elif found_magic:
            message = "Code signing already disabled"
            rc = 4
        
        else:
            message = "File is not code signed"
            rc = 4
            
    elif mode == "restore":
        if found_magic:
            message = "Successfully restored code signing"
            rc = 0
            
            if found_sig:
                print >> sys.stderr, message_prefix + "File is in a mixed state."
                if not force:
                    rc = 8
                    message = "File not modifyed, used -f to force."
            
        elif found_sig:
            message = "Code signing is not disabled"
            rc = 4
        
        else:
            message = "File was never code signed"
            rc = 4
            
    elif mode == "state":
        rc = 0
        
        if found_sig:
            message = "File is signed"
            
        elif found_magic:
            message =  "File has disabled signing"

        else:
            message =  "File is not signed"
    
    if mode != "state" and rc == 0:
        try:
            with open(input, "w") as f:
                f.write(data)
        except Exception as e:
            print >> sys.stderr, "%sCould not write file (%s)" % (message_prefix, e)
            return 5
    
    message = message_prefix + message
    
    if mode != "state":
        print >> sys.stderr, message
    else:
        print message

    return rc
    
        
if __name__ == "__main__":

    help = \
"""Usage: %s [-vf] (disable | restore | state) files...

Operations:
disable: Disable code signatures on the input files
restore: Restore a previously disabled code signature on the input files
state: Output the state of the input files without modifying them

Flags:
-v: Verbose, print additional data while processing
-f: Force disabling and restoring signatures even if the file has a mixed state
""" % (sys.argv[0], )    
    arguments = []
    options = []
    
    for arg in sys.argv[1:]:
        if arg == "--help" or arg == "-h":
            print >> sys.stderr, help
            exit(0)
            
        if arg[0] == '-':
            for c in arg[1:]:
                options += c
        else:
            arguments += [arg]
    
    if len(arguments) < 2 or arguments[0] not in ['disable', 'restore', "state"]:
        print >> sys.stderr, "Usage: %s [-vf] (disable | restore | state) files..." % (sys.argv[0], )
        exit(1)
    
    if len(arguments) == 2:
        exit(unsign(arguments[0], arguments[1], options))
    else:
        rc = 0
        for f in arguments[1:]:
            rc += unsign(arguments[0], f, options)
            if "v" in options:
                print >> sys.stderr, ""
            
        if rc:
            print >> sys.stderr, "Operation failed for one or more files."
            exit(6)
        exit(0)