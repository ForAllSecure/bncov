#!/usr/bin/env python

from struct import unpack
from os.path import basename

# Handle parsing files into sets of addresses, each describing the start of a basic block
# Can be invoked as a standalone script for debugging purposes


def detect_format(filename):
    """Return the name of the format based on the start of the file."""
    enough_bytes = 0x1000
    with open(filename, 'rb') as f:
        data = f.read(enough_bytes)
    if isinstance(data, bytes):
        data = data.decode(errors='replace')

    if data.startswith('DRCOV VERSION: 2'):
        return 'drcov'
    if '+' in data:
        # Check for module+offset, skipping any comment lines at start
        for line in data.split('\n'):
            if line.strip().startswith(';'):
                continue
            pieces = line.split('+')
            if len(pieces) == 2:
                try:
                    hex_int = int(pieces[1], 16)
                    return 'module+offset'
                except ValueError:
                    pass
    raise Exception('[!] File "%s" doesn\'t appear to be drcov or module+offset format' % filename)


def parse_coverage_file(filename, module_name, module_base, module_blocks, debug=False):
    """Return a set of addresses of covered blocks in the specified module"""
    file_format = detect_format(filename)
    if file_format == 'drcov':
        blocks = parse_drcov_file(filename, module_name, module_base, module_blocks)
    elif file_format == 'module+offset':
        blocks = parse_mod_offset_file(filename, module_name, module_base, module_blocks)
    return blocks


def parse_mod_offset_file(filename, module_name, module_base, module_blocks, debug=False):
    """Return blocks from a file with "module_name+hex_offset" format."""
    blocks = set()
    modules_seen = set()
    # We do a case-insensitive module name comparison to match Windows behavior
    module_name = module_name.lower()
    with open(filename, 'r') as f:
        for line in f.readlines():
            if line.strip().startswith(';'):
                continue
            pieces = line.split('+')
            if len(pieces) != 2:
                continue
            name, offset = pieces
            name = name.lower()
            if debug:
                if module_name != name and name not in modules_seen:
                    print('[DBG] module mismatch, expected (%s), encountered (%s)' % (module_name, name))
                    modules_seen.add(name)
            block_offset = int(offset, 16)
            block_addr = module_base + block_offset
            if block_addr in module_blocks:
                blocks.add(block_addr)
            elif debug:
                print('[!] DBG: address 0x%x not in module_blocks!' % block_addr)
    return blocks


def parse_drcov_header(header, module_name, filename, debug):
    module_name = module_name.lower()
    module_table_start = False
    module_ids = []
    for i, line in enumerate(header.split("\n")):
        # Encountering the basic block table indicates end of the module table
        if line.startswith("BB Table"):
            break
        # The first entry in the module table starts with "0", potentially after leading spaces
        if line.strip().startswith("0"):
            module_table_start = True
        if module_table_start:
            columns = line.split(",")
            if debug:
                print("[DBG] Module table entry: %s" % line.strip())
            for col in columns[1:]:
                if module_name != "" and module_name in basename(col).lower():
                    module_ids.append(int(columns[0]))
                    if debug:
                        print("[DBG] Target module found (%d): %s" % (int(columns[0]), line.strip()))
    if not module_table_start:
        raise Exception('[!] No module table found in "%s"' % filename)
    if not module_ids and not debug:
        raise Exception("[!] Didn't find expected target '%s' in the module table in %s" %
                        (module_name, filename))

    return module_ids


def parse_drcov_binary_blocks(block_data, filename, module_ids, module_base, module_blocks, debug):
    blocks = set()
    block_data_len = len(block_data)
    blocks_seen = 0

    remainder = block_data_len % 8
    if remainder != 0:
        print("[!] Warning: %d trailing bytes left over in %s" % (remainder, filename))
        block_data = block_data[:-remainder]
    if debug:
        module_dict = {}

    for i in range(0, block_data_len, 8):
        block_offset = unpack("I", block_data[i:i + 4])[0]
        block_size = unpack("H", block_data[i + 4:i + 6])[0]
        block_module_id = unpack("H", block_data[i + 6:i + 8])[0]
        block_addr = module_base + block_offset
        blocks_seen += 1
        if debug:
            print("%d: 0x%08x 0x%x" % (block_module_id, block_offset, block_size))
            module_dict[block_module_id] = module_dict.get(block_module_id, 0) + 1
        if block_module_id in module_ids:
            cur_addr = block_addr
            # traces can contain "blocks" that split and span blocks
            # so we need a fairly comprehensive check to get it right
            while cur_addr < block_addr + block_size:
                if cur_addr in module_blocks:
                    blocks.add(cur_addr)
                    cur_addr += module_blocks[cur_addr]
                else:
                    cur_addr += 1
    if debug:
        print('[DBG] Block count per-module:')
        for module_number, blocks_hit in sorted(module_dict.items()):
            print('    %d: %d' % (module_number, blocks_hit))
    return blocks, blocks_seen


def parse_drcov_ascii_blocks(block_data, filename, module_ids, module_base, module_blocks, debug):
    blocks = set()
    blocks_seen = 0
    int_base = 0  # 0 not set, 10 or 16
    if debug:
        module_dict = {}

    for line in block_data.split(b"\n"):
        # example: 'module[  4]: 0x0000000000001090,   8'
        left_bracket_index = line.find(b'[')
        right_bracket_index = line.find(b']')
        # skip bad/blank lines
        if left_bracket_index == -1 or right_bracket_index == -1:
            continue
        block_module_id = int(line[left_bracket_index+1: right_bracket_index])
        block_offset, block_size = line[right_bracket_index+2:].split(b',')

        if int_base:
            block_offset = int(block_offset, int_base)
        else:
            if b'x' in block_offset:
                int_base = 16
            else:
                int_base = 10
            block_offset = int(block_offset, int_base)

        block_size = int(block_size)
        block_addr = module_base + block_offset
        blocks_seen += 1
        if debug:
            print("%d: 0x%08x 0x%x" % (block_module_id, block_offset, block_size))
            module_dict[block_module_id] = module_dict.get(block_module_id, 0) + 1
        if block_module_id in module_ids:
            cur_addr = block_addr
            while cur_addr < block_addr + block_size:
                if cur_addr in module_blocks:
                    blocks.add(cur_addr)
                    cur_addr += module_blocks[cur_addr]
                else:
                    cur_addr += 1
    if debug:
        print('[DBG] Block count per-module:')
        for module_number, blocks_hit in sorted(module_dict.items()):
            print('    %d: %d' % (module_number, blocks_hit))
    return blocks, blocks_seen


def parse_drcov_file(filename, module_name, module_base, module_blocks, debug=False):
    """Return set of blocks in module covered (block definitions provided in module_blocks)"""
    with open(filename, 'rb') as f:
        data = f.read()

    # Sanity checks for expected contents
    if not data.startswith(b"DRCOV VERSION: 2"):
        raise Exception("[!] File %s does not appear to be a drcov format file, " % filename +
                        "it doesn't start with the expected signature: 'DRCOV VERSION: 2'")

    header_end_pattern = b"BB Table: "
    header_end_location = data.find(header_end_pattern)
    if header_end_location == -1:
        raise Exception("[!] File %s does not appear to be a drcov format file, " % filename +
                        "it doesn't contain a header for the basic block table'")
    header_end_location = data.find(b"\n", header_end_location) + 1  # +1 to skip the newline

    # Check for ascii vs binary drcov version (binary is the default)
    binary_file = True
    ascii_block_header = b"module id, start, size:"

    block_header_candidate = data[header_end_location:header_end_location + len(ascii_block_header)]
    if block_header_candidate == ascii_block_header:
        binary_file = False
        # Skip the ascii block header line ("module id, start, size:\n")
        header_end_location = data.find(b"\n", header_end_location) + 1  # +1 to skip the newline

    # Parse the header
    header = data[:header_end_location].decode()
    block_data = data[header_end_location:]
    module_ids = parse_drcov_header(header, module_name, filename, debug)

    # Parse the block data itself
    if binary_file:
        parse_blocks = parse_drcov_binary_blocks
    else:
        parse_blocks = parse_drcov_ascii_blocks
    if debug:
        print("[DBG] Detected drcov %s format" % ("binary" if binary_file else "ascii"))
        print("[DBG] Basic block dump (module_id, block_offset, block_size)")
    blocks, blocks_seen = parse_blocks(block_data, filename, module_ids, module_base, module_blocks, debug)

    if debug:
        if not module_ids:
            print("[*] %d blocks parsed, no module id specified" % blocks_seen)
        else:
            num_blocks_found = len(blocks)
            print("[*] %d blocks parsed; module_ids %s" %
                  (blocks_seen, module_ids))
    return blocks


if __name__ == "__main__":
    import sys
    import time
    if len(sys.argv) == 1:
        print("STANDALONE USAGE: %s <trace_file> [module_name]" % sys.argv[0])
        exit()
    target = sys.argv[1]
    module_name = ""
    if len(sys.argv) >= 3:
        module_name = sys.argv[2]
    start = time.time()
    parse_coverage_file(sys.argv[1], module_name, 0, [], debug=True)
    duration = time.time() - start
    print('[*] Completed parsing in %.2f seconds' % duration)
