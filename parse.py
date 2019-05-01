#!/usr/bin/env python

from ast import literal_eval
from struct import unpack

# Handle parsing files into sets of addresses, each describing the start of a basic block
# Can be invoked as a standalone script for debugging purposes


def parse_coverage_file(filename, module_name, module_base, module_blocks):
    """Return a set of addresses of covered blocks in the specified module"""
    # FUTURE: Do format detection here if multiple types need to be supported
    blocks = parse_drcov_file(filename, module_name, module_base, module_blocks)
    return blocks


def parse_drcov_file(filename, module_name, module_base, module_blocks, debug=False):
    """Return set of blocks in module covered (block definitions provided in module_blocks)"""
    with open(filename, 'rb') as f:
        data = f.read()
    if not data.startswith(b"DRCOV VERSION: 2"):
        raise Exception("[!] File %s does not appear to be a drcov format file, " % filename +
                        "it doesn't start with the expected signature: 'DRCOV VERSION: 2'")
    lines = data.split(b"\n")
    module_table_start = False
    module_id = None
    for i, line in enumerate(lines):
        # Encountering the basic block table indicates end of the module table
        if line.startswith(b"BB Table"):
            if debug:
                break
            if module_table_start:
                raise Exception("[!] Didn't find expected target '%s' in the module table in %s"
                                % (module_name, filename))
            else:
                raise Exception("[!] No module table found in %s" % filename)
        # The first entry in the module table starts with "0", potentially after leading spaces
        if line.strip().startswith(b"0"):
            module_table_start = True
        if module_table_start:
            columns = line.split(b",")
            if debug:
                print("[DBG] Module table entry: %s" % line.strip())
            for col in columns[1:]:
                if module_name != "" and module_name in col:
                    module_id = int(columns[0])
                    if debug:
                        print("[DBG] Target module found (%d): %s" % (int(columns[0]), line.strip()))
            if module_id is not None:
                break

    basicblocks_index = data.find(b"BB Table")
    if basicblocks_index == -1:
        raise Exception("[!] BB table header not found in %s" % filename)
    basicblocks_start = data.find(b"\n", basicblocks_index) + 1
    bb_table_line = data[basicblocks_index:basicblocks_start]
    _, _, bb_count, _ = bb_table_line.split(b' ')
    bb_count = int(bb_count)

    if basicblocks_start <= 0:
        raise Exception("[!] No basic blocks found in file %s" % filename)
    data = data[basicblocks_start:]

    blocks = set()
    total_blocks = len(data) / 8
    remainder = len(data) % 8
    if remainder != 0:
        print("[!] Warning: %d trailing bytes left over in %s" % (len(data), filename))
        data = data[:-remainder]
    if debug:
        print("[DBG] Basic block dump (module_id, block_offset, block_size)")
    for i in range(0, len(data), 8):
        block_offset = unpack("I", data[i:i+4])[0]
        block_size = unpack("H", data[i+4:i+6])[0]
        block_module_id = unpack("H", data[i+6:i+8])[0]
        block_addr = module_base + block_offset
        if debug:
            print("%d: 0x%08x 0x%x" % (block_module_id, block_offset, block_size))
        if block_module_id == module_id and block_addr not in blocks:
            cur_addr = block_addr
            # traces can contain "blocks" that split and span blocks
            # so we need a fairly comprehensive check to get it right
            while cur_addr < block_addr + block_size:
                if cur_addr in module_blocks:
                    blocks.add(cur_addr)
                    cur_addr += module_blocks[cur_addr]
                else:
                    cur_addr += 1  # TODO: find more efficient way without querying bv?
    num_blocks_found = len(blocks)
    if debug:
        if module_id is None:
            print("[*] %d blocks parsed" % total_blocks)
        else:
            print("[*] %d blocks parsed, %d matched module_id %d" %
                  (total_blocks, num_blocks_found, module_id))
    return blocks


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        print("STANDALONE USAGE: %s <trace_file> [module_name]" % sys.argv[0])
        exit()
    target = sys.argv[1]
    module_name = ""
    if len(sys.argv) >= 3:
        module_name = sys.argv[2]
    parse_drcov_file(sys.argv[1], module_name, 0, [], debug=True)
