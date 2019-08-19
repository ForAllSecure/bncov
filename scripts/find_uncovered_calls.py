#!/usr/bin/env python

import sys
import os
import time
import shutil
import subprocess

from binaryninja import *
# this line allows these scripts to be run portably on python2/3
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import bncov

# By default, path_to_addr2line == "", so try to find it in path using built-ins
if sys.version_info[0] == 3 and sys.version_info[1] >= 3:
    which_func = shutil.which
else:
    try:
        from distutils import spawn
        which_func = spawn.find_executable
    except AttributeError:
        def which_func(x): return None

path_to_addr2line = ""  # if addr2line isn't in your path, you can put the path to the binary here
# do a simple str.replace(old, new) over the original source path
source_path_old = ""
source_path_new = ""

USAGE = "USAGE: %s <target_file> <coverage directory>" % sys.argv[0]


def get_uncovered_descendants(covdb, root_block, max_depth=1):
    """Return set of all uncovered blocks up to max_depth edges away.

    max_depth=0 does nothing, max_depth=1 gets immediate uncovered children.
    return value is a set of BN BasicBlocks
    """
    blocks_checked = {}
    child_blocks = set()
    blocks_remaining = {root_block: 0}

    while len(blocks_remaining) > 0:
        cur_block, depth = blocks_remaining.popitem()
        blocks_checked[cur_block] = depth
        next_depth = depth + 1
        # skip this block if children are beyond max_depth
        if next_depth > max_depth:
            continue

        for edge in cur_block.outgoing_edges:
            child_block = edge.target
            if child_block.start in covdb.total_coverage:
                continue
            child_blocks.add(child_block)

            if child_block not in blocks_checked:
                # only add/update when next_depth is better than current entry
                if child_block in blocks_remaining and blocks_remaining[child_block] <= next_depth:
                    pass
                else:
                    blocks_remaining[child_block] = next_depth
            else:  # child block in blocks_checked
                # if it was checked at a higher depth, we need to reconsider it
                if blocks_checked[child_block] > next_depth:
                    blocks_checked.pop(child_block)
                    blocks_remaining[child_block] = next_depth

    return child_blocks


def get_uncovered_calls(covdb, max_distance=2):
    """Return a dictionary of addresses of uncovered calls mapped to their disassembly.

    max_distance specifies the number of edges away from the frontier to check.
    max_distance=None considers all uncovered blocks in functions with partial coverage.
    """
    function_coverage_stats = covdb.collect_function_coverage()

    bv = covdb.bv
    uncovered_calls = {}
    # if no max distance is specified, just search all uncovered blocks
    if max_distance is None:
        for func in bv.functions:
            if function_coverage_stats[func.name].blocks_covered == 0:
                continue
            for block in func:
                if block.start in covdb.total_coverage:
                    continue
                block_offset = 0
                for instruction in block:
                    token_list, inst_size = instruction
                    inst_addr = block.start + block_offset
                    if func.is_call_instruction(inst_addr):
                        for disassembly_line in block.get_disassembly_text():
                            if disassembly_line.address == inst_addr:
                                uncovered_calls[inst_addr] = str(disassembly_line)
                                break
                    block_offset += inst_size
    else:  # check for calls that are within max_distance edges of the frontier
        blocks_checked = set()
        for block_start in covdb.get_frontier():

            cur_block = bv.get_basic_blocks_starting_at(block_start)[0]
            uncovered_child_blocks = get_uncovered_descendants(covdb, cur_block, max_distance)
            for block in uncovered_child_blocks:
                if block in blocks_checked:
                    continue
                func = block.function
                block_offset = 0
                for instruction in block:
                    token_list, inst_size = instruction
                    inst_addr = block.start + block_offset
                    if func.is_call_instruction(inst_addr):
                        for disassembly_line in block.get_disassembly_text():
                            if disassembly_line.address == inst_addr:
                                uncovered_calls[inst_addr] =  str(disassembly_line)
                                break
                    block_offset += inst_size
            blocks_checked.update(uncovered_child_blocks)

    return uncovered_calls


def get_source_line(target_binary_path, address):
    """Returns corresponding "filepath:line" for address, or None on failure.

    Filepath portion may be "" or "??".
    Line portion may have trailing information such as "168 (discriminator 1)", or may be "?".
    """
    global path_to_addr2line
    # find addr2line
    if not path_to_addr2line:
        path_to_addr2line = which_func("addr2line")
        if path_to_addr2line is None:
            return None

    # Run addr2line to get source line info
    cmd = "%s -e %s -a 0x%x" % (path_to_addr2line, target_binary_path, address)
    p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = p.communicate()
    if not isinstance(output, str):
        output = output.decode()
        error = error.decode()
    if error:
        print("[!] stderr from addr2line: %s" % error)
        return None
    source_line_info = output.strip().split('\n')[-1]
    return source_line_info


warnings_given = {}  # warn only first time on failures
def print_source_line(target_binary_path, address, num_context_lines=5):
    """Print source line for address if possible, prints warning on failure.

    Uses addr2line under the hood to do offset-to-source mapping.
    Returns True on success, False on failure."""
    global warnings_given

    source_line_info = get_source_line(target_binary_path, address)
    if source_line_info is None:
        if "addr2line" not in warnings_given:
            print('[!] ERROR: addr2line not found, will not do source mapping')
            print('    Either put addr2line in the path or set the variable "path_to_addr2line" in this script')
            warnings_given['addr2line'] = True
        return False
    print('Source line: %s' % source_line_info)
    original_filepath, target_line_number = source_line_info.split(':')
    if original_filepath == "" or "??" in original_filepath:
        print("[*] No source file mapping for address 0x%x" % address)
        return False
    if os.sep not in original_filepath:  # observed on library files with no path
        if original_filepath not in warnings_given:
            print('[*] Note: Original source file appears built-in: %s' % original_filepath)
            warnings_given[original_filepath] = True
        return False
    if target_line_number == "?":
        # source line will show the "?" for line number above, no explicit warning needed
        return False

    # fix up filepath, which may have ".." naturally, or "~" if we use it in the source path replacement
    filepath = os.path.abspath(original_filepath)
    if source_path_old and source_path_new:
        filepath = filepath.replace(source_path_old, source_path_new)
    filepath = os.path.expanduser(filepath)
    if not os.path.exists(filepath):

        if original_filepath not in warnings_given or \
                warnings_given[original_filepath] != (source_path_old, source_path_new):
            print('[!] Warning: original source file "%s" not found' % original_filepath)
            if source_path_old and source_path_new:
                print('    After path translation, looked for it at: "%s"' % filepath)
            else:
                print('    You can specify a path replacement in the script with source_path_new/old')
            warnings_given[original_filepath] = (source_path_old, source_path_new)
        return False

    # Fix up source line if needed
    try:
        target_line_number = int(target_line_number)
    except ValueError:
        # drop discriminator info for line numbers that include it, like: "800 (discriminator 4)"
        if ' ' in target_line_number:
            target_line_number = int(target_line_number.split(' ')[0])
        else:
            print('[!] Unexpected non-integer line number: %s' % target_line_number)
            return False
    # Print lines from source file
    # print("[DBG] Found source file at %s" % filepath)
    with open(filepath, 'r') as f:
        lines = f.readlines()
        start = max(0, target_line_number - num_context_lines - 1)  # avoid negative index value
        stop = min(len(lines), target_line_number + num_context_lines)
        max_num_len = len(str(stop))
        for i, line in enumerate(lines[start:stop]):
            cur_line_number = start + i + 1  # plus 1 for zero-indexing
            if cur_line_number == target_line_number:
                prefix = "-->"
            else:
                prefix = "   "
            sys.stdout.write("%s%s: %s" % (prefix, str(cur_line_number).rjust(max_num_len), line))
    return True


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(USAGE)
        exit()

    target_filename = sys.argv[1]
    covdir = sys.argv[2]

    bv = bncov.get_bv(target_filename, quiet=False)
    covdb = bncov.get_covdb(bv, covdir, quiet=False)

    uncovered_calls = get_uncovered_calls(covdb)
    for i, item in enumerate(uncovered_calls.items()):
        address, disassembly = item
        function_name = bv.get_functions_containing(address)[0].symbol.short_name
        print('\n[%d] %s: 0x%x: "%s"' % (i, function_name, address, disassembly))
        print_source_line(bv.file.original_filename, address)
