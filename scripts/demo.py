#!/usr/bin/env python

import sys
import os

from binaryninja import *
# this line allows these scripts to be run portably on python2/3
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import bncov.coverage as coverage

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("USAGE: %s <target_file> <coverage_directory>" % sys.argv[0])
        exit()
    filename = sys.argv[1]
    coverage_dir = sys.argv[2]

    bv = BinaryViewType.get_view_of_file(filename)
    bv.update_analysis_and_wait()
    print("[*] Loaded %s" % filename)

    covdb = coverage.CoverageDB(bv)
    covdb.add_directory(coverage_dir)

    print(covdb.module_name)
    print("Module base: 0x%x" % covdb.module_base)
    print("Files (%d): %s" % (len(covdb.coverage_files), len(covdb.trace_dict.keys())))
    print("Blocks: %d %d" % (len(covdb.block_dict), len(covdb.total_coverage)))

    frontier = covdb.get_frontier()
    print("Frontier: %s" % repr(frontier))
    print("Rare blocks: %s" % repr(covdb.get_rare_blocks()))

    rare_block = covdb.get_rare_blocks()[0]
    print("Traces for rare block: %s" % repr(covdb.get_traces_from_block(rare_block)))
    print("Function coverage: %s" % repr(covdb.get_overall_function_coverage()))

    num_addrs = 7
    print("First %d num traces by addr:" % num_addrs)
    for i in range(num_addrs):
        addr = list(covdb.block_dict.keys())[i]
        print(" %d 0x%x %d" % (i, addr, len(covdb.get_traces_from_block(addr))))

    rare_traces = covdb.get_traces_from_block(rare_block)
    print("Get_traces_from_block - rare_block: %s" % repr(rare_traces))
    print("Get_traces_with_rare_blocks(): %s" % repr(covdb.get_traces_with_rare_blocks()))

    rare_trace = rare_traces[0]
    print("Get_trace_uniq_blocks - rare_trace: %s" % repr(covdb.get_trace_uniq_blocks(rare_trace)))
    print("Get_trace_blocks - rare_trace: %s" % repr(covdb.get_trace_blocks(rare_trace)))
    print("Get_functions_from_trace - rare_trace: %s" % repr(covdb.get_functions_from_trace(rare_trace, by_name=True)))
    print("Get_functions_from_blocks - rare_blocks: %s" %
          repr(covdb.get_functions_from_blocks(covdb.get_rare_blocks(), by_name=True)))
    print("Get_trace_uniq_functions - rare_trace: %s" % repr(covdb.get_trace_uniq_functions(rare_trace, by_name=True)))

    rare_func_start = list(covdb.get_functions_with_rare_blocks())[0]
    rare_func = bv.get_function_at(rare_func_start).name
    print("get_functions_with_rare_blocks(): %s" % repr(covdb.get_functions_with_rare_blocks(by_name=True)))
    print("Get_functions_from_blocks - frontier: %s" % repr(covdb.get_functions_from_blocks(frontier, by_name=True)))

    function_name = rare_func
    function_start = rare_func_start
    print("Get_traces_from_function_name - %s: %s" % (function_name,  repr(covdb.get_traces_from_function_name(function_name))))
    print("Get_traces_from_function - 0x%x: %s" % (function_start,  repr(covdb.get_traces_from_function(function_start))))
    print("Get_overall_function_coverage: %s" % repr(covdb.get_overall_function_coverage()))

    key, value = list(covdb.function_stats.items())[0]
    print("First func_stats: %s : %s" % (key, value))

