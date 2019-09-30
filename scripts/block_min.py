#!/usr/bin/env python

import sys
import os
import time
import shutil

from binaryninja import *
# this line allows these scripts to be run portably on python2/3
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import bncov

USAGE = "USAGE: %s <target_file> <seed_directory> [coverage_directory] [output_dir] " % sys.argv[0]
USAGE += "\n  Calculate minimal set of files that cover all blocks"
# if coverage_directory not specified, assume <seed_directory>-cov
# if output_dir not specified, use <seed_directory>-bmin

if __name__ == "__main__":
    if len(sys.argv) not in [3, 4, 5]:
        print(USAGE)
        exit(1)

    target_filename = sys.argv[1]
    seed_dir = os.path.normpath(sys.argv[2])
    coverage_dir = seed_dir + "-cov"
    output_dir = seed_dir + "-bmin"
    if len(sys.argv) >= 4:
        coverage_dir = os.path.normpath(sys.argv[3])
    if len(sys.argv) == 5:
        output_dir = os.path.normpath(sys.argv[4])

    script_start = time.time()
    bv = bncov.get_bv(target_filename)
    covdb = bncov.get_covdb(bv, coverage_dir)

    seed_paths = [os.path.join(seed_dir, filename) for filename in os.listdir(seed_dir)]
    seed_sizes = {seed_path: os.path.getsize(seed_path) for seed_path in seed_paths}
    coverage_to_seed = {}
    seed_to_coverage = {}
    for trace_path in covdb.trace_dict.keys():
        trace_name = os.path.basename(trace_path)
        if trace_name.endswith('.cov') is False:
            print("[!] Trace file %s doesn't the right extension (.cov), bailing..." % trace_path)
            exit(1)
        seed_name = trace_name[:-4]
        seed_path = os.path.join(seed_dir, seed_name)
        if not os.path.exists(seed_path):
            print("[!] Couldn't find matching seed path (%s) for trace %s, bailing..." % (seed_path, trace_path))
            exit(1)
        coverage_to_seed[trace_path] = seed_path
        seed_to_coverage[seed_path] = trace_path

    sys.stdout.write("[M] Starting block minset calculation...")
    sys.stdout.flush()
    minset_start = time.time()
    block_minset = set()
    minset_files = []
    while True:
        blocks_remaining = covdb.total_coverage - block_minset
        if len(blocks_remaining) == 0:
            break
        next_block = blocks_remaining.pop()
        containing_traces = covdb.get_traces_from_block(next_block)
        # map traces to seed files' sizes
        containing_traces_by_size = sorted(containing_traces,
                                           key=lambda trace_name: seed_sizes[coverage_to_seed[trace_name]])
        # pick the smallest file by size
        matching_trace = containing_traces_by_size[0]
        minset_files.append(coverage_to_seed[matching_trace])
        block_minset.update(covdb.trace_dict[matching_trace])
    minset_duration = time.time() - minset_start
    print(" finished in %.2f seconds" % minset_duration)

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    for seed_path in minset_files:
        output_path = os.path.join(output_dir, os.path.basename(seed_path))
        shutil.copy(seed_path, output_path)
        # print("[DBG]  %s: %d" % (seed_path, seed_sizes[seed_path]))
    print('[+] Finished, minset contains %d files, saved to "%s" ' % (len(minset_files), output_dir))
