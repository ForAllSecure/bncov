#!/usr/bin/env python

import sys
import time
import os

from binaryninja import *
# this line allows these scripts to be run portably on python2/3
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import bncov.coverage as coverage

if len(sys.argv) != 3:
    print("USAGE: %s <target_file_or_bndb> <coverage_dir>" % sys.argv[0])
    exit()

target_filename = sys.argv[1]
coverage_dir = sys.argv[2]

script_start = time.time()

def time_print(s):
    print("[%.2f] %s" % (time.time() - script_start, s)) 

print("=== LOADING DATA ===")
sys.stdout.write("[*] Loading Binary Ninja view of %s..." % target_filename)
sys.stdout.flush()
start = time.time()
bv = BinaryViewType.get_view_of_file(target_filename)
bv.update_analysis_and_wait()
duration = time.time() - start
print("finished in %.02f seconds" % duration)

sys.stdout.write("[*] Creating coverage db from directory %s..." % coverage_dir)
sys.stdout.flush()
start = time.time()
covdb = coverage.CoverageDB(bv)
covdb.add_directory(coverage_dir)
duration = time.time() - start
num_files = len(os.listdir(coverage_dir))
print(" finished (%d files) in %.02f seconds" % (num_files, duration))

number_of_functions, total_blocks_covered, total_blocks = covdb.get_overall_function_coverage()
time_print("Coverage baseline has %d blocks covered in %d functions" % (total_blocks_covered, number_of_functions))

poll_interval = 1
try:
    while True:
        coverage_files = os.listdir(coverage_dir)
        for filename in coverage_files:
            coverage_filepath = os.path.join(coverage_dir, filename)
            if coverage_filepath not in covdb.trace_dict:
                coverage_before = set()
                coverage_before.update(covdb.total_coverage)
                coverage_from_file = covdb.add_file(coverage_filepath)
                new_coverage = coverage_from_file - coverage_before
                time_print("New coverage file found: %s, %d new blocks covered" % (filename, len(new_coverage)))
                function_mapping = covdb.get_functions_from_blocks(new_coverage)
                for function_name in function_mapping:
                    for block in function_mapping[function_name]:
                        time_print("    New block 0x%x in %s" % (block, function_name))
        time.sleep(poll_interval)
except KeyboardInterrupt:
    time_print("Caught CTRL+C, exiting")
