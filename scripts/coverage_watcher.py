#!/usr/bin/env python

import sys
import time
import os

from binaryninja import *
# this line allows these scripts to be run portably on python2/3
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import bncov


def get_duration():
    duration = time.time() - script_start
    return "%02d:%02d:%02d" % (duration // 3600, (duration // 60) % 60, duration % 60)


def time_print(s):
    print("[%s] %s" % (get_duration(), s))


def watch_coverage(covdb):
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


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("USAGE: %s <target_file_or_bndb> <coverage_dir>" % sys.argv[0])
        exit()

    target_filename = sys.argv[1]
    coverage_dir = sys.argv[2]
    bv = bncov.make_bv(target_filename, quiet=False)
    covdb = bncov.make_covdb(bv, coverage_dir, quiet=False)

    script_start = time.time()
    watch_coverage(covdb)
