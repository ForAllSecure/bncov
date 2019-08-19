#!/usr/bin/env python

import sys
import time
import os

from binaryninja import *
# this line allows these scripts to be run portably on python2/3
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import bncov.coverage as coverage

# This script compares block coverage, given a target and two directories of coverage files
USAGE = "%s <target_file> <coverage_dir1> <coverage_dir2>" % sys.argv[0]


# It's MUCH faster to save/load CoverageDBs, helpful for multiple analyses over coverage sets
def get_coverage_db(dirname, bv):
    # Allow specification of covdb files directly
    if dirname.endswith(".covdb"):
        covdb_name = dirname
    else:
        covdb_name = os.path.basename(dirname + ".covdb")

    start = time.time()
    if os.path.exists(covdb_name):
        sys.stdout.write("[L] Loading coverage from object file %s..." % covdb_name)
        sys.stdout.flush()
        covdb = coverage.CoverageDB(bv, covdb_name)
        duration = time.time() - start
        num_files = len(covdb.coverage_files)
        print(" finished (%d files) in %.02f seconds" % (num_files, duration))
    else:
        sys.stdout.write("[C] Creating coverage db from directory %s..." % dirname)
        sys.stdout.flush()
        covdb = coverage.CoverageDB(bv)
        covdb.add_directory(dirname)
        duration = time.time() - start
        num_files = len(os.listdir(dirname))
        print(" finished (%d files) in %.02f seconds" % (num_files, duration))

    return covdb


def print_function_blocks(covdb, block_set):
    function_mapping = covdb.get_functions_from_blocks(block_set)
    for function_name, blocks in function_mapping.items():
        function_obj = [f for f in bv.functions if f.name == function_name][0]
        pretty_name = function_obj.symbol.short_name
        print("    %s: %s" % (pretty_name, ["0x%x" % b for b in blocks]))


def compare_covdbs(covdb1, covdb2):
    print("=== COMPARISON ===")
    print("[*] %s and %s have %d blocks in common" %
          (covdir1, covdir2, len(covdb1.total_coverage & covdb2.total_coverage)))

    only_1 = covdb1.total_coverage - covdb2.total_coverage
    print("[1] %d Blocks only in %s:" % (len(only_1), covdir1))
    print_function_blocks(covdb1, only_1)

    only_2 = covdb2.total_coverage - covdb1.total_coverage
    print("[2] %d Blocks only in %s:" % (len(only_2), covdir2))
    print_function_blocks(covdb2, only_2)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(USAGE)
        exit()

    # Loading .bndb's also works, and is faster
    target_filename = sys.argv[1]
    covdir1 = sys.argv[2]
    covdir2 = sys.argv[3]

    if not os.path.exists(target_filename):
        print("[!] Couldn't find target file \"%s\"..." % target_filename)
        print("    Check that target_filename is correct")
        exit(1)
    for covdir in [covdir1, covdir2]:
        if not os.path.exists(covdir):
            print("[!] Couldn't find coverage directory \"%s\"..." % covdir)
            print("    Check that covdirs specified are correct")
            exit(1)

    print("=== LOADING DATA ===")
    sys.stdout.write("[B] Loading Binary Ninja view of %s..." % target_filename)
    sys.stdout.flush()
    start = time.time()
    bv = BinaryViewType.get_view_of_file(target_filename)
    bv.update_analysis_and_wait()
    print("finished in %.02f seconds" % (time.time() - start))

    covdb1 = get_coverage_db(covdir1, bv)
    covdb2 = get_coverage_db(covdir2, bv)
    compare_covdbs(covdb1, covdb2)
