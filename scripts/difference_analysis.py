#!/usr/bin/env python

import sys
import time
import os

from binaryninja import *
# this line allows these scripts to be run portably on python2/3
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import bncov.coverage as coverage


def get_coverage_object_name(dirname):
    output_filename = os.path.basename(dirname + ".covdb")
    return output_filename


def get_coverage_db(dirname, bv):
    covdb_name = get_coverage_object_name(dirname)
    start = time.time()
    if os.path.exists(covdb_name):
        sys.stdout.write("[*] Loading coverage from object file %s..." % covdb_name)
        sys.stdout.flush()
        covdb = coverage.CoverageDB(bv, covdb_name)
        duration = time.time() - start
        num_files = len(covdb.coverage_files)
        print(" finished (%d files) in %.02f seconds" % (num_files, duration))
    else:
        sys.stdout.write("[*] Creating coverage db from directory %s..." % dirname)
        sys.stdout.flush()
        covdb = coverage.CoverageDB(bv)
        covdb.add_directory(dirname)
        duration = time.time() - start
        num_files = len(os.listdir(dirname))
        print(" finished (%d files) in %.02f seconds" % (num_files, duration))
        # Including for example, disabling to reduce surprise
        # try:
        #     import msgpack  # dependency for save_to_file
        #     sys.stdout.write("[*] Saving coverage object to file '%s'..." % covdb_name)
        #     sys.stdout.flush()
        #     start = time.time()
        #     covdb.save_to_file(covdb_name)
        #     duration = time.time() - start
        #     print(" finished in %.02f seconds" % duration)
        # except ImportError:
        #     pass
    return covdb


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("USAGE: %s <target_file_or_bndb> <base_covdir> <successor_covdir> ..." % sys.argv[0])
        exit()

    target_filename = sys.argv[1]
    coverage_dirs = sys.argv[2:]

    print("=== LOADING DATA ===")
    sys.stdout.write("[*] Loading Binary Ninja view of %s..." % target_filename)
    sys.stdout.flush()
    start = time.time()
    bv = BinaryViewType.get_view_of_file(target_filename)
    bv.update_analysis_and_wait()
    duration = time.time() - start
    print("finished in %.02f seconds" % duration)

    covdbs = [get_coverage_db(dirname, bv) for dirname in coverage_dirs]

    prev_covdb = None
    print("=== ANALYSIS ===")
    for i, covdb in enumerate(covdbs):
        if i == 0:
            prev_covdb = covdb
            print('[*] "%s" is the base, containing %d blocks' % (coverage_dirs[i], len(covdb.total_coverage)))
            continue
        new_coverage = covdb.total_coverage - prev_covdb.total_coverage
        prev_covdb = covdb
        num_new_coverage = len(new_coverage)
        print('[*] "%s" contains %d new blocks' % (coverage_dirs[i], num_new_coverage))
        covdb.collect_function_coverage()
        if num_new_coverage > 0:
            f2a = covdb.get_functions_from_blocks(new_coverage)
            for function, blocks in f2a.items():
                print("  %s: %s" % (function, str(["0x%x" % addr for addr in blocks])))

