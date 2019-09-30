#!/usr/bin/env python

import os
import sys

from binaryninja import *
# this line allows these scripts to be run portably on python2/3
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import bncov

# Basic demo script: print the number of frontier blocks by function

if __name__ == "__main__":
    USAGE = "%s <target_file> <coverage_dir>" % sys.argv[0]
    if len(sys.argv) != 3:
        print(USAGE)
        exit()

    target_filename = sys.argv[1]
    covdir = sys.argv[2]

    bv = bncov.get_bv(target_filename, quiet=False)
    covdb = bncov.get_covdb(bv, covdir, quiet=False)

    frontier = covdb.get_frontier()
    print("[*] %d total frontier blocks found" % len(frontier))
    function_mapping = covdb.get_functions_from_blocks(frontier)
    for function_name, frontier_blocks in function_mapping.items():
        print("  %d frontier blocks in %s" % (len(frontier_blocks), function_name))

