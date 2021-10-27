#!/usr/bin/env python

import os
import sys

from binaryninja import *
# this line allows these scripts to be run portably on python2/3
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import bncov

USAGE = "%s <target_file> <coverage_dir>" % sys.argv[0]
USAGE += "\n  Print a summary of functions and blocks covered"


def print_coverage_summary(bv, covdb):
    overall_coverage_stats = covdb.get_overall_function_coverage()
    number_of_functions, total_blocks_covered, total_blocks = overall_coverage_stats

    # Summarize coverage for all functions with nonzero coverage
    function_summaries = {}
    for function_obj in covdb.bv.functions:
        stats = covdb.function_stats[function_obj.start]
        if stats.blocks_covered == 0:
            continue
        demangled_name = function_obj.symbol.short_name
        summary = "%.1f%% (%d/%d blocks)" % (stats.coverage_percent, stats.blocks_covered, stats.blocks_total)
        function_summaries[demangled_name] = summary

    print("Coverage Summary for %s:" % target_filename)

    for name, summary in sorted(function_summaries.items()):
        print("  %s %s" % (name, summary))

    total_coverage = float(total_blocks_covered) / float(total_blocks) * 100
    print("Overall %d/%d Functions covered, %.1f%% block coverage (%d blocks)" %
          (len(function_summaries), len(bv.functions), total_coverage, total_blocks_covered))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(USAGE)
        exit()

    target_filename = sys.argv[1]
    covdir = sys.argv[2]

    bv = bncov.make_bv(target_filename, quiet=False)
    covdb = bncov.make_covdb(bv, covdir, quiet=False)
    print_coverage_summary(bv, covdb)
