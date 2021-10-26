#!/usr/bin/env python

import sys
import os
import time

from binaryninja import *
# this line allows these scripts to be run portably on python2/3
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import bncov

USAGE = "USAGE: %s <target_file> <seed_directory> <coverage_directory> [log_name]" % sys.argv[0]
USAGE += "\n  Break down timeline of when coverage increased based on modification time of seeds"


def format_duration(seconds):
    return "%02d:%02d:%02d" % (seconds // 3600, (seconds // 60) % 60, seconds % 60)


def get_timestamp(path):
    """Return a timestamp to give a sense of time between seeds.
    If you want to maintain timestamps via other means (db, flat file with times, etc),
    just swap out this function for your implementation."""
    return os.path.getmtime(path)


def get_coverage_timeline(covdb, seed_dir, cov_dir):
    if not os.path.exists(seed_dir):
        print("[!] Seed dir `%s` doesn't exist" % seed_dir)
        exit(1)
    seeds = os.listdir(seed_dir)
    seed_paths = [os.path.join(seed_dir, seed_name) for seed_name in seeds]
    seed_times = {path: get_timestamp(path) for path in seed_paths}

    # Assume the bncov naming convention
    seed_to_coverage = {}
    for seed_path in seed_paths:
        seed_name = os.path.basename(seed_path)
        coverage_path = os.path.join(cov_dir, seed_name) + ".cov"
        if coverage_path not in covdb.trace_dict:
            print("[!] Didn't find matching trace (expected %s) for seed \"%s\", skipping" % (coverage_path, seed_path))
            seed_times.pop(seed_path)
        else:
            seed_to_coverage[seed_path] = coverage_path

    sorted_seeds = sorted(seed_times.items(), key=lambda kv: kv[1])
    running_coverage = set()
    initial_time = sorted_seeds[0][1]
    datapoints = []  # list of (seconds_elapsed, total_blocks)
    for seed_path, mod_time in sorted_seeds:
        # print("[DBG] %s: %s" % (seed_path, time.asctime(time.localtime(mod_time))))
        seed_name = os.path.basename(seed_path)
        seed_coverage = covdb.trace_dict[seed_to_coverage[seed_path]]
        new_coverage = seed_coverage - running_coverage
        # print('[DBG] %s: %d total, %d new' % (seed_name, len(seed_coverage), len(new_coverage)))
        if len(new_coverage) > 0:
            seconds_elapsed = mod_time - initial_time
            num_new_blocks = len(new_coverage)
            running_coverage.update(new_coverage)
            num_total_blocks = len(running_coverage)
            print("[T+%s] %d new blocks from %s (%d)" %
                  (format_duration(seconds_elapsed), num_new_blocks, seed_name, num_total_blocks))
            datapoints.append((int(seconds_elapsed)+1, num_total_blocks))
    return datapoints


if __name__ == "__main__":
    if len(sys.argv) not in [4, 5]:
        print(USAGE)
        exit(1)
    target_filename, seed_dir, cov_dir = sys.argv[1:4]
    log_name = None
    if len(sys.argv) == 5:
        log_name = sys.argv[4]
    bv = bncov.make_bv(target_filename, quiet=False)
    covdb = bncov.make_covdb(bv, cov_dir, quiet=False)

    datapoints = get_coverage_timeline(covdb, seed_dir, cov_dir)
    
    if log_name is not None:
        with open(log_name, 'w') as f:
            f.write(repr(datapoints))
            print('[+] Wrote %d datapoints to %s' % (len(datapoints), log_name))
