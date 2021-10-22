#!/usr/bin/env python

from __future__ import print_function
import os
import subprocess
import sys
import time
import glob
import multiprocessing

# wraps calling drcov on a bunch of files and renaming the outputs

USAGE = "USAGE: %s <seed dir> [output directory] [optional_args] -- <non-instrumented target @@-invocation>" % sys.argv[0]
USAGE += "\n  Optional script arguments:"
USAGE += "\n      --workers=N             Use N worker processes"
USAGE += "\n      --continuously_monitor  Process new seeds as they appear"
USAGE += "\n      --debug                 Print stdout and stderr of target"

# Path to DynamoRIO root
path_to_dynamorio = os.getenv("DYNAMORIO", "/mnt/hgfs/vmshare/dr/")
if not os.path.exists(path_to_dynamorio):
    print("[!] DynamoRIO not found at '%s'" % path_to_dynamorio +
          "please update in the script (%s) or set environment variable DYNAMORIO to point to path" % sys.argv[0])
    exit()


def wrap_get_block_coverage(path):
    try:
        name = os.path.basename(path)
        output_path = os.path.join(output_dir, name + ".cov")
        if get_block_coverage(path, output_path, command):
            return 1
        else:
            print("[!] Error occurred on seed: %s" % path)
    except KeyboardInterrupt:
        pool.terminate()


def get_block_coverage(path, output_path, command):
    command = command.replace("@@", path)
    drcov_process = subprocess.Popen(command.split(),
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     shell=False)
    output, err = drcov_process.communicate()
    if debug:
        print("[DBG] stdout: `%s`" % output)
        print("[DBG] stderr: `%s`" % err)
        print("[DBG] returncode: %s" % repr(drcov_process.poll())) 

    # handle the output file that is produced
    matching = glob.glob("drcov*%05d*.log" % drcov_process.pid)
    if len(matching) == 0:
        print("[!] drcov didn't output a file named after pid %d" % drcov_process.pid)
        print("    command invoked: %s" % command)
        print("    stderr: %s" % err)
        return False
    if len(matching) > 1:
        print("[!] More than one drcov file matched pid %d" % drcov_process.pid)
        return False
    matching = matching[0]
    # handle drcov failures
    return_code = drcov_process.poll()
    # drcov errors ask users to report errors
    if return_code != 0 and b"report" in err.lower() and b"dynamorio" in err.lower():
        print("[!] drcov process %d indicated failure return code (%d)" % (drcov_process.pid, return_code))
        print("    command invoked: %s" % command)
        print("    stdout: %s" % output)
        print("    stderr: %s" % err)
        os.unlink(matching)
        return False
    else:
        os.rename(matching, output_path)
        return True


def is64bit(binary_path):
    with open(binary_path, "rb") as f:
        data = f.read(32)
    e_machine = data[18]
    if isinstance(e_machine, str):  # python2/3 compatibility, handle e_machine as string or value
        e_machine = ord(e_machine)
    if e_machine == 0x03:  # x86
        return False
    elif e_machine == 0x3e:  # x64
        return True
    raise Exception("[!] Unexpected e_machine value in 64-bit check: %s (e_machine: 0x%x)" % (binary_path, e_machine))


if __name__ == "__main__":
    if len(sys.argv) < 4 or "--" not in sys.argv:
        print(USAGE)
        exit()

    script_options = sys.argv[1:sys.argv.index("--")]
    target_invocation = " ".join(sys.argv[sys.argv.index("--")+1:])

    # parse and remove optional switches
    num_workers = 4
    continuously_monitor = False
    debug = False
    worker_index = -1
    monitor_index = -1
    debug_index = -1
    for i, option in enumerate(script_options):
        if option.startswith("--workers="):
            num_workers = int(option.split('=')[1])
            worker_index = i
            print("[*] Using %d worker processes" % num_workers)
        elif option == "--continuously_monitor":
            continuously_monitor = True
            monitor_index = i
            print("[*] Will continuously monitor seed directory")
        elif option == "--debug":
            debug = True
            debug_index = i
        elif option.startswith('--'):
            print("[!] Unrecognized option: %s" % option)
            print(USAGE)
            exit()
    if worker_index != -1:
        script_options.pop(worker_index)
    if monitor_index != -1:
        script_options.pop(monitor_index)
    if debug_index != -1:
        script_options.pop(debug_index)

    # if no output dir provided, just name it based on seed dir
    to_process = script_options[0]
    if len(script_options) == 1:
        to_process = os.path.normpath(to_process)
        output_dir = to_process + "-cov"
    else:
        output_dir = script_options[1]

    if not os.path.exists(to_process):
        print("[!] Seed directory %s does not exist, quitting." % to_process)
        exit()

    print("[*] Using output directory %s" % output_dir)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    if "@@" not in target_invocation:
        print("[!] Currently only AFL-style @@-replacement invocations are supported,")
        print("    and '@@' not found in the target invocation; quitting.")
        exit()
    print("[*] Non-instrumented invocation: %s" % target_invocation)
    target_binary = target_invocation.split()[0]
    print("[*] Presumed target executable: %s" % target_binary)

    bitness = 32
    if is64bit(target_binary):
        bitness = 64
    path_to_drrun = "%s/bin%d/drrun" % (path_to_dynamorio, bitness)
    if not os.path.exists(path_to_drrun):
        print("[!] drrun not found at expected path: %s" % path_to_drrun)
        exit()
    command = "%s -t drcov -- %s" % (path_to_drrun, target_invocation)

    prev_skipped_files = -1
    pool = None
    # break out of loop by checking continuously_monitor at end
    # or CTRL+C at any time
    try:
        while True:
            # gather inputs
            if os.path.isdir(to_process):
                files_to_process = [os.path.join(to_process, name) for name in os.listdir(to_process)]
            else:
                files_to_process = [to_process]
            num_existing_files = len(os.listdir(output_dir))

            files_to_remove = []
            skipped_files = 0
            for filepath in files_to_process:
                # silently remove afl-style state file
                if os.path.basename(filepath) == ".state":
                    # print("[!] Removing \".state\" from list of seeds, rename the file to include it")
                    files_to_remove.append(filepath)
                    continue
                # silently remove tmp files
                if os.path.basename(filepath).startswith(".fuse_hidden"):
                    files_to_remove.append(filepath)
                    continue
                # skip input files with existing coverage file
                output_path = os.path.join(output_dir, os.path.basename(filepath) + ".cov")
                if os.path.exists(output_path):
                    files_to_remove.append(filepath)
                    skipped_files += 1
            files_to_process = [f for f in files_to_process if f not in files_to_remove]
            # for continuous monitoring, only announce skipping when number of files changes
            if skipped_files != prev_skipped_files:
                print("[*] Skipping %d files with existing coverage" % skipped_files)
            prev_skipped_files = skipped_files
            num_files = len(files_to_process)
            if num_files != 0:
                print("[*] %d files to process:" % num_files)

            pool = multiprocessing.Pool(num_workers)
            return_stream = pool.imap(wrap_get_block_coverage, files_to_process)
            for i, path in enumerate(files_to_process):
                if return_stream.next():
                    # If this doesn't work, use sys.stdout.write("\b" * prev_output_len) 
                    sys.stdout.write("\r[%d/%d] Coverage collected for %s" 
                                     % (i+1, num_files, path))
                    sys.stdout.flush() 
            sys.stdout.write("\n")
            pool.close()
            pool = None

            if continuously_monitor:
                time.sleep(2)
            else:
                break
    except KeyboardInterrupt:
        print("[!] Caught CTRL+C")
        if pool:
            pool.terminate()

    print("[*] Done, check for coverage files in %s" % output_dir)
