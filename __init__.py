from __future__ import division, absolute_import

from binaryninja import *
import os
from time import time, sleep

from .coverage import CoverageDB

# __init__.py is only for Binary Ninja UI-related tasks

USAGE_HINT = """[*] In the python shell, do `import bncov` to use
[*] bncov.covdb houses the the coverage-related functions (see coverage.py for more):
    bncov.covdb.get_traces_from_block(addr) - get files that cover block starting at addr
        Tip: click somewhere, then do bncov.covdb.get_traces_from_block(here)
    bncov.covdb.get_rare_blocks(threshold) - get blocks covered by <= threshold traces
    bncov.covdb.get_frontier(bv) - get blocks that have outgoing edges that aren't covered
[*] Helpful covdb members:
    covdb.trace_dict (maps filenames to set of block start addrs)
    covdb.block_dict (maps block start addrs to files containing it)
    covdb.total_coverage (set of addresses of starts of bbs covered)
[*] If you pip install msgpack, you can save/load the covdb (WARNING: files can be large)
[*] Useful UI-related bncov functions (more are in the Highlights submenu)
    bncov.highlight_set(addr_set, color=None) -
        Highlight blocks by set basic block start addrs, optional color override
    bncov.highlight_trace(filepath, color_name="") -
        Highlight one trace file, optionally with a human-readable color_name
    bncov.restore_default_highlights() - Reverts covered blocks to heatmap highlights.
[*] Built-in python set operations and highlight_set() allow for custom highlights.
    You can also import coverage.py for coverage analysis in headless scripts.
    Please report any bugs via the git repo."""


# Helpers for scripts
def get_bv(target_filename, quiet=True):
    """Return a BinaryView of target_filename"""
    if not os.path.exists(target_filename):
        print("[!] Couldn't find target file %s..." % target_filename)
        return None
    if not quiet:
        print("=== LOADING DATA ===")
        sys.stdout.write("[B] Loading Binary Ninja view of %s... " % target_filename)
        sys.stdout.flush()
        start = time()
    bv = BinaryViewType.get_view_of_file(target_filename)
    if not quiet:
        bv.update_analysis_and_wait()
        print("finished in %.02f seconds" % (time() - start))
    return bv


def get_covdb(bv, coverage_directory, quiet=True):
    """Return a CoverageDB based on bv and directory"""
    if not quiet:
        sys.stdout.write("[C] Creating coverage db from directory %s..." % coverage_directory)
        sys.stdout.flush()
        start = time()
    covdb = CoverageDB(bv)
    covdb.add_directory(coverage_directory)
    if not quiet:
        duration = time() - start
        num_files = len(os.listdir(coverage_directory))
        print(" finished (%d files) in %.02f seconds" % (num_files, duration))
    return covdb


def save_bndb(bv, bndb_name=None):
    """Save current BinaryView to .bndb"""
    if bndb_name is None:
        bndb_name = os.path.basename(bv.file.filename)  # filename may be a .bndb already
    if not bndb_name.endswith('.bndb'):
        bndb_name += ".bndb"
    bv.create_database(bndb_name)


# Globals and functions managing them:
watcher = None
watching = False
gbv = None
covdb = None


def set_globals(bv):
    global gbv, covdb
    if gbv is None:
        gbv = bv
        log.log_info(USAGE_HINT)
    if covdb is None:
        covdb = CoverageDB(bv)


def clear_globals():
    global gbv, covdb
    gbv = None
    covdb = None
    cancel_watch()


# UI warning function
def no_coverage_warn():
    """If no coverage imported, pops a warning box and returns True"""
    if covdb is None or len(covdb.coverage_files) == 0:
        show_message_box("Need to Import Traces First",
                         "Can't perform this action yet, no traces have been imported",
                         MessageBoxButtonSet.OKButtonSet,
                         MessageBoxIcon.ErrorIcon)
        return True
    return False


# UI interaction functions:
def get_heatmap_color(hit_count, max_count):
    """Return HighlightColor between Blue and Red based on hit_count/max_count.

    If max_count is 1 or 0, uses red."""
    heatmap_colors = [[0, 0, 255], [255, 0, 0]]  # blue to red
    rgb = []
    hit_count -= 1  # 0 hits wouldn't be highlighted at all
    max_count -= 1  # adjust max to reflect lack of hitcount == 0
    if max_count <= 0:
        rgb = heatmap_colors[1]
    else:
        for i in range(len("rgb")):
            common = heatmap_colors[0][i]
            uncommon = heatmap_colors[1][i]
            step = (common - uncommon) / max_count
            rgb.append(int(uncommon + step * hit_count))
    color = HighlightColor(red=rgb[0], green=rgb[1], blue=rgb[2])
    return color


def highlight_block(block, count=0, color=None):
    """Highlight a block with heatmap default or a specified HighlightColor"""
    if color is None:
        if covdb is not None:
            max_count = len(covdb.trace_dict)
        else:
            max_count = 0
        color = get_heatmap_color(count, max_count)
    block.set_user_highlight(color)


# This is the basic building block for visualization
def highlight_set(addr_set, color=None, bv=None):
    """Take a set of addresses and highlight the blocks containing them.

    You can use this manually, but you'll have to clear your own highlights.
    bncov.highlight_set(addrs, color=bncov.colors['blue'], bv=bv)"""
    if bv is not None:
        binary_view = bv
    else:
        if gbv is None:
            print("[!] To use manually, pass in a binary view or set bncov.gbv first")
            return
        binary_view = gbv
    for addr in addr_set:
        blocks = binary_view.get_basic_blocks_at(addr)
        if len(blocks) >= 1:
            for block in blocks:
                if covdb is not None:
                    if addr in covdb.block_dict:
                        count = len(covdb.block_dict[addr])
                    else:
                        count = 0
                    highlight_block(block, count, color)
                else:
                    highlight_block(block, 0, color)
        else:
            log.log_warn("[!] No basic block at requested addr 0x%x" % addr)


def clear_highlights(addr_set, bv):
    """Clear all highlights from the set of blocks"""
    for addr in addr_set:
        blocks = bv.get_basic_blocks_at(addr)
        for block in blocks:
            block.set_user_highlight(HighlightStandardColor.NoHighlightColor)


colors = {"black":   HighlightStandardColor.BlackHighlightColor,
          "blue":    HighlightStandardColor.BlueHighlightColor,
          "cyan":    HighlightStandardColor.CyanHighlightColor,
          "green":   HighlightStandardColor.GreenHighlightColor,
          "magenta": HighlightStandardColor.MagentaHighlightColor,
          "orange":  HighlightStandardColor.OrangeHighlightColor,
          "red":     HighlightStandardColor.RedHighlightColor,
          "white":   HighlightStandardColor.WhiteHighlightColor,
          "yellow":  HighlightStandardColor.YellowHighlightColor}


# Good for interactive highlighting, undo with restore_default_highlights()
def highlight_trace(filepath, color_name=""):
    """Highlight blocks from a given trace with human-readable color_name"""
    if filepath not in covdb.coverage_files:
        log.log_error("[!] %s is not in the coverage DB" % filepath)
        return
    blocks = covdb.trace_dict[filepath]
    if color_name == "":
        color = HighlightStandardColor.OrangeHighlightColor
    elif color_name.lower() in colors:
        color = colors[color_name]
    else:
        log.log_warn("[!] %s isn't a HighlightStandardColor, using my favorite color instead" % color_name)
        color = colors["red"]
    highlight_set(blocks, color)
    log.log_info("[*] Highlighted %d basic blocks in trace %s" % (len(blocks), filepath))


def tour_set(addresses, duration=None, delay=None):
    """Go on a whirlwind tour of a set of addresses"""
    bv = gbv
    default_duration = 20  # seconds
    num_addresses = len(addresses)
    # overriding duration is probably safer
    if duration is None:
        duration = default_duration
    # but why not
    if delay is None:
        delay = duration / num_addresses
    else:
        delay = float(delay)
    log.log_debug("[*] %d addresses to tour, delay: %.2f, tour time: %.2f" %
                  (num_addresses, delay, delay*num_addresses))
    for addr in addresses:
        bv.navigate(bv.view, addr)
        sleep(delay)


# NOTE: this call will block until it finishes
def highlight_dir(bv, covdir=None, color=None):
    set_globals(bv)
    if covdir is None:
        covdir = get_directory_name_input("Coverage File Directory")
    covdb.add_directory(covdir)
    highlight_set(covdb.total_coverage)
    log.log_info("Highlighted basic blocks for %d files from %s" % (len(os.listdir(covdir)), covdir))


def restore_default_highlights(bv=None):
    """Resets coverage highlighting to the default heatmap"""
    highlight_set(covdb.total_coverage)
    log.log_info("Default highlight colors restored")


# Import helpers:
def cancel_watch():
    """If continuous monitoring was used, cancel it"""
    global watcher, watching
    if watcher is not None:
        watcher.finish()
        watcher = None
        watching = False


class BackgroundHighlighter(BackgroundTaskThread):
    def __init__(self, bv, coverage_dir, watch=False):
        super(BackgroundHighlighter, self).__init__("Starting import...", can_cancel=True)
        self.progress = "Initializing..."
        self.bv = bv
        self.coverage_dir = coverage_dir
        self.watch = watch
        self.start_time = time()
        self.files_processed = []

    def watch_dir_forever(self):
        self.progress = "Will continue monitoring %s" % self.coverage_dir
        # Immediately (re)color blocks in new traces, but also recolor all blocks when idle for some time
        # in order to show changes in relative rarity for blocks not touched by new traces
        idle = -1  # idle -1 means no new coverage seen
        idle_threshold = 5
        while True:
            dir_files = os.listdir(self.coverage_dir)
            new_files = [name for name in dir_files if name not in self.files_processed]
            new_coverage = set()
            for new_file in new_files:
                new_coverage |= covdb.add_file(os.path.join(self.coverage_dir, new_file))
                log.log_debug("[DBG] Added new coverage from file %s @ %d" % (new_file, int(time())))
                self.files_processed.append(new_file)
            num_new_coverage = len(new_coverage)
            if num_new_coverage > 0:
                highlight_set(new_coverage)
                idle = 0
                log.log_debug("[DBG] Updated highlights for %d blocks" % num_new_coverage)
            else:
                if idle >= 0:
                    idle += 1
                if idle > idle_threshold:
                    highlight_set(covdb.total_coverage)
                    idle = -1
            sleep(1)
            if not watching:
                break
            if self.cancelled:
                break

    def run(self):
        try:
            log.log_info("[*] Loading coverage files from %s" % self.coverage_dir)
            dirlist = os.listdir(self.coverage_dir)
            num_files = len(dirlist)
            files_processed = 0
            for filename in dirlist:
                covdb.add_file(os.path.join(self.coverage_dir, filename))
                self.progress = "%d / %d files processed" % (files_processed, num_files)
                files_processed += 1
                self.files_processed.append(filename)
                if self.cancelled:
                    break
            highlight_set(covdb.total_coverage)
            log.log_info("[*] Highlighted basic blocks for %d files from %s" % (len(dirlist), self.coverage_dir))
            log.log_info("[*] Parsing/highlighting took %.2f seconds" % (time() - self.start_time))
            if self.watch:
                self.watch_dir_forever()
        finally:
            self.progress = ""


# PluginCommand - Coverage import functions
def import_file(bv, filepath=None, color=None):
    """Import a single coverage file"""
    set_globals(bv)
    if filepath is None:
        filepath = get_open_filename_input("Coverage File")
        if filepath is None:
            return
    covdb.add_file(filepath)
    blocks = covdb.trace_dict[filepath]
    highlight_set(blocks, color)
    log.log_info("[*] Highlighted %d basic blocks for file %s" % (len(blocks), filepath))


def background_import_dir(bv, watch=False):
    """Import a directory containing coverage files"""
    global watcher, watching
    set_globals(bv)
    coverage_dir = get_directory_name_input("Coverage File Directory")
    if coverage_dir is None:
        return
    watching = True
    watcher = BackgroundHighlighter(bv, coverage_dir, watch)
    watcher.start()


def background_import_dir_and_watch(bv):
    """Import a directory, and then watch for new files and import them"""
    background_import_dir(bv, watch=True)


def import_saved_covdb(bv, filepath=None):
    """Import a previously-generated and saved .covdb (fast but requires msgpack)"""
    try:
        import msgpack
    except ImportError:
        log.log_error("[!] Can't import saved covdb files without msgpack installed")
        return
    set_globals(bv)
    if filepath is None:
        filepath = get_open_filename_input("Saved CoverageDB")
        if filepath is None:
            return
    start_time = time()
    covdb.load_from_file(filepath)
    highlight_set(covdb.total_coverage)
    log.log_info("[*] Highlighted %d blocks from %s (containing %d files) in %.2f seconds" %
                 (len(covdb.total_coverage), filepath, len(covdb.coverage_files), time() - start_time))


def clear_coverage(bv=None):
    """Deletes coverage objects and removes coverage highlighting"""
    if covdb and len(covdb.coverage_files) > 0:
        remove_highlights()
    clear_globals()
    log.log_info("[*] Coverage information cleared")


# PluginCommands - Highlight functions, only valid once coverage is imported
def remove_highlights(bv=None):
    """Removes highlighting from all covered blocks"""
    if no_coverage_warn():
        return
    if bv is None:
        bv = gbv
    clear_highlights(covdb.total_coverage, bv)
    log.log_info("Highlights cleared.")


def highlight_frontier(bv=None):
    """Highlights blocks with uncovered outgoing edge targets a delightful green"""
    if no_coverage_warn():
        return
    frontier_set = covdb.get_frontier()
    frontier_color = HighlightStandardColor.GreenHighlightColor
    highlight_set(frontier_set, frontier_color)
    log.log_info("[*] Highlighted %d frontier blocks" % (len(frontier_set)))
    for block in frontier_set:
        log.log_info("      0x%x" % block)


def highlight_rare_blocks(bv, threshold=1):
    """Highlights blocks covered by < threshold traces a whitish red"""
    if no_coverage_warn():
        return
    rare_blocks = covdb.get_rare_blocks(threshold)
    rare_color = HighlightStandardColor.RedHighlightColor
    highlight_set(rare_blocks, rare_color)
    log.log_info("[*] Found %d rare blocks (threshold: %d)" %
                 (len(rare_blocks), threshold))
    for block in rare_blocks:
        log.log_info("      0x%x" % block)


# PluginCommand - Report
# Included this to show the potential usefulness of in-GUI reports
def show_coverage_report(bv):
    """Open a tab with a report of coverage statistics for each function"""
    if no_coverage_warn():
        return
    num_functions, blocks_covered, blocks_total = covdb.get_overall_function_coverage()
    title = "Coverage Report for %s" % covdb.module_name
    report = "%d Functions, %d blocks covered of %d total\n" % (num_functions, blocks_covered, blocks_total)
    report_html = "<h3>%d Functions, %d blocks covered of %d total</h3>\n" % (num_functions, blocks_covered, blocks_total)
    report_html += "<table>\n"
    function_dict = {f.name: f for f in bv.functions}
    name_dict = {}
    for f in bv.functions:
        name_dict[f.name] = f.symbol.short_name
    max_name_length = max([len(name) for name in name_dict.values()])
    for mangled_name, stats in sorted(covdb.function_stats.items(), key=lambda x: x[1].coverage_percent, reverse=True):
        name = name_dict[mangled_name]
        pad = " " * (max_name_length - len(name))
        function_addr = function_dict[mangled_name].start
        report += "  0x%08x  %s%s : %.2f%% coverage\t( %-3d / %3d blocks)\n" % \
                  (function_addr, name, pad, stats.coverage_percent, stats.blocks_covered, stats.blocks_total)
        report_html += "<tr><td><a href='binaryninja:?expr=0x%x'>0x%08x</a></td><td>%s</td><td>%.2f%% coverage</td><td>%-3d / %3d blocks</td></tr>\n" % \
                  (function_addr, function_addr, name, pad, stats.coverage_percent, stats.blocks_covered, stats.blocks_total)

    report_html += "</table>\n"
    show_html_text_report(title, report_html, plaintext=report)


# Register plugin commands
PluginCommand.register("bncov\\Coverage Data\\Import Directory",
                       "Import basic block coverage from files in directory",
                       background_import_dir)
PluginCommand.register("bncov\\Coverage Data\\Import Directory and Watch",
                       "Import basic block coverage from directory and watch for new coverage",
                       background_import_dir_and_watch)
PluginCommand.register("bncov\\Coverage Data\\Import File",
                       "Import basic blocks by coverage",
                       import_file)
try:
    import msgpack
    PluginCommand.register("bncov\\Coverage Data\\Import Saved CoverageDB",
                           "Import saved coverage database",
                           import_saved_covdb)
except ImportError:
    pass

PluginCommand.register("bncov\\Coverage Data\\Reset Coverage State",
                       "Clear the current coverage state",
                       clear_coverage)

# These are only valid once coverage data exists
PluginCommand.register("bncov\\Highlighting\\Remove Highlights",
                       "Remove basic block highlights",
                       remove_highlights)
PluginCommand.register("bncov\\Highlighting\\Highlight Rare Blocks",
                       "Highlight only the rarest of blocks",
                       highlight_rare_blocks)
PluginCommand.register("bncov\\Highlighting\\Highlight Coverage Frontier",
                       "Highlight blocks that didn't get fully covered",
                       highlight_frontier)
PluginCommand.register("bncov\\Highlighting\\Restore Default Highlights",
                       "Highlight coverage",
                       restore_default_highlights)

PluginCommand.register("bncov\\Reports\\Generate Coverage Report",
                       "Show a report of function coverage",
                       show_coverage_report)
