from __future__ import division, absolute_import

from binaryninja import *

import os
import sys
from dataclasses import dataclass
from typing import Optional
from time import time, sleep
from html import escape as html_escape
from webbrowser import open_new_tab as open_new_browser_tab

from .coverage import CoverageDB

# shim for backwards-compatible log
import binaryninja
if hasattr(binaryninja.log, 'log_debug'):
    log_debug = log.log_debug
    log_info = log.log_info
    log_warn = log.log_warn
    log_error = log.log_error

# __init__.py is only for Binary Ninja UI-related tasks

PLUGIN_NAME = "bncov"

USAGE_HINT = """[*] In the python shell, do `import bncov` to use
[*] bncov.get_covdb(bv) gets the covdb object for the given Binary View
    covdb houses the the coverage-related functions (see coverage.py for more):
    covdb.get_traces_from_block(addr) - get files that cover block starting at addr
        Tip: click somewhere, then do bncov.covdb.get_traces_from_block(here)
    covdb.get_rare_blocks(threshold) - get blocks covered by <= threshold traces
    covdb.get_frontier(bv) - get blocks that have outgoing edges that aren't covered
[*] Helpful covdb members:
    covdb.trace_dict (maps filenames to set of block start addrs)
    covdb.block_dict (maps block start addrs to files containing it)
    covdb.total_coverage (set of addresses of starts of bbs covered)
[*] If you pip install msgpack, you can save/load the covdb (WARNING: files can be large)
[*] Useful UI-related bncov functions (more are in the Highlights submenu)
    bncov.highlight_set(addr_set, color=None) -
        Highlight blocks by set of basic block start addrs, optional color override
    bncov.highlight_trace(bv, filepath, color_name="") -
        Highlight one trace file, optionally with a human-readable color_name
    bncov.restore_default_highlights(bv) - Reverts covered blocks to heatmap highlights.
[*] Built-in python set operations and highlight_set() allow for custom highlights.
    You can also import coverage.py for coverage analysis in headless scripts.
    Please report any bugs via the git repo."""


@dataclass
class Ctx:
    covdb: CoverageDB
    watcher: Optional[BackgroundTaskThread]


# Helpers for scripts
def make_bv(target_filename, quiet=True):
    """Return a BinaryView of target_filename"""
    if not os.path.exists(target_filename):
        print("[!] Couldn't find target file \"%s\"..." % target_filename)
        return None
    if not quiet:
        sys.stdout.write("[B] Loading Binary Ninja view of \"%s\"... " % target_filename)
        sys.stdout.flush()
        start = time()
    bv = BinaryViewType.get_view_of_file(target_filename)
    bv.update_analysis_and_wait()
    if not quiet:
        print("finished in %.02f seconds" % (time() - start))
    return bv


def make_covdb(bv: BinaryView, coverage_directory, quiet=True):
    """Return a CoverageDB based on bv and directory"""
    if not os.path.exists(coverage_directory):
        print("[!] Couldn't find coverage directory \"%s\"..." % coverage_directory)
        return None
    if not quiet:
        sys.stdout.write("[C] Creating coverage db from directory \"%s\"..." % coverage_directory)
        sys.stdout.flush()
        start = time()
    covdb = CoverageDB(bv)
    covdb.add_directory(coverage_directory)
    if not quiet:
        duration = time() - start
        num_files = len(os.listdir(coverage_directory))
        print(" finished (%d files) in %.02f seconds" % (num_files, duration))
    return covdb


def save_bndb(bv: BinaryView, bndb_name=None):
    """Save current BinaryView to .bndb"""
    if bndb_name is None:
        bndb_name = os.path.basename(bv.file.filename)  # filename may be a .bndb already
    if not bndb_name.endswith('.bndb'):
        bndb_name += ".bndb"
    bv.create_database(bndb_name)


usage_shown = False
def get_ctx(bv: BinaryView) -> Ctx:
    global usage_shown
    ctx = bv.session_data.get(PLUGIN_NAME)

    if ctx is None:
        covdb = CoverageDB(bv)
        ctx = Ctx(covdb, None)
        bv.session_data[PLUGIN_NAME] = ctx
        if not usage_shown:
            log_info(USAGE_HINT)
            usage_shown = True

    return ctx


def get_covdb(bv: BinaryView) -> CoverageDB:
    return get_ctx(bv).covdb


def close_covdb(bv: BinaryView):
    cancel_watch(bv)
    bv.session_data.pop(PLUGIN_NAME)


# UI warning function
def no_coverage_warn(bv: BinaryView):
    """If no coverage imported, pops a warning box and returns True"""
    ctx = get_ctx(bv)
    if len(ctx.covdb.coverage_files) == 0:
        show_message_box("Need to Import Traces First",
                         "Can't perform this action yet, no traces have been imported for this Binary View",
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
    ctx = get_ctx(block.view)
    if color is None:
        if ctx.covdb is not None:
            max_count = len(ctx.covdb.trace_dict)
        else:
            max_count = 0
        color = get_heatmap_color(count, max_count)
    block.set_user_highlight(color)


# This is the basic building block for visualization
def highlight_set(bv: BinaryView, addr_set, color=None, start_only=True):
    """Take a set of addresses and highlight the blocks starting at (or containing if start_only=False) those addresses.

    You can use this manually, but you'll have to clear your own highlights.
    bncov.highlight_set(bv, addrs, color=bncov.colors['blue'])
    If you're using this manually just to highlight the blocks containing
    a group of addresses and aren't worry about overlapping blocks, use start_only=False.
    """
    if start_only:
        get_blocks = bv.get_basic_blocks_starting_at
    else:
        get_blocks = bv.get_basic_blocks_at
    for addr in addr_set:
        blocks = get_blocks(addr)
        if len(blocks) >= 1:
            ctx = get_ctx(bv)
            for block in blocks:
                if addr in ctx.covdb.block_dict:
                    count = len(ctx.covdb.block_dict[addr])
                else:
                    count = 0
                highlight_block(block, count, color)
        else:
            if get_blocks == bv.get_basic_blocks_starting_at:
                containing_blocks = bv.get_basic_blocks_at(addr)
                if containing_blocks:
                    log_warn("[!] No blocks start at 0x%x, but %d blocks contain it:" %
                                 (addr, len(containing_blocks)))
                    for i, block in enumerate(containing_blocks):
                        log_info("%d: 0x%x - 0x%x in %s" % (i, block.start, block.end, block.function.name))
                else:
                    log_warn("[!] No blocks contain address 0x%x; check the address is inside a function." % addr)
            else:  # get_blocks is bv.get_basic_blocks_at
                log_warn("[!] No blocks contain address 0x%x; check the address is inside a function." % addr)


def clear_highlights(bv: BinaryView, addr_set):
    """Clear all highlights from the set of blocks containing the addrs in addr_set"""
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
def highlight_trace(bv: BinaryView, filepath, color_name=""):
    """Highlight blocks from a given trace with human-readable color_name"""
    ctx = get_ctx(bv)
    if filepath not in ctx.covdb.coverage_files:
        log_error("[!] %s is not in the coverage DB" % filepath)
        return
    blocks = ctx.covdb.trace_dict[filepath]
    if color_name == "":
        color = HighlightStandardColor.OrangeHighlightColor
    elif color_name.lower() in colors:
        color = colors[color_name]
    else:
        log_warn("[!] %s isn't a HighlightStandardColor, using my favorite color instead" % color_name)
        color = colors["red"]
    highlight_set(bv, blocks, color)
    log_info("[*] Highlighted %d basic blocks in trace %s" % (len(blocks), filepath))


def tour_set(bv: BinaryView, addresses, duration=None, delay=None):
    """Go on a whirlwind tour of a set of addresses"""
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
    log_debug("[*] %d addresses to tour, delay: %.2f, tour time: %.2f" %
                  (num_addresses, delay, delay*num_addresses))
    for addr in addresses:
        bv.navigate(bv.view, addr)
        sleep(delay)


# NOTE: this call will block until it finishes
def highlight_dir(bv: BinaryView, covdir=None, color=None):
    ctx = get_ctx(bv)
    if covdir is None:
        covdir = get_directory_name_input("Coverage File Directory")
    ctx.covdb.add_directory(covdir)
    highlight_set(bv, ctx.covdb.total_coverage)
    log_info("Highlighted basic blocks for %d files from %s" % (len(os.listdir(covdir)), covdir))


def restore_default_highlights(bv: BinaryView):
    """Resets coverage highlighting to the default heatmap"""
    ctx = get_ctx(bv)
    highlight_set(bv, ctx.covdb.total_coverage)
    log_info("Default highlight colors restored")


# Import helpers:
def cancel_watch(bv: BinaryView):
    """If continuous monitoring was used, cancel it"""
    ctx = get_ctx(bv)
    if ctx.watcher is not None:
        ctx.watcher.finish()
        ctx.watcher = None


class BackgroundHighlighter(BackgroundTaskThread):
    def __init__(self, bv: BinaryView, coverage_dir, watch=False):
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
        ctx = get_ctx(self.bv)
        while True:
            dir_files = os.listdir(self.coverage_dir)
            new_files = [name for name in dir_files if name not in self.files_processed]
            new_coverage = set()
            for new_file in new_files:
                new_coverage |= ctx.covdb.add_file(os.path.join(self.coverage_dir, new_file))
                log_debug("[DBG] Added new coverage from file %s @ %d" % (new_file, int(time())))
                self.files_processed.append(new_file)
            num_new_coverage = len(new_coverage)
            if num_new_coverage > 0:
                highlight_set(self.bv, new_coverage)
                idle = 0
                log_debug("[DBG] Updated highlights for %d blocks" % num_new_coverage)
            else:
                if idle >= 0:
                    idle += 1
                if idle > idle_threshold:
                    highlight_set(self.bv, ctx.covdb.total_coverage)
                    idle = -1
            sleep(1)
            if ctx.watcher is None:
                break
            if self.cancelled:
                break

    def run(self):
        try:
            ctx = get_ctx(self.bv)
            log_info("[*] Loading coverage files from %s" % self.coverage_dir)
            dirlist = os.listdir(self.coverage_dir)
            num_files = len(dirlist)
            files_processed = 0
            for filename in dirlist:
                filepath = os.path.join(self.coverage_dir, filename)
                if os.path.getsize(filepath) == 0:
                    log_warn('Coverage file %s is empty, skipping...' % filepath)
                    continue
                blocks = ctx.covdb.add_file(filepath)
                if len(blocks) == 0:
                    log_warn('Coverage file %s yielded zero coverage information' % filepath)
                self.progress = "%d / %d files processed" % (files_processed, num_files)
                files_processed += 1
                self.files_processed.append(filename)
                if self.cancelled:
                    break
            highlight_set(self.bv, ctx.covdb.total_coverage)
            log_info("[*] Highlighted basic blocks for %d files from %s" % (len(dirlist), self.coverage_dir))
            log_info("[*] Parsing/highlighting took %.2f seconds" % (time() - self.start_time))
            if self.watch:
                self.watch_dir_forever()
        finally:
            self.progress = ""


# PluginCommand - Coverage import functions
def import_file(bv: BinaryView, filepath=None, color=None):
    """Import a single coverage file"""
    ctx = get_ctx(bv)
    if filepath is None:
        filepath = get_open_filename_input("Coverage File")
        if filepath is None:
            return
    if os.path.getsize(filepath) == 0:
        log_warn('Coverage file %s is empty!' % filepath)
        return
    blocks = ctx.covdb.add_file(filepath)
    if len(blocks) == 0:
        log_warn('Coverage file %s yielded 0 coverage blocks' % filepath)
    else:
        highlight_set(bv, blocks, color)
        log_info("[*] Highlighted %d basic blocks for file %s" % (len(blocks), filepath))


def background_import_dir(bv: BinaryView, watch=False):
    """Import a directory containing coverage files"""
    ctx = get_ctx(bv)
    coverage_dir = get_directory_name_input("Coverage File Directory")
    if coverage_dir is None:
        return
    ctx.watcher = BackgroundHighlighter(bv, coverage_dir, watch)
    ctx.watcher.start()


def background_import_dir_and_watch(bv: BinaryView):
    """Import a directory, and then watch for new files and import them"""
    background_import_dir(bv, watch=True)


def import_saved_covdb(bv: BinaryView, filepath=None):
    """Import a previously-generated and saved .covdb (fast but requires msgpack)"""
    try:
        import msgpack
    except ImportError:
        log_error("[!] Can't import saved covdb files without msgpack installed")
        return
    ctx = get_ctx(bv)
    if filepath is None:
        filepath = get_open_filename_input("Saved CoverageDB")
        if filepath is None:
            return
    start_time = time()
    ctx.covdb.load_from_file(filepath)
    highlight_set(bv, ctx.covdb.total_coverage)
    log_info("[*] Highlighted %d blocks from %s (containing %d files) in %.2f seconds" %
                 (len(ctx.covdb.total_coverage), filepath, len(ctx.covdb.coverage_files), time() - start_time))


def clear_coverage(bv: BinaryView):
    """Deletes coverage objects and removes coverage highlighting"""
    ctx = get_ctx(bv)
    if len(ctx.covdb.coverage_files) > 0:
        remove_highlights(bv)
    close_covdb(bv)
    log_info("[*] Coverage information cleared")


# PluginCommands - Highlight functions, only valid once coverage is imported
def remove_highlights(bv: BinaryView):
    """Removes highlighting from all covered blocks"""
    if no_coverage_warn(bv):
        return
    ctx = get_ctx(bv)
    clear_highlights(bv, ctx.covdb.total_coverage)
    log_info("Highlights cleared.")


def highlight_frontier(bv: BinaryView):
    """Highlights blocks with uncovered outgoing edge targets a delightful green"""
    if no_coverage_warn(bv):
        return
    ctx = get_ctx(bv)
    frontier_set = ctx.covdb.get_frontier()
    frontier_color = HighlightStandardColor.GreenHighlightColor
    highlight_set(bv, frontier_set, frontier_color)
    log_info("[*] Highlighted %d frontier blocks" % (len(frontier_set)))
    for block in frontier_set:
        log_info("      0x%x" % block)


def highlight_rare_blocks(bv: BinaryView, threshold=1):
    """Highlights blocks covered by < threshold traces a whitish red"""
    if no_coverage_warn(bv):
        return
    ctx = get_ctx(bv)
    rare_blocks = ctx.covdb.get_rare_blocks(threshold)
    rare_color = HighlightStandardColor.RedHighlightColor
    highlight_set(bv, rare_blocks, rare_color)
    log_info("[*] Found %d rare blocks (threshold: %d)" %
                 (len(rare_blocks), threshold))
    for block in rare_blocks:
        log_info("      0x%x" % block)


# PluginCommand - Report
# Included this to show the potential usefulness of in-GUI reports
def show_coverage_report(bv: BinaryView, save_output=False, filter_func=None, report_name=None):
    """Open a tab with a report of coverage statistics for each function.

    Optionally accept a filter function that gets the function start and stats
    and returns True if it should be included in the report, False otherwise."""

    if no_coverage_warn(bv):
        return
    covdb = get_covdb(bv)
    covdb.get_overall_function_coverage()

    # Build report overview stats with the optional filter callback
    blocks_covered = 0
    blocks_total = 0
    addr_to_name_dict = {}
    for function_addr, stats in covdb.function_stats.items():
        if filter_func is None or filter_func(function_addr, stats):
            demangled_name = bv.get_function_at(function_addr).symbol.short_name
            addr_to_name_dict[function_addr] = demangled_name
            blocks_covered += stats.blocks_covered
            blocks_total += stats.blocks_total
    num_functions = len(addr_to_name_dict)
    if num_functions == 0 and filter_func is not None:
        log_error('All functions filtered!')
        return

    if report_name is None:
        report_name = 'Coverage Report'
    title = "%s for %s" % (report_name, covdb.module_name)

    num_functions_unfiltered = len(covdb.function_stats)
    if num_functions == num_functions_unfiltered:
        report_header = "%d Functions, %d blocks covered of %d total" % \
            (num_functions, blocks_covered, blocks_total)
    else:
        report_header = "%d / %d Functions shown, %d / %d blocks covered" % \
            (num_functions, num_functions_unfiltered, blocks_covered, blocks_total)

    report_plaintext = "%s\n" % report_header
    report_html = "<h3>%s</h3>\n" % report_header
    column_titles = ['Start Address', 'Function Name', 'Coverage Percent', 'Blocks Covered / Total', 'Complexity']
    report_html += ("<table class=\"sortable\">\n<thead>\n<tr>%s</tr>\n</thead>\n<tbody>" % \
        ''.join('<th>%s</th>' % title for title in column_titles))

    max_name_length = max([len(name) for name in addr_to_name_dict.values()])
    for function_addr, stats in sorted(covdb.function_stats.items(), key=lambda x: (x[1].coverage_percent, x[1].blocks_covered), reverse=True):
        # skip filtered functions
        if function_addr not in addr_to_name_dict:
            continue

        name = addr_to_name_dict[function_addr]
        pad = " " * (max_name_length - len(name))

        report_plaintext += "  0x%08x  %s%s : %.2f%%\t( %-3d / %3d blocks)\n" % \
                  (function_addr, name, pad, stats.coverage_percent, stats.blocks_covered, stats.blocks_total)

        # build the html table row one item at a time, then combine them
        function_link = '<a href="binaryninja://?expr=0x%x">0x%08x</a>' % (function_addr, function_addr)
        function_name = html_escape(name)
        coverage_percent = '%.2f%%' % stats.coverage_percent
        blocks_covered = '%d / %d blocks' % (stats.blocks_covered, stats.blocks_total)
        row_data = [function_link, function_name, coverage_percent, blocks_covered, str(stats.complexity)]
        table_row = '<tr>' + ''.join('<td>%s</td>' % item for item in row_data) + '</tr>'
        report_html += table_row

    report_html += "</tbody></table>\n"

    embedded_css = '''<style type="text/css" media="screen">

table {
  table-layout: fixed;
  width: 100%;
  border-collapse: collapse;
  white-space: nowrap;
}

table th, td {
    border: 1px solid gray;
    padding: 4px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    color: #e0e0e0;
}

table tr:nth-child(even) {
    background-color: #242424;
}
table tr:nth-child(odd) {
    background-color: #2a2a2a;
}

table th {
    font: bold;
    background-color: #181818;
}

a:link { color: #80c6e9; }

</style>\n'''
    # Optional, if it doesn't load, then the table is pre-sorted
    js_sort = '<script src="https://www.kryogenix.org/code/browser/sorttable/sorttable.js"></script>'
    report_html = '<html>\n<head>\n%s\n%s\n</head>\n<body>\n%s\n</body>\n</html>' % \
        (embedded_css, js_sort, report_html)

    # Save report if it's too large to display or if user asks
    choices = ["Cancel Report", "Save Report to File", "Save Report and Open in Browser"]
    choice = 0  # "something unexpected" choice
    save_file, save_and_open = 1, 2  # user choices
    if len(report_html) > 1307673:  # if Qt eats even one little wafer more, it bursts
        choice = interaction.get_choice_input(
            "Qt can't display a report this large. Select an action.",
            "Generated report too large",
            choices)
        if choice in [save_file, save_and_open]:
            save_output = True
    else:
        bv.show_html_report(title, report_html, plaintext=report_plaintext)

    target_dir, target_filename = os.path.split(bv.file.filename)
    html_file = os.path.join(target_dir, 'coverage-report-%s.html' % target_filename)
    if save_output:
        with open(html_file, 'w') as f:
            f.write(report_html)
            log_info("[*] Saved HTML report to %s" % html_file)
    if choice == save_file:
        interaction.show_message_box("Report Saved",
                                     "Saved HTML report to: %s" % html_file,
                                     enums.MessageBoxButtonSet.OKButtonSet,
                                     enums.MessageBoxIcon.InformationIcon)
    if choice == save_and_open:
        open_new_browser_tab("file://" + html_file)


def show_high_complexity_report(bv, min_complexity=20, save_output=False):
    """Show a report of just high-complexity functions"""

    def complexity_filter(cur_func_start, cur_func_stats):
        if cur_func_stats.complexity >= min_complexity:
            return True
        else:
            return False

    show_coverage_report(bv, save_output, complexity_filter, 'High Complexity Coverage Report')


def show_nontrivial_report(bv, save_output=False):
    """Demonstrate a coverage report filtered using BN's analysis"""

    def triviality_filter(cur_func_start, cur_func_stats):
        cur_function = bv.get_function_at(cur_func_start)

        trivial_block_count = 4
        trivial_instruction_count = 16
        blocks_seen = 0
        instructions_seen = 0
        for block in cur_function.basic_blocks:
            blocks_seen += 1
            instructions_seen += block.instruction_count
            if blocks_seen > trivial_block_count:
                return True
            if instructions_seen > trivial_instruction_count:
                return True
        return False

    show_coverage_report(bv, save_output, triviality_filter, 'Nontrivial Coverage Report')


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

PluginCommand.register("bncov\\Reports\\Show Coverage Report",
                       "Show a report of function coverage",
                       show_coverage_report)
PluginCommand.register("bncov\\Reports\\Show High-Complexity Function Report",
                       "Show a report of high-complexity function coverage",
                       show_high_complexity_report)
PluginCommand.register("bncov\\Reports\\Show Non-Trivial Function Report",
                       "Show a report of non-trivial function coverage",
                       show_nontrivial_report)
