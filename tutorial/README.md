# bncov Usage Tutorial

In this example we'll compile the target program, fuzz it, and watch
coverage roll in with Binary Ninja.  This is the simplest example and
won't coverage much in the way of scripting (which you should definitely
explore later in the `scripts` directory).

If you're so excited to try out bncov that you can't wait any longer, we've
also included the sample binary with seeds and coverage traces in the
[example folder](example/).

## Compiling the Target

The first thing we have to do is compile our target, which is a simple
C program designed to illustrate how a coverage-guided fuzzer like
AFL can discover new blocks pretty quickly.  Let's start with a
shell in the current `tutorial` directory.

Normal compilation of the target:

```bash
gcc fuzztest.c -o fuzztest
```

In order to use AFL for our example, we also need to compile an
instrumented version of our target by using afl-gcc instead.
[Download here](http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz)
if you don't already have it installed.

Instrumented compilation of the target:

```bash
afl-gcc fuzztest.c -o fuzztest-instrumented
```

## Running the Target

We can run the target and confirm that it works:

```bash
echo "Does nothing" > seed.txt && ./fuzztest seed.txt
echo "FuzzTest" > crash.txt && ./fuzztest crash.txt
```

Fuzzing the target isn't much more work, especially if you're
familiar with AFL:

```bash
mkdir seeds && echo "AAAAAAAA" > seeds/original.txt
afl-fuzz -i seeds -o output -- ./fuzztest-instrumented @@
```

That should eventually find its way all the way down to the crash,
but wouldn't it be great if we could watch the fuzzer make progress
in real-time?  You can leave the fuzzer running, or stop it and remove
the `output` directory and restart it later.

## Getting Coverage

If you haven't downloaded DynamoRIO, now would be a great time!
[DynamoRIO binary package download Link](https://github.com/DynamoRIO/dynamorio/wiki/Downloads).

In a new terminal, you'll need to tell the coverage script where to
find the DynamoRIO binaries, which you can do by changing a variable in
the script or by setting an environment variable like so:

```bash
DYNAMORIO=/mnt/hgfs/vmshare/dr ../dr_block_coverage.py output/queue/ output/coverage --continuously_monitor -- ./fuzztest @@
```

You should change the command above so that DYNAMORIO points to the directory
you extracted DynamoRIO to.  The other parts of the command specify where
to look for seeds that the fuzzer generates, where to write the coverage
files to (if omitted, the script bases it off the seed directory name), and an
optional switch saying that you want the script to continuously poll for new
inputs as the fuzzer runs.

The last thing to note is that we used the *NON-instrumented* version of
the binary.  You should be able to use either, but in general I recommend
using the non-instrumented version for all analysis tasks since the
disassembly is a little cleaner to look at.

You should see that the script is collecting coverage information and storing
coverage files in the coverage output directory and naming them after the seed
that was run.  These coverage files are referred to as a "trace" or "trace
file" throughout this codebase.  Now that we have these traces, let's
visualize them!

## Visualizing Coverage

If somehow you've gotten this far and not installed the plugin in Binary Ninja,
go ahead and do that now ([Read more about that here](https://docs.binary.ninja/guide/plugins/index.html#using-plugins)).

Then open up Binary Ninja and open the non-instrumented target we made earlier.
You should be able to right-click and see near
the bottom of the context menu a `bncov` submenu, where you'll want to select
`bncov -> Coverage Data -> Import Directory and Watch` because we want to both
import all of the existing coverage files as well as monitor for new coverage
files that appear (which will happen as long as both the fuzzer and the drcov 
script are running).  Navigate to the coverage output directory we specified
earlier (`output/coverage` if you've been following along).

You'll want to navigate to the function of interest, which you can quickly do
by hitting `g` and typing `main` to jump to the function by name.  At this point,
depending on how long the fuzzer has been running and how fast/lucky it is,
you'll either see most of or some portion of the function of interest covered,
which is indicated by blocks being colored blue, red, or some color in-between.

If you don't see that, double check any error messages that may have appeared
in the log.  Common mistakes include picking the wrong directory (we want the
coverage file directory, not the seed directory), having the wrong binary open
in binary ninja (double check the coverage script invocation), or the coverage
directory could be empty if the fuzzer or coverage script had an error, so make
sure those are up and running correctly.

## Coverage Rarity

The coloring indicates the relative rarity of coverage, where a pure blue block
indicates that every coverage file (or trace) covered that block (which is to say
that during execution, the seed corresponding to that trace caused the program
to execute that specific basic block of code).  A pure red block would mean that
only one trace covered that block, and purple coloring means that some but not
all traces cover it.

If we look at the target function and see a gradual descent from blue to red,
it makes sense intuitively based on how AFL works and how this code is structured
that the further into the nested if-statements we go, the rarer coverage is
(since AFL primarily only saves seeds it thinks have new/better edge coverage).

## Scripting

While it's interesting to watch the fuzzer discover new blocks in real-time
(if you haven't that done yet, you can delete the whole `output` directory
we made, restart the fuzzer and the coverage script, and either restart
Binary Ninja or do `bncov -> Coverage Data -> Reset Coverage State`,
followed by `bncov -> Coverage Data -> Import Directory and Watch` again to
watch it happen), the other advantage is that we can now ask interesting
questions about the coverage represented by the seeds generated by the fuzzer,
and using Binary Ninja we can reason about the program we are analyzing.

For example, we can ask the coverage plugin what blocks were only covered
by ten or fewer traces, and what functions those blocks are in by going
to the python console and typing:

```python
import bncov
rare_blocks = bncov.covdb.get_rare_blocks(10)
for block in rare_blocks:
    print("0x%x %s" % (block, bv.get_functions_containing(block)[0].name))
```

Or you can identify which traces are hitting blocks of interest (like the
one right above the call to `abort()` in the function `main`) by clicking
the address of interest and typing in the python console:

```python
bncov.covdb.get_traces_from_block(here)
```

Using this information, you can use python's built-in set operations
to reason about the difference in coverage between traces like this:

```python
hit = '/Users/user/vmshare/bncov/tutorial/output/coverage/id&%000040,src&%000034,op&%havoc,rep&%4.cov'
miss = '/Users/user/vmshare/bncov/tutorial/output/coverage/id&%000029,src&%000021,op&%havoc,rep&%16.cov'
bncov.covdb.trace_dict[hit] - bncov.covdb.trace_dict[miss]
# output: set([2336L, 2366L, 2351L])
```

If you wanted to minimize the number of seeds and coverage files to
only those with unique block coverage, that too is straightforward:

```python
uniq_traces = {}
for cur_trace, cur_coverage in bncov.covdb.trace_dict.items():
    cur_coverage = set(cur_coverage)
    if cur_coverage not in uniq_traces.values():
        uniq_traces[cur_trace] = cur_coverage
#print("%d unique among %d" % (len(uniq_traces), len(bncov.covdb.trace_dict)))
```

The bncov plugin can be used to write arbitrary analysis scripts, and it can
also be used without the GUI if your Binary Ninja license allows for headless
scripting.  You can also make your own reports within Binary Ninja like the
built-in `bncov -> Reports -> Generate Coverage Report` demonstrates.
Happy hunting!
