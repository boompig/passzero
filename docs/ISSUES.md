# Problems and how to fix them

Over the years PassZero has had a number of issues. Here are some helpful go-tos.

## Memory Usage / Profiling

Problem: PassZero runs out of memory.

Solution: Use `memray` to look at memory allocations with a flamegraph.

Then can fix. Often this has to do with older libraries that have memory leaks, and identifying the library and bumping the version is enough to fix the issue most of the time.

Another good solution for heavyweight imports is function-level importing, combined with occassional cycling of workers in `gunicorn`.
