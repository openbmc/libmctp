# Fuzzing libmctp

## Build

From the top level libmctp directory, run `./tests/fuzz/fuzz-build.py`. That
will produce several build variants required for different fuzz engines/stages.

## Honggfuzz

[Honggfuzz](https://github.com/google/honggfuzz) handles running across multiple
threads itself with a single corpus directory, which is easy to work with. It
needs to be built from source.

Run with

```
nice honggfuzz -T -i corpusdir --linux_perf_branch -- ./bhf/tests/fuzz/i2c-fuzz
```

The `--linux_perf_branch` switch is optional, it requires permissions for perf
counters:

```
echo 0 | sudo tee /proc/sys/kernel/perf_event_paranoid
```

Optionally a thread count can be given, 24 threads on a 12 core system seems to
give best utilisation (`--threads 24`).

The corpus directory can be reused between runs with different fuzzers.

## AFL++

Running a single instance (just for testing):

```
afl-fuzz -i fuzzrun/hf11/ -o fuzzrun/out12single ./bfuzz/tests/fuzz/i2c-fuzz
```

AFL++ requires a separate TUI instantiation for each CPU thread. The helper
[AFL Runner](https://github.com/0xricksanchez/afl_runner) makes that easier.

Running with 20 threads:

```
nice aflr run  -t bfuzz/tests/fuzz/i2c-fuzz -i workdir/out5/m_i2c-fuzz/queue -o workdir/out6 -c bcmplog/tests/fuzz/i2c-fuzz -s bfuzzasan/tests/fuzz/i2c-fuzz -n 20  --session-name fuzz
```

Kill it with `aflr kill fuzz`.

`aflr tui workdir/out6` could be used to view progress, though its calculations
may be inaccurate if some runners are idle. Another option is
`afl-whatsup workdir/out6`.

## Coverage

The coverage provided by a corpus directory can be reported using
`tests/fuzz/fuzz-coverage.py`.

It will:

- Run a binary compiled with `--coverage` against each corpus file
- Use [grcov](https://github.com/mozilla/grcov) to aggregate the coverage traces
  (much faster than lcov).
- Use `genhtml` to create a report

Typical usage, with corpus in `fuzzrun/corpus`:

```
./tests/fuzz/fuzz-coverage.py fuzzrun/corpus bnoopt/tests/fuzz/i2c-fuzz . bnoopt/ coverage-output
```

## Reproducing crashes

When the fuzz run encounters a crash, the testcase can be run against the built
target manually, and stepped through with GDB etc.

```
./bnoopt/tests/fuzz/i2c-fuzz < crashing.bin
```
