#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# usage: fuzz-coverage.py [-h] corpus program srcdir builddir outdir

# Runs corpus (directory of testcases) against a program
# built with coverage, and produces a html report.

# The program should be built with --coverage -fprofile-abs-path
# -O0 may make the html report more legible?

# Requires lcov and https://github.com/mozilla/grcov

import argparse
import subprocess
import sys
from pathlib import Path


def run(args):
    corpus = Path(args.corpus)
    outdir = Path(args.outdir)

    for c in Path(args.builddir).glob("**/*.gcda"):
        print(f"Removed old coverage {c}", file=sys.stderr)
        c.unlink()

    print("Running corpus", file=sys.stderr)
    for c in corpus.glob("*"):
        c = c.open("rb").read()
        subprocess.run([args.program], input=c)

    print("Running grcov", file=sys.stderr)
    outdir.mkdir(parents=True, exist_ok=True)
    coverage_paths = [args.builddir]
    lcov_file = outdir / "lcov.info"

    subprocess.run(
        [
            "grcov",
            "-b",
            args.program,
            "-o",
            lcov_file,
            "-t",
            "lcov",
            "-s",
            args.srcdir,
        ]
        + coverage_paths,
        check=True,
    )

    print("Running genhtml", file=sys.stderr)
    subprocess.run(
        [
            "genhtml",
            "-o",
            outdir,
            "--show-details",
            "--highlight",
            "--ignore-errors",
            "source",
            "--ignore-errors",
            "unmapped",
            "--legend",
            lcov_file,
        ],
        check=True,
    )

    html = outdir / "index.html"
    print(f"\n\nOutput is file://{html.absolute()}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=str, help="Corpus directory")
    parser.add_argument("program", type=str, help="Target Program")
    parser.add_argument("srcdir", type=str, help="Source directory")
    parser.add_argument("builddir", type=str)
    parser.add_argument("outdir", type=str)
    args = parser.parse_args()

    run(args)


if __name__ == "__main__":
    main()
