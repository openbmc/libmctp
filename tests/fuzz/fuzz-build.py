#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# Builds fuzzing variants. Run this from the toplevel directory.
# Beware this will wipe build directories.

# Requires honggfuzz and afl++ installed

# Builds are:
# * AFL (normal, asan, cmplog)
# * honggfuzz (asan, msan, ubsan)
# * -O0, with coverage

import os
import subprocess

# reduce warning level since tests since gtest is noisy
BASE_MESONFLAGS = "-Dwarning_level=2 -Ddefault_library=static --wipe".split()
FUZZ_PROGRAMS = ["tests/fuzz/i2c-fuzz"]


def build(
    build_dir: str,
    cc: str = None,
    cxx: str = None,
    cflags="",
    cxxflags="",
    opt="3",
    env={},
    mesonflags=[],
):
    env = os.environ | env
    env["CFLAGS"] = cflags
    env["CXXFLAGS"] = cxxflags

    # Meson sets CC="ccache cc" by default, but ccache removes -fprofile-arcs
    # so coverage breaks (ccache #1531). Prevent that by setting CC/CXX.
    env["CC"] = cc if cc else "cc"
    env["CXX"] = cxx if cxx else "c++"

    meson_cmd = ["meson"] + BASE_MESONFLAGS + mesonflags
    meson_cmd += [f"-Doptimization={opt}"]
    meson_cmd += [build_dir]
    subprocess.run(meson_cmd, env=env, check=True)

    ninja_cmd = ["ninja", "-C", build_dir] + FUZZ_PROGRAMS
    subprocess.run(ninja_cmd, env=env, check=True)


def build_afl():
    env = {
        # seems to be required for afl-clang-lto?
        "AFL_REAL_LD": "ld.lld",
    }
    cc = "afl-clang-lto"
    cxx = "afl-clang-lto++"

    # normal
    build("bfuzz", cc=cc, cxx=cxx, env=env)
    # ASAN
    build(
        "bfuzzasan",
        cc=cc,
        cxx=cxx,
        mesonflags=["-Db_sanitize=address"],
        env=env,
    )
    # cmplog
    build("bcmplog", cc=cc, cxx=cxx, env={"AFL_LLVM_CMPLOG": "1"} | env)


def main():
    # No profiling, has coverage
    build(
        "bnoopt",
        cflags="-fprofile-abs-path",
        cxxflags="-fprofile-abs-path",
        opt="0",
        mesonflags=["-Db_coverage=true"],
    )

    # AFL
    build_afl()

    # Honggfuzz
    # asan by default
    build(
        "bhf",
        cc="hfuzz-clang",
        cxx="hfuzz-clang++",
        env={"HFUZZ_CC_ASAN": "1"},
    )
    # msan
    build(
        "bhf-msan",
        cc="hfuzz-clang",
        cxx="hfuzz-clang++",
        env={"HFUZZ_CC_MSAN": "1"},
    )
    # ubsan
    build(
        "bhf-ubsan",
        cc="hfuzz-clang",
        cxx="hfuzz-clang++",
        env={"HFUZZ_CC_UBSAN": "1"},
    )


if __name__ == "__main__":
    main()
