#!/usr/bin/env bash
#
# mayhem/build.sh — build libnpy's fuzz harness + test suite.
#
# libnpy is a header-only C++ library (include/npy.hpp). This builds:
#   1) the libFuzzer harness (sanitized, DWARF-3)      -> /mayhem/fuzz_parse_header
#   2) a standalone run-once reproducer per harness    -> /mayhem/fuzz_parse_header-standalone
#   3) the upstream test suite with NORMAL flags       -> /mayhem/test-read, /mayhem/test-write
#      (catch2 v2 single header vendored at mayhem/vendor/catch2/catch.hpp;
#       test data pre-generated at mayhem/testdata/ — no network, no numpy needed)
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

CXXSTD="-std=c++14"
INCLUDES="-I$SRC/include -I$SRC/mayhem"

# 1) libFuzzer harness (sanitized + instrumented; header-only lib so the fuzzed
#    code compiles into the harness translation unit and is fully instrumented).
$CXX $CXXSTD $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$SRC/mayhem/fuzz_parse_header.cpp" $INCLUDES \
    -o "$SRC/fuzz_parse_header"

# 2) Standalone (non-fuzzer) run-once reproducer. Compile the driver as a C
#    object first so its LLVMFuzzerTestOneInput reference keeps C linkage.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CXX $CXXSTD $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$SRC/mayhem/fuzz_parse_header.cpp" /tmp/standalone_main.o $INCLUDES \
    -o "$SRC/fuzz_parse_header-standalone"

# 3) Upstream test suite, NORMAL flags (clean build, no sanitizers) so test.sh
#    only has to RUN it. Test data ships pre-generated in mayhem/testdata/.
$CXX $CXXSTD -O2 $COVERAGE_FLAGS -I"$SRC/include" -I"$SRC/mayhem/vendor" \
    "$SRC/tests/test-read.cpp" -o "$SRC/test-read"
$CXX $CXXSTD -O2 $COVERAGE_FLAGS -I"$SRC/include" \
    "$SRC/tests/test-write.cpp" -o "$SRC/test-write"
