#!/usr/bin/env bash
#
# mayhem/test.sh — RUN libnpy's own test suite (built by mayhem/build.sh):
#   * /mayhem/test-read  — upstream catch2 suite: known-answer reads of pre-generated
#     .npy files (asserts shapes, values, fortran_order).
#   * /mayhem/test-write — upstream writer; its outputs are byte-compared against
#     committed golden .npy files (golden-output diff).
# Emits a CTRF summary; exits non-zero iff any test failed.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

for bin in test-read test-write; do
  if [ ! -x "$SRC/$bin" ]; then
    echo "FATAL: $SRC/$bin missing — mayhem/build.sh should have built it" >&2
    emit_ctrf "catch2" 0 1
    exit 1
  fi
done

passed=0; failed=0

# Run from a writable scratch dir; the tests read/write ./data/.
WORK="$(mktemp -d)"
cp -r "$SRC/mayhem/testdata/data" "$WORK/data"
cd "$WORK"

# 1) test-read: catch2 known-answer suite. Parse the catch2 summary.
read_out="$("$SRC/test-read" 2>&1)" ; read_rc=$?
echo "$read_out"
if [ $read_rc -eq 0 ] && grep -qE 'All tests passed \([0-9]+ assertions in [0-9]+ test case' <<<"$read_out"; then
  n="$(grep -oE 'in [0-9]+ test case' <<<"$read_out" | grep -oE '[0-9]+')"
  passed=$(( passed + n ))
else
  # "test cases: T | P passed | F failed" on failure; anything unparsable = failure.
  p="$(grep -oE '[0-9]+ passed' <<<"$read_out" | grep -oE '[0-9]+' | head -1 || true)"
  f="$(grep -oE '[0-9]+ failed' <<<"$read_out" | grep -oE '[0-9]+' | head -1 || true)"
  passed=$(( passed + ${p:-0} ))
  failed=$(( failed + ${f:-1} ))
fi

# 2) test-write: run the writer, then golden-diff every output against the
#    committed reference .npy files (behavioral: bytes must match exactly).
"$SRC/test-write" ; write_rc=$?
for g in "$SRC"/mayhem/testdata/golden/*.npy; do
  name="$(basename "$g")"
  if [ $write_rc -eq 0 ] && cmp -s "$g" "data/$name"; then
    passed=$(( passed + 1 ))
  else
    echo "GOLDEN MISMATCH: $name" >&2
    failed=$(( failed + 1 ))
  fi
done

cd "$SRC"
emit_ctrf "catch2" "$passed" "$failed"
