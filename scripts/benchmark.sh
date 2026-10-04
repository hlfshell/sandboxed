#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Put BENCH_TMPDIR on the filesystem you want to measure.
export GOCACHE="${GOCACHE:-/tmp/sandboxed-go-cache}"
export TMPDIR="${BENCH_TMPDIR:-${TMPDIR:-/tmp}}"
mkdir -p "$GOCACHE" "$TMPDIR"
output="${1:-benchmark-results/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$output"
{
 date -u
 go version
 git rev-parse HEAD
 git status --short
 uname -a
 if command -v lscpu >/dev/null; then lscpu; fi
 df -T "$TMPDIR"
 printf 'BENCH=%s\nBENCHTIME=%s\nCOUNT=%s\nCPU=%s\nTMPDIR=%s\n' \
  "${BENCH:-Benchmark(Suite|Sparse|LookupScaling|RandomWriteBatch|PartialWrite|DurableSmallWrites|WAL)}" "${BENCHTIME:-1s}" "${COUNT:-5}" "${CPU:-1,4}" "$TMPDIR"
} > "$output/environment.txt"
go test ./... -count=1 2>&1 | tee "$output/tests.txt"
go test ./... -race -count=1 2>&1 | tee "$output/race.txt"
go test -run '^$' -bench "${BENCH:-Benchmark(Suite|Sparse|LookupScaling|RandomWriteBatch|PartialWrite|DurableSmallWrites|WAL)}" -benchmem \
 -benchtime "${BENCHTIME:-1s}" -count "${COUNT:-5}" -cpu "${CPU:-1,4}" \
 -timeout "${TIMEOUT:-60m}" 2>&1 | tee "$output/bench.txt"
printf 'Results: %s\n' "$output"
