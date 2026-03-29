#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: scripts/test-bindings-dedup.sh [go|swift|all]

Runs focused deduplication regression checks for language bindings.

  go     Run Go dedup helper tests only
  swift  Run Swift dedup helper tests only
  all    Run both Go and Swift checks (default)
EOF
}

run_go() {
  echo "[go] Running dedup helper tests"
  (
    cd "$repo_root/bindings/go"
    go test ./... -run 'TestDeduplicateInPlace_LastWins|TestDeduplicated_DoesNotMutateOriginal|TestDiffAndScoreDeduplicatedHelpers'
  )
}

run_swift() {
  echo "[swift] Running dedup helper tests"
  (
    cd "$repo_root/bindings/swift"
    swift test --filter dedup
  )
}

target="${1:-all}"

case "$target" in
  go)
    run_go
    ;;
  swift)
    run_swift
    ;;
  all)
    run_go
    run_swift
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    echo "Unknown target: $target" >&2
    usage >&2
    exit 2
    ;;
esac
