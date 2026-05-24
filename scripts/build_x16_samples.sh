#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)

exec "$ROOT/x16_samples/build_matrix.sh" "$@"
