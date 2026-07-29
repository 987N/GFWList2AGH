#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python_bin="${PYTHON:-python3}"

exec "${python_bin}" "${script_dir}/scripts/build_rules.py" \
    --manifest "${script_dir}/data/sources.json" \
    --modify "${script_dir}/data/data_modify.txt" \
    "$@"
