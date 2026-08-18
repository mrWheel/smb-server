#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
vendor="${root}/components/libsmb2_port/vendor/libsmb2"
revision="${root}/components/libsmb2_port/UPSTREAM_REVISION.txt"

if [[ ! -f "${vendor}/LICENCE-LGPL-2.1.txt" ]]; then
  echo "ERROR: vendored libsmb2 source/license is missing."
  echo "Run tools/vendor_libsmb2.sh first."
  exit 1
fi

if grep -RIn --include='idf_component.yml' -E '^[[:space:]]+git:' "${root}/components"; then
  echo "ERROR: a component manifest still contains a Git dependency."
  exit 1
fi

if grep -q 'NOT YET IMPORTED\|UNKNOWN' "${revision}"; then
  echo "ERROR: exact upstream libsmb2 revision has not been recorded."
  exit 1
fi

echo "Local component dependency structure looks Registry-ready."
echo "Still required before release: clean build, interoperability tests,"
echo "resource measurements, license review and component pack validation."
