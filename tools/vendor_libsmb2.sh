#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /path/to/libsmb2"
  exit 2
fi

src="$(cd "$1" && pwd)"
project_root="$(cd "$(dirname "$0")/.." && pwd)"
dst="${project_root}/components/libsmb2_port/vendor/libsmb2"

required=(
  "CMakeLists.txt"
  "COPYING"
  "LICENCE-LGPL-2.1.txt"
  "include/smb2/libsmb2.h"
  "include/smb2/libsmb2-raw.h"
  "lib"
)

for item in "${required[@]}"; do
  if [[ ! -e "${src}/${item}" ]]; then
    echo "ERROR: '${src}' does not look like a complete libsmb2 source tree."
    echo "Missing: ${item}"
    exit 1
  fi
done

rm -rf "${dst}"
mkdir -p "$(dirname "${dst}")"

#— Copy the complete upstream source tree rather than guessing which protocol
#— source files are safe to remove. Flash/RAM optimization comes only after a
#— verified ESP32 server build.
cp -R "${src}" "${dst}"

rm -rf "${dst}/.git" "${dst}/build" "${dst}/dist"

revision_file="${project_root}/components/libsmb2_port/UPSTREAM_REVISION.txt"
{
  echo "Upstream: https://github.com/sahlberg/libsmb2"
  if git -C "${src}" rev-parse HEAD >/dev/null 2>&1; then
    echo "Commit: $(git -C "${src}" rev-parse HEAD)"
    echo "Describe: $(git -C "${src}" describe --always --dirty --tags 2>/dev/null || true)"
  else
    echo "Commit: UNKNOWN - source was imported without Git metadata"
  fi
  echo "Imported: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} > "${revision_file}"

echo "Vendored libsmb2 into:"
echo "  ${dst}"
echo
cat "${revision_file}"
