<!--
smb-server - change log of the smb-server repository
Copyright (C) 2026 Willem Aandewiel (mrWheel)
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
-->

# Changelog

fileVersion: [2] - 20-11-2026 - 11:18

## Unreleased

- `smb_server`: fixed a forced disconnect during file uploads — the
  receive loop now grows the per-connection request buffer to the
  announced NetBIOS frame size (clients send up to the advertised
  64 KB `max_write_size` WRITE requests in one frame) instead of
  disconnecting with `NetBIOS frame exceeds buffer size`.
- `smb_server`: always-grant `SMB2_LOCK` (0x0a) with a header-only
  success response instead of `STATUS_NOT_SUPPORTED`.
- `smb_server`: added framing-desync diagnostics (hex dump of the
  offending frame on oversized/ill-typed NetBIOS frames and on stalled
  partial frames); a mid-WRITE-stream desync is currently open and
  awaiting a retest log.
- Example app: the verbosity tweak is a `__attribute__((constructor))`
  that silences `smb_protocol`/`smb_packet` before `app_main()` (bare
  `esp_log_level_set` calls at file scope do not compile).

## 0.3.0

- Restored a buildable application at the repository root (root
  `CMakeLists.txt`, `main/` and symlinked example configuration) so
  `idf.py build`/`flash` from the checkout builds the basic example, the same
  layout as the ringFileStore repository; the example inside the component
  remains the single source.
- Added the standard GPL-3.0 copyright/license header to every `.c`, `.h`
  and `.md` file (Copyright (C) 2026 Willem Aandewiel (mrWheel)).
- Removed the development-tool directory from the example tree.
- Component manifest version set to 0.3.0.

## 0.2.0

- Custom in-house SMB2/SMB3 server implementation in `components/smb_server`
  (an early `libsmb2_port` vendoring experiment was abandoned before release
  and removed; the component never shipped with libsmb2).
- Removed `tools/vendor_libsmb2.sh`, `tools/check_registry_ready.sh`, the
  unused root project build entry point and the root-only partition table /
  `flash_data/` folder.
- Reorganized the repository for ESP Component Registry publication: the
  example moved to `components/smb_server/examples/basic` and became
  self-contained (own manifest, partition table and LittleFS assets).
- Kept WiFi provisioning, mDNS and filesystem mounting in the example,
  outside the reusable `smb_server` component.

## 0.1.0

- Initial project scaffold.
