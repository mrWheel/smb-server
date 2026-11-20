<!--
smb-server - change log of the smb_server component
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

- Always-grant `SMB2_LOCK` (0x0a): byte-range lock requests are answered
  with a header-only `STATUS_SUCCESS` (Samba `locking = off` style)
  instead of `STATUS_NOT_SUPPORTED`, which stricter SMB2 clients treat
  as fatal.
- Added framing-desync diagnostics to the client receive loop: hex dump
  of the buffer front on an oversized announced NetBIOS frame, a WARN
  when a frame carries a non-`0x00` NetBIOS type byte, and a
  once-per-3 s WARN when a partial frame stops making progress. (Open
  issue: a mid-WRITE-stream desync was observed where the announced
  frame length disagrees with the bytes actually sent.)

- Fixed a forced disconnect during file uploads: the Negotiate response
  advertises `max_write_size` of 64 KB, and a client honouring it sends
  WRITE requests in a single NetBIOS frame far larger than the client
  handler's fixed 8 KB receive buffer; the receive loop now reads the
  announced NetBIOS frame length and grows the request buffer on demand
  (capped at the advertised IO size plus headroom) instead of
  disconnecting with `NetBIOS frame exceeds buffer size`.
- Moved the example app's `esp_log_level_set("smb_protocol", ...)` call
  from file scope (not valid C; broke the build) into `app_main()` right
  before `smb_server_start()`.

## 0.3.0

- Added the standard GPL-3.0 copyright/license header to every `.c`, `.h`
  and `.md` file (Copyright (C) 2026 Willem Aandewiel (mrWheel)).
- `LICENSE` header now names the copyright holder.
- Removed development-tool directories from the example tree; the manifest
  no longer needs packaging filters for them.
- Verified all four declared targets (esp32, esp32s2, esp32s3, esp32c3) and
  the self-contained example from the packed component archive.

## 0.2.0

- Custom SMB2/SMB3 protocol implementation (no external SMB stack dependency).
- Negotiate (SMB 2.0.2 - 3.0.2 selection, SMB1 negotiate bridge only),
  Session Setup (guest), Tree Connect/Disconnect (disk share and `IPC$`).
- File operations: Create/Close, Read/Write, Query Info (file and volume
  size), Set Info (end-of-file, delete-on-close, basic-info acknowledgement),
  Query Directory, Flush, Echo, Logoff.
- DCE/RPC `srvsvc`/`NetrShareEnum` over `IPC$` for share browsing.
- `CHANGE_NOTIFY` with create/delete notifications (documented deviations)
  and `CANCEL` support.
- Compound-request handling, per-connection tree table and per-owner handle
  release for concurrent clients.
- Component packaging metadata: `idf_component.yml`, `Kconfig`, GPL-3.0
  license text, component README and self-contained basic example.

## 0.1.0 - development

- Initial `smb_server` component structure.
- Added ESP-IDF public API and Kconfig.
- Added bounded server state and FreeRTOS task.
- Added safe SMB path normalization and traversal prevention.
- Added ESP-IDF VFS/POSIX helpers.
- Added bounded session/file-handle table.
- Added guest access configuration and SMB2/SMB3 negotiation setup.
- Added LittleFS/WiFi/mDNS basic example.
