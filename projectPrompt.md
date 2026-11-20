<!--
projectPrompt.md - change log of the smb-server projectPrompt
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
fileVersion: [3] - 20-11-2026 - 11:43

# SMB Server — ESP32 Custom Implementation

# Project Prompt — `smb_server`

## Goal

Build a **minimal, production-quality SMB2/SMB3 server component** for ESP32 that exposes an already-mounted ESP-IDF VFS filesystem as an SMB2/SMB3 network share.

The component must work reliably with:
- macOS Finder, `smbutil` and `mount_smbfs`
- Windows File Explorer
- Linux `mount -t cifs`
- iOS/iPadOS SMB clients (FileBrowser, Files, "Filer")

The final result must be structured and reusable so that the `smb_server` component can be published in the Espressif Component Registry.

## Architecture Decision: Custom SMB2 Implementation

**CRITICAL:** Do NOT use libsmb2 (upstream or Espressif registry).

**Reason:** libsmb2 is a client library. Its server-side callbacks are incomplete stubs. Specifically:
- IOCTL output buffers are not serialized into SMB2 response packets
- DCE/RPC pipe operations (srvsvc) cannot be properly implemented
- Attempting workarounds wastes development time without resolution

**Solution:** Implement a minimal, focused SMB2 protocol handler directly in the `smb_server` component.

**References:** Don't guess but check "/protocolReferences.md". It contains the
authoritative MS-SRVS / MS-RPCE references, the Samba srvsvc IDL pointers, and the
hardware-observed wire facts (SMB1 preamble bridge, raw NTLMSSP flow, BIND/BIND_ACK
sizes, `FSCTL_PIPE_TRANSCEIVE` code, `opnum 0x000f`). Never change NetrShareEnum
byte layouts from memory: derive them from MS-SRVS plus Samba's `srvsvc.idl`, then
validate the exact bytes on hardware.

## Repository Layout

```
smb-server/
├── CMakeLists.txt            # root demo app: project(smb_server_basic)
├── main/                     # root entry point, #includes the example main.c
│   ├── main.c
│   └── idf_component.yml     # demo deps: wifi-provisioner, mdns, littlefs
├── partitions.csv            # symlink → examples/basic/partitions.csv
├── sdkconfig.defaults        # symlink → examples/basic/sdkconfig.defaults
├── protocolReferences.md     # normative protocol references + wire facts
├── README.md / PUBLISHING.md / CHANGELOG.md
└── components/smb_server/
    ├── CMakeLists.txt        # idf_component_register (see Build wiring)
    ├── Kconfig               # SMB_SERVER_* options (see Configuration)
    ├── idf_component.yml     # version 0.3.0, GPL-3.0-or-later, idf >=6.0
    ├── LICENSE / README.md / CHANGELOG.md
    ├── include/
    │   ├── smb_server.h      # public API only
    │   └── smb_packet.h      # wire structs, constants, codec API
    ├── src/
    │   ├── smb_internal.h    # shared internal types (handle table, VFS/path API)
    │   ├── smb_server.c      # lifecycle, config validation, server task
    │   ├── smb_protocol.c    # listener, per-client task, all command handlers
    │   ├── smb_packet.c      # little-endian codec, header parse/build
    │   ├── smb_path.c        # UTF-16LE→UTF-8, path resolve/containment
    │   ├── smb_vfs.c         # thin POSIX/VFS wrapper (open/pread/pwrite/stat/…)
    │   └── smb_session.c     # global file/dir/pipe handle table
    └── examples/basic/       # self-contained demo (WiFi prov, mDNS, LittleFS)
```

The root build and the component example share one `main.c` (the root `main/`
includes the example file); `littlefs_assets/` is baked into the `littlefs`
partition at build time. The component itself stays publishable and independent.

## Public API (`include/smb_server.h`)

```c
typedef struct
{
  const char *share_name;    // 1..31 characters, e.g. "ESP32"
  const char *mount_point;   // absolute VFS path, e.g. "/littlefs"
  bool read_only;
  size_t max_clients;        // 1..4
  uint16_t port;             // 445 by default
} smb_server_config_t;

#define SMB_SERVER_DEFAULT_CONFIG() { /* from Kconfig; mount_point = NULL */ }

esp_err_t smb_server_start(const smb_server_config_t *config);
esp_err_t smb_server_stop(void);
bool smb_server_is_running(void);
esp_err_t smb_server_get_config(smb_server_config_t *config);
```

`smb_server_start()` validates: non-NULL config; non-empty `share_name` < 32
chars; absolute `mount_point` < 128 chars that `stat()` resolves to a directory;
`max_clients` 1..4; `port` != 0; returns `ESP_ERR_INVALID_STATE` when already
running, `ESP_ERR_NO_MEM` when the task cannot be created. It copies the config
into a global state struct and creates the server task
(`CONFIG_SMB_SERVER_TASK_STACK_SIZE` / `CONFIG_SMB_SERVER_TASK_PRIORITY`).
`smb_server_stop()` sets the stop flag, closes the listen socket and lets the
loop exit (graceful; client tasks end when their sockets close).

## Configuration (Kconfig)

| Option | Default | Purpose |
|---|---|---|
| `SMB_SERVER_DEFAULT_SHARE_NAME` | `ESP32` | Share name for `SMB_SERVER_DEFAULT_CONFIG()` |
| `SMB_SERVER_MAX_CLIENTS` | 1 (range 1-4) | Advertised simultaneous clients |
| `SMB_SERVER_TASK_STACK_SIZE` | 12288 | Server/listener task stack |
| `SMB_SERVER_TASK_PRIORITY` | 5 | Server task priority |
| `SMB_SERVER_PORT` | 445 | TCP listen port |
| `SMB_SERVER_VERBOSE_LOGGING` | n | Verbose protocol logging |

## Build wiring (`components/smb_server/CMakeLists.txt`)

```cmake
idf_component_register(
  SRCS src/smb_server.c src/smb_protocol.c src/smb_packet.c
       src/smb_path.c src/smb_vfs.c src/smb_session.c
  INCLUDE_DIRS "include"
  PRIV_INCLUDE_DIRS "src"
  REQUIRES esp_common
  PRIV_REQUIRES freertos log heap lwip vfs
)
```

Compile warnings: `-Wall -Wextra -Werror=return-type`. Public header depends only
on `esp_err.h`/std C headers so the public surface stays minimal.
`idf_component.yml`: version `0.3.0`, license `GPL-3.0-or-later`, targets
`esp32`, `esp32s2`, `esp32s3`, `esp32c3`, `idf >= 6.0`.

## Scope: Minimal SMB2 Server

### Core SMB2 Commands (command code = SMB2 header `Command` field)

1. **NEGOTIATE (0x00)** — dialect selection (SMB 2.0.2, 2.1, 3.0, 3.0.2; no 3.1.1)
2. **SESSION_SETUP (0x01)** — guest-only, two-leg NTLMSSP handshake (no crypto)
3. **LOGOFF (0x02)** — header-only success; frees this connection's handles/watches
4. **TREE_CONNECT (0x03)** — disk share or `IPC$` (srvsvc pipe)
5. **TREE_DISCONNECT (0x04)** — frees tree slot + this connection's handles/watches
6. **CREATE (0x05)** — open/create files, directories, `srvsvc` pipes; MxAc context
7. **CLOSE (0x06)** — close handle, honour delete-pending
8. **FLUSH (0x07)** — header-only `STATUS_SUCCESS`
9. **READ (0x08)** — file data via `pread`-style offset read
10. **WRITE (0x09)** — file data via `pwrite`-style offset write
11. **LOCK (0x0a)** — always granted, header-only `STATUS_SUCCESS` (no enforcement)
12. **IOCTL (0x0b)** — `FSCTL_PIPE_TRANSCEIVE` (DCE/RPC); others well-formed NOT_SUPPORTED
13. **CANCEL (0x0c)** — async cancel of a pending CHANGE_NOTIFY; no response, ever
14. **ECHO (0x0d)** — 4-byte body success
15. **QUERY_DIRECTORY (0x0e)** — `FileIdBothDirectoryInformation` listing
16. **CHANGE_NOTIFY (0x0f)** — async directory watch (interim `STATUS_PENDING`)
17. **QUERY_INFO (0x10)** — file info classes + `FileFsSizeInformation`
18. **SET_INFO (0x11)** — disposition (delete-on-close), EOF (truncate), basic (no-op)

Any other command must be answered with a well-formed
`STATUS_NOT_SUPPORTED` response — never a silent drop (a dropped command kills
Finder sessions with "Server connection interrupted").

### Named-Pipe / DCE/RPC Operations (via `IPC$` tree, `FSCTL_PIPE_TRANSCEIVE` = `0x0011c017`)

19. **DCE/RPC BIND** — accept with the fixed 56-byte NDR32 BIND_ACK template
20. **DCE/RPC REQUEST/RESPONSE** — opnum dispatch
21. **NetrShareEnum (opnum 0x000f)** — enumerate the single configured share (NDR32)

### Explicitly Out of Scope

- Request/response signing and encryption (the Negotiate response advertises
  `security_mode=1` signing-enabled, but nothing is ever signed or verified)
- Authentication beyond guest (any SESSION_SETUP is accepted; no NTLM crypto check)
- Opportunistic locks / leases
- Durable or resilient handles
- Multi-channel
- SMB 1 operations — with one exception: the SMB1-framed *negotiate preamble* is
  accepted as a bridge into SMB2 (see Negotiate section)
- SMB 3.1.1 and Negotiate Contexts (never offered)
- DFS, ACLs, security descriptors, symbolic links, change journals

## Implementation Strategy

### Phase 1: Protocol Foundation

**Deliverable:** SMB2 packet parser, NetBIOS framing, response helper, session state machine.

- SMB2 wire structs `#pragma pack(1)`; explicit little-endian get/put codec
- Header parse (minimum 14 bytes, every field past offset 14 gated on length)
  and header build; signature check `fe 53 4d 42`
- NetBIOS-over-TCP framing on receive and send (partial frames, coalescing,
  dynamic growth) — see Critical Wire Requirements
- One client-handler FreeRTOS task per connection; heap request/response buffers
- Shared response-header helper: echoes request ids, grants credits, always
  appends the 8-byte SMB2 Error Response tail on non-success
- Per-connection context: `socket`, `session_setup_started`, per-connection tree
  table (`tree_id`/`in_use`/`is_ipc` + monotonic `next_tree_id`), last request header
- ECHO, LOGOFF, TREE_DISCONNECT, unsupported-command fallback
- Compound-request loop (NextCommand chain, related-FileId substitution)

### Phase 2: Core Disk Share Access

**Deliverable:** file I/O over the mounted share.

- CREATE (UTF-16LE path decode → containment check → open/create, delete-on-close
  flag, MxAc create-context), CLOSE (release-then-delete ordering), READ, WRITE
- QUERY_INFO: `FileBasicInformation`, `FileStandardInformation`,
  `FileNetworkOpenInformation`, `FileAllInformation`,
  `FileFsSizeInformation` (static placeholder volume size)
- SET_INFO: `FileDispositionInformation`, `FileEndOfFileInformation`,
  `FileBasicInformation` (acknowledge only)
- FLUSH (header-only success), LOCK (always grant)
- Path security: `..` traversal, drive letters, separators rejected; stay inside mount point
- `errno` → NTSTATUS mapping (table below)

### Phase 3: Directory Enumeration

**Deliverable:** QUERY_DIRECTORY handler for Finder listing.

- `FILE_ID_BOTH_DIR_INFORMATION` (class 37) encoder with `readdir()`
- `SL_RESTART_SCAN` / `SL_RETURN_SINGLE_ENTRY` flags, search-pattern filtering,
  `NextEntryOffset` chaining, 8-byte alignment, `STATUS_NO_MORE_FILES`

### Phase 4: IPC$ Share and srvsvc

**Deliverable:** share enumeration via named pipe.

- `IPC$` tree recognised (case-insensitive `IPC$` in the path); disk-tree path
  must contain the configured share name
- CREATE of `srvsvc` on an IPC tree → pipe handle (never a VFS path)
- IOCTL `FSCTL_PIPE_TRANSCEIVE`; DCE/RPC BIND → BIND_ACK; REQUEST opnum
  0x000f → NetrShareEnum NDR response (exact layouts below)

### Phase 5: Async, Robustness & Client Integration

**Deliverable:** verified on hardware across clients; async + hardening features.

- CHANGE_NOTIFY: watch table, interim `STATUS_PENDING`, fire hooks on
  CREATE(ADDED)/CLOSE(REMOVED), `SO_RCVTIMEO`-driven poll + final async response,
  CANCEL, cleanup by file-id/socket. (Deliberate scope addition beyond the
  original out-of-scope list, requested when "Filer" busy-polled QUERY_DIRECTORY
  because the command returned NOT_SUPPORTED.)
- Two-leg SESSION_SETUP with NTLMSSP/SPNEGO envelope mirroring; LOGOFF resets the
  session-leg state
- Per-socket handle/watch release (`release_by_socket`) — one client's LOGOFF/TREE_DISCONNECT
  must never close another client's handles; global reset only once at server start
- Robustness caps: compound-chain cap, max request frame cap, stalled-frame diagnostics
- Trim debug-only hex dumps back to `ESP_LOGD` once features are validated
- Cross-client hardware validation (see Validation Criteria)

## Implementation Constraints

### Filesystems

Support these filesystems only:
- LittleFS
- FatFS

Do NOT implement SPIFFS support.

The SMB layer operates against an ESP-IDF VFS mount point and is
filesystem-agnostic (all I/O goes through the thin POSIX wrapper `smb_vfs.c`).
Validated on LittleFS; the wrapper keeps other VFS filesystems viable.

Typical mount points:
```
/littlefs
/sdcard
```

### Component Independence

The `smb_server` component must NOT:
- Configure WiFi or perform WiFi provisioning
- Mount LittleFS or FatFS
- Initialize SD card
- Initialize mDNS

These responsibilities belong to the example application. The reusable component
remains independent from networking and filesystem initialization.

### Memory and Storage

**ESP32 Constraints:**
- Flash: 4 MB (typical)
- SRAM: 520 KB (user-accessible heap)
- Task stack: 12 KB (configurable)

**Component Footprint (target):**
- Binary size: 60–100 KB
- Per-session runtime: 2–4 KB (handles, path buffers)
- Per-file runtime: 1–2 KB (file descriptors, seek positions)

**Hard rule:** never put 8 KB packet buffers on a task stack (a 6 KB stack with
two 8 KB stack buffers caused guaranteed `Guru Meditation` overflows in
`lwip_recvfrom`). All packet buffers are heap-allocated per connection.

**Fixed-size internal limits (`smb_internal.h` / `smb_protocol.c`):**

| Constant | Value | Meaning |
|---|---|---|
| `SMB_SERVER_SHARE_NAME_MAX` | 32 | share name buffer |
| `SMB_SERVER_MOUNT_POINT_MAX` | 128 | mount point buffer |
| `SMB_SERVER_PATH_MAX` | 512 | resolved VFS paths |
| `SMB_SERVER_HANDLE_COUNT` | 24 | global file/dir/pipe handle slots |
| `SMB_SERVER_MAX_TREES` | 4 | open trees per connection |
| `SMB_SERVER_MAX_NOTIFY_WATCHES` | 8 | pending CHANGE_NOTIFY watches |
| `SMB_SERVER_NOTIFY_NAME_MAX` | 64 | notify filename buffer |
| `SMB_SERVER_MAX_CREDITS` | 32 | credit grant cap |
| `SMB_SERVER_MAX_COMPOUND_COMMANDS` | 16 | compound chain cap |
| `SMB_SERVER_MAX_IO_SIZE` | 65536 | advertised transact/read/write size |
| `SMB_SERVER_MAX_REQUEST_FRAME` | `MAX_IO_SIZE + 1024` | receive frame cap |

## Networking and Socket Handling (as implemented)

- lwIP POSIX sockets; `SO_REUSEADDR` on the listen socket, backlog 4
- Listen socket is bound to `INADDR_ANY:445`. Note: the current code hard-codes
  445 in `smb_protocol_listener_task()` and ignores `config.port`; when
  rebuilding, honour `config.port` (default 445 via Kconfig) or replicate the
  hard-coded bind exactly
- One `smb_client` handler task per accepted socket (6144-byte stack, priority 5);
  the handler deletes itself on disconnect
- `SO_RCVTIMEO` = 1 s on the client socket: the recv timeout tick is what drives
  pending CHANGE_NOTIFY delivery
- `max_clients` (1..4) is validated at `smb_server_start()` but the accept loop
  does not count or cap concurrent handlers; a rebuild should enforce the cap
  around task creation
- Receive loop must: (1) grow `request_buffer` via `realloc()` to exactly
  `4 + announcedNetBIOSLength` (announced from bytes 1..3 of the pending frame at
  the buffer front) capped at `SMB_SERVER_MAX_REQUEST_FRAME`; (2) treat an
  announcement above the cap as a protocol violation and disconnect; (3) keep any
  incomplete trailing frame at the buffer front across `recv()` calls
  (`memmove` the leftover; never discard a partial frame); (4) process *all*
  complete frames present after one `recv()` (clients coalesce messages);
  (5) warn (once per 3 s) on a stalled partial frame and dump the first 16 bytes
- Responses are sent as two `send()` calls: 4-byte NetBIOS header (type `0x00`,
  24-bit big-endian length) then the SMB2 message
- On connection end: `smb_session_release_by_socket()`,
  `smb_protocol_notify_release_by_socket()`, free buffers, close socket

## Critical Wire Requirements

These are non-negotiable, hardware-proven requirements. Each maps directly to a
behaviour in `smb_protocol.c` / `smb_packet.c`.

### Packet layer

- All wire structs are `#pragma pack(1)`; verify `sizeof(smb2_header_t) == 64`
- Access multi-byte fields through the `smb2_get/put_uXX_le()` codec, never via
  struct casts over unaligned client data
- `smb2_parse_header()` accepts anything ≥ 14 bytes (signature + command at
  offset 12); fields beyond that are read only when the length allows, the rest
  stay zero from the initial `memset`
- Clients exist that send `structure_size != 64` (e.g. 114): warn, do not reject
- SMB2 signature constant is the u32 `0x424d53fe` (wire bytes `fe 53 4d 42`);
  SMB1 preamble is `0x424d53ff` (`ff 53 4d 42`)

### Response headers (all paths)

- Echo from the last parsed request header: `command`, `message_id`, `tree_id`,
  `session_id`. **Every** response path must echo `session_id` — including
  hand-built headers (TREE_CONNECT originally omitted it; clients reject a tree
  whose response carries `session_id = 0`)
- Set `SMB2_FLAGS_SERVER_TO_REDIR`; in responses the header bytes 14..15 are
  `CreditCount`/granted credits — grant `clamp(requested, 1, 32)`; final async
  CHANGE_NOTIFY responses grant 0
- Non-success responses must carry the minimal 8-byte SMB2 Error Response body
  (`StructureSize=9, ErrorContextCount=0, Reserved=0, ByteCount=0`) — iOS clients
  hang waiting for the 8-byte tail when it is missing
- The shared helper memsets the body region: handlers that pre-write their body
  into the response buffer **before** calling the helper must pass
  `body_length = 0` and set `*response_length` manually afterwards (READ data,
  QUERY_INFO, QUERY_DIRECTORY) — otherwise the body is zeroed after being filled

### Negotiate (0x00)

- Accept dialects `0x0202, 0x0210, 0x0300, 0x0302` (+ wildcard `0x02FF`); log
  every offered dialect raw; select the highest accepted; never offer `0x0311`
- Response body (64 bytes): `StructureSize=65`, `SecurityMode=1` (signing
  advertised, never enforced), `DialectRevision=selected`, fixed `ServerGuid`
  (`53 4d 42 32 45 53 50 33 32 2d 53 45 52 56 52 01` = "SMB2ESP32-SERVER" + 0x01),
  `Capabilities=0`, `MaxTransact/MaxRead/MaxWrite = SMB_SERVER_MAX_IO_SIZE`,
  `SystemTime = ServerStartTime = FILETIME(now)`,
  `SecurityBufferOffset = 64 + 64 = 128`, `SecurityBufferLength = 0`
- **SMB1 preamble bridge:** when the payload signature is `ff 53 4d 42`, accept
  the request *only* if it is an SMB1 negotiate (`request[4] == 0x72`, dialect
  block at offset 35, length u16 at offset 33) whose dialect list contains a
  string starting `"SMB 2."`. Reply by running the normal NEGOTIATE with the
  single dialect `0x02FF` (wildcard) — the standard multi-protocol handshake that
  prompts the client to send a real SMB2 NEGOTIATE with its full dialect list.
  **Never pin the legacy reply to `0x0202`:** Apple clients accept 0x0202 for
  anonymous `IPC$` browsing but silently abandon the connection right after a
  successful TREE_CONNECT to the real disk share. All other SMB1 requests: reject

### Session Setup (0x01) — guest, two legs, envelope mirroring

- Leg detection: `session_setup_started` flag on the connection; LOGOFF must
  reset it (a re-login on the same TCP connection is a fresh leg 1)
- Inspect the request security buffer: if it starts with `"NTLMSSP\0"` the client
  wants **bare** NTLMSSP (macOS `mount_smbfs`, "Filer"); otherwise it sent
  **SPNEGO** (iOS Files) and must get a SPNEGO-wrapped reply. Mirror the form
  the client itself used — a mismatched envelope makes the client `LOGOFF`
  immediately after leg 1
- Leg 1 reply: header `status = STATUS_MORE_PROCESSING_REQUIRED`,
  `session_id = 1`; body (8 bytes) `StructureSize=9`, `SessionFlags=0`,
  `SecurityBufferOffset = 64 + 8 = 72`, `SecurityBufferLength` = token size.
  The declared `StructureSize` value **9** is spec convention (fixed-size + 1),
  **not** a byte offset — the token starts at absolute offset 72
- Bare token = fixed 94-byte NTLMSSP type-2 Challenge: signature
  `"NTLMSSP\0"`, type 2, target fields, flags `0x62880205`, static 8-byte server
  challenge `01 23 45 67 89 ab cd ef`, target/NetBIOS-domain/NetBIOS-server
  strings `"ESP32"` in UTF-16LE (target-info AV-pairs included) — copy the exact
  byte array from `smb_protocol.c`
- SPNEGO token = `[0]`-less `[1] NegTokenResp` DER:
  `a1 77 30 75 | a0 03 0a 01 01` (negState accept-incomplete) `| a1 0c 06 0a
  2b 06 01 04 01 82 37 02 02 0a` (supportedMech OID 1.3.6.1.4.1.311.2.2.10)
  `| a2 60 04 5e` + the identical 94-byte NTLM Challenge
- Leg 2 reply: `status = STATUS_SUCCESS`, `SessionFlags =
  SMB2_SESSION_FLAG_IS_GUEST (0x0001)`, `SecurityBufferLength = 0`
- The username is never parsed; all requests are accepted (guest server)

### Tree Connect (0x03) / Tree Disconnect (0x04)

- Decode the UTF-16LE path; `IPC$` = case-insensitive substring match →
  `share_type 2`, else `share_type 1` and the path **must** contain the
  configured share name (else `STATUS_OBJECT_NAME_NOT_FOUND`)
- Per-connection tree table (4 slots); every successful connect gets a unique
  id from a monotonic counter (skip 0) — MS-SMB2 2.2.9 requires unique ids for
  concurrently open trees (clients open several `IPC$` trees at once)
- Success body (16 bytes): `StructureSize=16`, `ShareType`, `ShareFlags=0`,
  `Capabilities=0`, `MaximalAccess=0x001f01ff`; error path: header-only 64-byte
  response
- TREE_DISCONNECT frees the matching slot, then falls through to the LOGOFF
  cleanup: `smb_session_release_by_socket()` + `notify_release_by_socket()` for
  this connection only (never the global reset — that belongs at server start)

### Create (0x05)

- Decode `FileName` UTF-16LE → `smb_path_resolve()`: reject `..` segments,
  drive letters (`:`), collapse separators, refuse escape from the mount point
- On an `IPC$` tree a create for `srvsvc` (case-insensitive) allocates a **pipe**
  handle — never a VFS path like `/littlefs/srvsvc`
- Existence via `stat()` first. Create-action semantics: 1 = opened (existed),
  2 = created (new), 3 = overwritten. The `3` override for
  `FILE_OVERWRITE/FILE_OVERWRITE_IF/FILE_SUPERSEDE` applies **only when the file
  already exists** — an unconditional override breaks the ADDED notify hook (see
  CHANGE_NOTIFY invariants)
- Disposition/attribute conflicts: `FILE_CREATE` on existing →
  `OBJECT_NAME_COLLISION`; open/overwrite of missing → mapped errno
  (typically `OBJECT_NAME_NOT_FOUND`); dir flag vs actual type mismatch →
  `NOT_A_DIRECTORY` / `FILE_IS_A_DIRECTORY`; `read_only` config denies create /
  truncate dispositions
- Directories: `mkdir` (0777) when absent (unless read_only) then `opendir()` —
  the DIR* lives on the handle. Files: `open()` O_CREAT/O_TRUNC per disposition,
  `O_RDWR` unless read_only
- `FILE_DELETE_ON_CLOSE` (0x00001000) sets `delete_pending` on the handle
- **MxAc create-context:** scan the create-context chain for a 4-byte name
  `"MxAc"`; when requested the response must append the 32-byte context
  (`Next=0, NameOffset=16, NameLength=4, DataOffset=24, DataLength=8,` name
  `"MxAc", QueryStatus=0, MaximalAccess=0x001f01ff`) and set the fixed body's
  `CreateContextsOffset` at body offset 80 / `Length` at 84. macOS's kernel
  mount path stalls (122 s timeout) when this is silently skipped
- Response body (88 bytes): `StructureSize=89`, `OplockLevel=0`,
  `CreateAction`, four FILETIMEs (creation/access/write/change from `stat`),
  `AllocationSize=EndOfFile=st_size`, `FileAttributes = S_ISDIR ? 0x10 : 0x80`,
  16-byte FileId (u64 handle id in the low 8 bytes, rest zero)
- Genuine new objects (`create_action == 2`) fire `notify_fire(parentDir,
  FILE_ACTION_ADDED, leaf)`

### Close (0x06)

- Capture `stat()` **before** releasing the handle; release the handle (closing
  fd/DIR) **before** `unlink()`/`rmdir()` — LittleFS refuses to delete a path
  that still has an open fd ("Has open FD")
- Keep the pre-delete stat for the response even after a successful delete:
  macOS's kernel client rejects a CLOSE response with all-zero attributes
- Success body (60 bytes): `StructureSize=60`, timestamps, sizes, attributes from
  the captured stat

### Read (0x08) / Write (0x09)

- READ: pipes answer `STATUS_END_OF_FILE`; directories answer
  `STATUS_FILE_IS_A_DIRECTORY`; read past EOF → `STATUS_END_OF_FILE`; clamp the
  requested length to the response capacity
- READ response: `StructureSize=17`, `DataOffset` (u8) = `64 + 16`,
  `DataLength`; data directly into the buffer after the 16-byte body; use the
  `body_length = 0` helper trick
- WRITE: bounds-check `DataOffset`/`DataLength` against the frame; `read_only` →
  `STATUS_ACCESS_DENIED`; directory/pipe handles → `STATUS_FILE_IS_A_DIRECTORY`;
  offset write via lseek+write wrapper
- WRITE response: `StructureSize=17`, `Count = bytes written`

### Query Info (0x10)

- `info_type == SMB2_0_INFO_FILESYSTEM`: only `FileFsSizeInformation` (class 3),
  else `STATUS_NOT_SUPPORTED`. ESP-IDF's VFS has no generic `statvfs()`, so
  report **static placeholders**: 512 MB total, 256 MB free, 512-byte sectors
  (`SectorsPerAllocationUnit=1`) — a deliberate design choice to stay
  filesystem-agnostic. Output 24 bytes (FILE_FS_SIZE_INFORMATION):
  `TotalAllocationUnits = 512MB/512`, `AvailableAllocationUnits = 256MB/512`,
  `SectorsPerAllocationUnit = 1`, `BytesPerSector = 512`; response
  `OutputBufferOffset = 64 + 8 = 72`, `OutputBufferLength = 24`
- `info_type == SMB2_0_INFO_FILE` classes (from `stat`): `FileBasicInformation`
  (40 B), `FileStandardInformation` (24 B), `FileNetworkOpenInformation` (56 B),
  `FileAllInformation` (100 B + UTF-16 name); other classes →
  `STATUS_NOT_SUPPORTED`
- FILETIME conversion: `(unix_seconds + 11644473600) * 10000000`
- Any other `info_type` → `STATUS_NOT_SUPPORTED`

### Set Info (0x11)

- `FileDispositionInformation`: set/clear `delete_pending` from the first byte;
  read_only → `STATUS_ACCESS_DENIED`
- `FileEndOfFileInformation`: `ftruncate` to the u64 value; read_only/dir/pipe →
  `STATUS_ACCESS_DENIED`
- `FileBasicInformation`: acknowledge without applying (timestamps/attributes are
  not persisted)
- Success body **must** contain `StructureSize = 2` (2 bytes) — MS-SMB2 2.2.39.
  A zeroed SET_INFO response (the header helper's memset silently did this once)
  makes macOS report `fts_read: RPC struct is bad` on every `rm`

### Query Directory (0x0e)

- Only `FileIdBothDirectoryInformation` (class 37); else `STATUS_NOT_SUPPORTED`;
  non-directory handle → `STATUS_NOT_A_DIRECTORY`
- `SL_RESTART_SCAN (0x01)` → `rewinddir()`; `SL_RETURN_SINGLE_ENTRY (0x02)` →
  return exactly **one** matching entry then stop (protocol violation otherwise
  — Finder polls with `flags=0x03` + a specific filename)
- Honour the request `FileName` search pattern: decode UTF-16LE (low byte per
  code unit), case-insensitive DOS wildcard match (`*`, `?`); empty pattern or
  `"*"` matches everything; non-matching `readdir()` results are skipped —
  without filtering, single-entry probes always return the first entry and
  polling clients spin forever
- Entry encoding (`FILE_ID_BOTH_DIR_INFORMATION`): 104-byte fixed part + UTF-16LE
  name + 2-byte null; all four timestamps = change-time FILETIME;
  `EndOfFile = st_size`; `AllocationSize = roundup(st_size, 4096)`;
  **`FileAttributes` = `0x10` dir / `0x80` (FILE_ATTRIBUTE_NORMAL) file — `0` is
  invalid and Finder silently drops such entries**; `FileNameLength` excludes the
  null; `EaSize=0`, `ShortNameLength=0`, ShortName left zeroed; `FileId = st_ino`
- Entries are 8-byte aligned; **zero the alignment padding** (the response
  buffer is reused across requests and stale bytes leak onto the wire);
  `NextEntryOffset` of the previous entry is back-patched with the previous
  entry's *aligned* size once the next entry's offset is known; last entry's
  `NextEntryOffset = 0`
- No matching entries → `STATUS_NO_MORE_FILES (0x80000006)` (this is also the
  correct answer for AppleDouble `._*` probes that do not exist — it is not a bug)
- Response body: `StructureSize=9`, `OutputBufferOffset = 72`,
  `OutputBufferLength = bytes used`

### IOCTL (0x0b) — FSCTL_PIPE_TRANSCEIVE (0x0011C017)

- IOCTL request body parse: `CtlCode` at body+4, `InputOffset` at body+24,
  `InputCount` at body+28; validate against the frame before touching
- Unsupported control codes still get a well-formed response: 48-byte body,
  `StructureSize=49`, CtlCode echoed at +4, FileId (16 B) echoed at +8, all
  offsets/counts zero, `STATUS_NOT_SUPPORTED`
- **BIND** (DCE/RPC common header `ptype` at input byte 2 == `0x0b`,
  `InputCount >= 16`): reply with the fixed **56-byte BIND_ACK template**
  (bytes, verbatim — hardware-validated):
  `05 00 0c 03 10 00 00 00 38 00 00 00 00 00 00 00 b8 10 b8 10 00 00 00 00
  00 00 00 00 01 00 00 00 00 00 00 00 04 5d 88 8a eb 1c c9 11 9f e8 08 00
  2b 10 48 60 02 00 00 00`
  with bytes 12..15 (Call ID) overwritten from request bytes 12..15
- **REQUEST** (`ptype == 0x00`, `InputCount >= 24`, opnum u16 at input offset 22
  == `0x000f`) → NetrShareEnum. IOCTL response: `StructureSize=49`, CtlCode
  echo, FileId echo, `OutputOffset = 64 + 48`, `OutputCount` = NDR blob length,
  NDR blob appended at body+48
- **NetrShareEnum NDR32 blob** — exact layout (fields after the 24-byte
  DCE/RPC RESPONSE header; this layout is the hardware-validated one, do not
  "improve" it):
  - DCE/RPC RESPONSE header (24 B): version 5, minor 0, `ptype=2`,
    `pfc_flags=0x03`, data rep `10 00 00 00`, fragment length u16 at +8,
    auth version 0 at +10, Call ID u32 at +12 copied from the request, stub
    length (`blob_len − 24`) u32 at +16, cancel count u16 0 at +20, reserved
    `00 00` at +22..23
  - Stub: `Level=1`, union `switch_is=1`, container unique-pointer
    `0x00020000`, then deferred: `EntriesRead=1`, buffer pointer `0x00020004`,
    conformant array `MaximumCount=1`
  - `SHARE_INFO_1`: NetName pointer `0x00020008`, `Type=0`, Remark pointer
    `0x0002000c`
  - Deferred conformant-varying share name: `max_count = actual_count =
    len+1`, `offset=0`, UTF-16LE chars **including the null terminator**, pad to
    4-byte boundary
  - Deferred empty remark: `max=1, offset=0, actual=1`, single UTF-16 null, pad
    to 4-byte boundary
  - Output params in order: `TotalEntries=1`, `ResumeHandle=0`, `WERROR=0`
- Missing `EntriesRead` or the array `MaximumCount` shifts every following field
  by 4/8 bytes and corrupts the whole NDR stream (the classic
  "smbutil: Broken pipe" failure); derive from `srvsvc.idl` if in doubt

### Compound (chained) requests

- Loop over sub-commands using each header's `NextCommand` (0 = last); a
  missing compounding loop makes `mount_smbfs` hang exactly ~122 s (the kernel
  waits forever for a response to the chained CREATE+QUERY_INFO+CLOSE)
- Sub-commands carrying `SMB2_FLAGS_RELATED_OPERATIONS` must have their FileId
  (at `offsetof(..., file_id)` for CLOSE/READ/WRITE/QUERY_INFO/SET_INFO/
  QUERY_DIRECTORY/CHANGE_NOTIFY) replaced by the FileId of the **preceding
  successful CREATE in the same chain**
- Every non-final sub-response is zero-padded to an 8-byte multiple;
  `NextCommand` = padded length; final = 0
- Cap the chain at `SMB_SERVER_MAX_COMPOUND_COMMANDS` (16); on a malformed
  chain or failed sub-parse mid-chain, truncate gracefully by zeroing the
  previous response's `NextCommand` (never fail the whole frame after already
  having answered part of it)

### Locks, Flush, Echo, Cancel

- FLUSH: header-only `STATUS_SUCCESS`
- LOCK: always granted, header-only `STATUS_SUCCESS` (MS-SMB2 2.2.30 defines no
  response body; locks were never enforced anyway — Samba `locking = off`
  behaviour; `STATUS_NOT_SUPPORTED` here is fatal for stricter clients)
- ECHO: 4-byte body `{StructureSize=4}`
- CANCEL: never answered (sync or async). Async cancel reads the target's
  `AsyncId` from the request's `reserved`/`tree_id` header word pair and marks
  the matching pending watch cancelled

### CHANGE_NOTIFY (0x0f) — async directory watch

Design (the VFS has no change-event API and each connection has exactly one
blocking `recv()`):
- Fixed 8-slot watch table + its own mutex; slot stores `socket`, `file_id`,
  `watched_path`, `watch_tree`, `completion_filter`, `message_id`, `session_id`,
  `async_id` (monotonic, never 0), `fired`, `result_status`, `action`, `name`
- Register → immediate interim response: header `flags |= ASYNC_COMMAND`,
  `status = STATUS_PENDING (0x00000103)`, AsyncId split across the header's
  `reserved` (low 32) and `tree_id` (high 32) words (the same wire bytes the
  sync header uses there), 8-byte Error-Response-shaped body
  (`StructureSize=9`)
- Hooks: CREATE with `create_action == 2` → `FILE_ACTION_ADDED`; successful
  delete-on-close → `FILE_ACTION_REMOVED`; match on watched path (exact, or
  ancestor when `SMB2_WATCH_TREE`)
- The owning connection's 1 s `SO_RCVTIMEO` recv-timeout tick calls the notify
  poll: for each fired watch of this socket, send the final async response —
  header `ASYNC_COMMAND | SERVER_TO_REDIR`, original `message_id`/`session_id`,
  granted credits 0, body `StructureSize=9`, `OutputBufferOffset=72`, then
  `FILE_NOTIFY_INFORMATION` (single entry: next=0, action, FileNameLength,
  UTF-16LE name); cancelled watches send the status without body payload, then
  free the slot
- Cleanup: close of the watched handle frees its watch (by file id);
  TREE_DISCONNECT / LOGOFF / disconnect free this socket's watches
- **Three accepted spec deviations:** (1) all matching watches fire on an event
  instead of strict per-handle FIFO; (2) TREE_DISCONNECT cleanup is
  connection-wide, not tree-scoped (slots don't track tree ids); (3) no
  `CompletionFilter` bit-matching — any watched-path change fires regardless of
  the requested filter

**CHANGE_NOTIFY invariants (do not reintroduce these two bugs):**
1. A watch's "fired" state is the dedicated `bool fired` — **never** test
   `result_status != 0`: `STATUS_SUCCESS` is `0x00000000`, identical to the
   "still pending" sentinel, and the zero-check silently swallows every final
   response. `register`/`fire`/`cancel`/`poll` all read/write `fired`; read
   `result_status` only once `fired == true`.
2. `create_action` stays `2` (FILE_CREATED) for a genuinely new file even under
   `FILE_OVERWRITE/FILE_OVERWRITE_IF/FILE_SUPERSEDE`; force `3` only when the
   file exists. The ADDED fire-hook depends on this value being accurate.

### Handle / session state

- Handle table is global (24 slots) guarded by one mutex; every slot records
  `owner_socket`. Single-handle release closes fd/DIR and frees pipe buffers;
  `release_by_socket()` releases only that connection's handles; the global
  reset runs once at server start before any client connects — a per-client
  TREE_DISCONNECT/LOGOFF must never call it (it would close every other client's
  open files)
- Connection context (`smb_protocol_context_t`): socket, `session_setup_started`,
  tree table + `next_tree_id`, `last_request_header` (the single source for all
  echoed response ids)

### Path security

- UTF-16LE → UTF-8 decoder: BMP only (1–3 byte UTF-8), even input length, stop
  at null
- `smb_path_resolve()`: trailing-slash trimming on the mount point, collapse
  `/` and `\`, drop `.` segments, **reject** `..` (containment), reject any
  segment containing `:` (drive letters / ADS-style paths); overflow-checked
  against the output buffer

### Error handling

`errno` → NTSTATUS mapping (code: `smb_protocol_status_from_errno`):

| errno | NTSTATUS |
|---|---|
| `ENOENT` | `STATUS_OBJECT_NAME_NOT_FOUND` |
| `ENOTDIR` | `STATUS_NOT_A_DIRECTORY` |
| `EISDIR` | `STATUS_FILE_IS_A_DIRECTORY` |
| `EEXIST` | `STATUS_OBJECT_NAME_COLLISION` |
| `EACCES`/`EPERM`/`EBADF` | `STATUS_ACCESS_DENIED` |
| `ENOSPC` | `STATUS_DISK_FULL` |
| `ENOTEMPTY` | `STATUS_DIRECTORY_NOT_EMPTY` |
| other | `STATUS_INVALID_PARAMETER` |

Other rules: malformed DCE/RPC would warrant a fault PDU (`0x1c010002`) per
spec; the current code simply answers `STATUS_NOT_SUPPORTED` IOCTL responses —
acceptable for guest scope. Never crash on malformed client input; log with
`ESP_LOGE`.

### Logging

- `ESP_LOGE/W/I/D` only (no printf); tags: `smb_server`, `smb_protocol`,
  `smb_packet`, `smb_session`, `smb_vfs`
- All per-packet hex dumps (`smb_protocol_dump_packet`) stay at `ESP_LOGD` so
  they never flood the console; framing-desync WARNs (oversized frame, wrong
  NetBIOS type, stalled partial frame) include the first 16 buffer bytes as
  evidence

## Validation Criteria (Mandatory Before Completion)

**All of the following must pass on hardware:**

### macOS Validation

1. `smbutil view -G '//guest@<ESP_IP>'`
   - Completes without hanging
   - Lists the configured share name (e.g., "ESP32")
   - No "Broken pipe" error
2. Finder **Go > Connect to Server** with `smb://guest@<ESP_IP>/ESP32`
   - Share mounts successfully; directory contents listed
3. `mount_smbfs -N smb://guest@<ESP_IP>/ESP32 /mnt/esp32` succeeds
   (kernel-path mount — this exercises compounding, MxAc and
   FileFsSizeInformation; `smbutil` alone does NOT)
4. File operations on the mounted share:
   - List / read / create / write / read-back / delete file: all work
   - `mkdir` / `rmdir`: work
   - Multi-PDU transfer: `dd` a ≥100 KB file, `cp` + `diff` byte-exact
   - `rm` of a just-written file completes with no `RPC struct is bad`
5. Finder GUI shows the files (not only command-line `ls`)

### Windows Validation (if available)

1. `net view \\<ESP_IP>` lists the share
2. Explorer mounts and browses; read/write/delete work

### Linux Validation (if available)

1. `mount -t cifs //<ESP_IP>/ESP32 /mnt/esp32 -o guest` succeeds
2. File operations work (read, write, delete)
3. `umount /mnt/esp32` succeeds

### iOS Validation

1. Files app / "Filer": SESSION_SETUP completes (bare or SPNEGO envelope,
   whichever the client sent), disk share connects, listing + copy work

### Device Logging Validation

- Protocol logs captured with timestamps; no memory corruption or stack overflows
- Heap usage within 50% of available
- TCP connections close cleanly

## Milestones and Go/No-Go Checkpoints

**End of Phase 1:** SMB2 packets parse and serialize correctly; sessions/trees/
files can be allocated and released; ECHO keepalives answered.

**End of Phase 2:** file create/read/write/delete validated on hardware via a
kernel-path mount.

**End of Phase 3:** multi-entry `ls` (no `fts_read: RPC struct is bad`) and
Finder GUI listings show correct names, sizes and types.

**End of Phase 4:** `smbutil view -G` lists the share without "Broken pipe";
`mount_smbfs` mounts without the 122 s hang.

**End of Phase 5:** CHANGE_NOTIFY interim + final responses observed on the
wire; concurrent clients don't interfere; all Validation Criteria pass (iOS
third-party app outstanding — see Known Open Items).

## Notes for Developers

- Keep the protocol layer independent from the VFS layer (all FS access goes
  through `smb_vfs.c`; swapping LittleFS ↔ FatFS must not touch handlers)
- Use ESP_LOGI/ESP_LOGW/ESP_LOGE for all logging (no printf)
- Prefix comments with `//--` (project convention)
- Use Allman brace style and 2-space indentation
- Test frequently on hardware; compilation never implies protocol correctness —
  NDR/offset bugs only surface on the wire (tcpdump `-X -nn` + hand-decoding, or
  an `ESP_LOG_BUFFER_HEXDUMP` of the *outgoing* response, settles debates the
  spec can't)
- Do NOT skip security validation (path traversal checks, buffer bounds,
  offset/length validation of every variable data area before reading)
- Never hand-build a response header without echoing `session_id`

## Known Open Items (as of current code)

- `mount_smbfs` `ls -la` shows epoch timestamps (`Jan 1 1970`) — `st_mtime`
  reporting via the LittleFS VFS layer suspected; `smb_vfs_stat()` is a bare
  `stat()` passthrough — parked
- Under sustained copy load a mid-WRITE framing desync can occur: a frame
  announces fewer bytes than it carries and the next "NetBIOS header" is
  actually file data (`ff ff ff ff`-style announcements). Diagnostics (type-byte
  WARN, stalled-frame WARN + 16-byte dumps) are in place; root cause (client
  abort vs. announced/actual mismatch) not yet identified
- CHANGE_NOTIFY end-to-end behaviour (interim PENDING, real create/delete
  notifications, disappearance of the CREATE/QUERY_DIRECTORY busy-poll pattern)
  implemented and build-verified, hardware retest pending
- Windows `net view`/Explorer and Linux `mount -t cifs` validation pending
