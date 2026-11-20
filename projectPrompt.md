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
# SMB Server — ESP32 Custom Implementation

# Project Prompt — `smb_server`

## Goal

Build a **minimal, production-quality SMB2/SMB3 server component** for ESP32 that exposes an already-mounted ESP-IDF VFS filesystem as an SMB2/SMB3 network share.

The component must work reliably with:
- macOS Finder and `smbutil`
- Windows File Explorer
- Linux `mount -t cifs`
- iOS/iPadOS SMB clients (FileBrowser, etc.)

The final result must be structured and reusable so that the `smb_server` component can be published in the Espressif Component Registry.

## Architecture Decision: Custom SMB2 Implementation

**CRITICAL:** Do NOT use libsmb2 (upstream or Espressif registry).

**Reason:** libsmb2 is a client library. Its server-side callbacks are incomplete stubs. Specifically:
- IOCTL output buffers are not serialized into SMB2 response packets
- DCE/RPC pipe operations (srvsvc) cannot be properly implemented
- Attempting workarounds wastes development time without resolution

**Solution:** Implement a minimal, focused SMB2 protocol handler directly in the `smb_server` component.

**References:** Don't guess but check "/protocolReferences.md".

## Scope: Minimal SMB2 Server

Implement ONLY these operations (alphabetically):

### Core SMB2 Commands

1. **Negotiate** — Dialect selection (SMB 2.1, 3.0, 3.1.1)
2. **Session Setup** — Guest-only authentication (no NTLMSSP encryption)
3. **Tree Connect** — Connect to disk shares or `IPC$` (srvsvc pipe)
4. **Tree Disconnect** — Disconnect from share
5. **Create** — Open/create files, directories, or pipes
6. **Close** — Close file handles
7. **Read** — Read file data or pipe data
8. **Write** — Write file data or send pipe data (DCE/RPC requests)
9. **Query Info** — Get file metadata (size, timestamps, attributes)
10. **Set Info** — Modify file metadata
11. **Query Directory** — List directory contents
12. **Flush** — Flush file buffers
13. **Logoff** — End SMB session

### Named-Pipe / DCE/RPC Operations (via `IPC$` tree)

14. **DCE/RPC BIND** — Initiate RPC context (srvsvc interface)
15. **DCE/RPC REQUEST/RESPONSE** — RPC method invocation
16. **NetrShareEnum** — Enumerate available shares (operation 15)

### Explicitly Out of Scope (initial release)

- Signing/encryption (guest access only)
- Authentication beyond guest username
- Opportunistic locks (oplocks)
- Durable handles
- Multi-channel, multichannel resilient support
- SMB 1 (CIFS)

## Implementation Strategy

### Phase 1: Protocol Foundation (Week 1)

**Deliverable:** SMB2 packet parser and session state machine.

- Implement SMB2 packet header parsing (fixed 64-byte header)
- Implement variable-length message handling (Negotiate, SessionSetup, TreeConnect payloads)
- Session handle management (track context per client)
- Tree handle management (track mounted shares per session)
- File handle management (track open files per tree)

**Estimated lines of code:** 400–600

---

### Phase 2: Core Disk Share Access (Week 1–2)

**Deliverable:** READ/WRITE/QUERYINFO operations on files.

- Implement CREATE handler (resolve VFS path, open file with O_RDONLY/O_RDWR/O_CREAT)
- Implement CLOSE handler (close file descriptor, release handle)
- Implement READ handler (pread from file descriptor, return data)
- Implement WRITE handler (pwrite to file descriptor)
- Implement QUERY_INFO handler (stat() file, return size/timestamps/attributes)
- Implement SET_INFO handler (chmod/touch file metadata)
- Path security: Prevent `../` traversal; stay within configured mount point

**Estimated lines of code:** 400–600

---

### Phase 3: Directory Enumeration (Week 2)

**Deliverable:** QUERY_DIRECTORY handler for Finder listing.

- Implement QUERY_DIRECTORY handler (readdir() directory contents)
- Encode directory entries in SMB2 FILE_ID_BOTH_DIRECTORY_INFORMATION format
- Handle pagination (client may request entries in chunks)

**Estimated lines of code:** 200–300

---

### Phase 4: IPC$ Share and srvsvc (Week 2–3)

**Deliverable:** Share enumeration via named pipe.

- Implement CREATE for named pipes (allocate pipe context on `IPC$` tree)
- Implement WRITE/READ for pipe I/O (queue request data, queue response data)
- Implement DCE/RPC framing:
  - BIND request parsing (validate NDR32 syntax)
  - BIND_ACK generation (56 bytes, NDR32 acceptance)
  - REQUEST parsing (extract operation number, call ID)
  - RESPONSE generation (format output into NDR encoding)
- Implement NetrShareEnum handler:
  - Input: server name (ignored), level (0, 1, or 2)
  - Output: share name, share type, share remark (UTF-16LE encoded)
  - Encode in SHARE_INFO structure with NDR referent pointers

**Estimated lines of code:** 400–600

---

### Phase 5: Client Integration & Testing (Week 3–4)

**Deliverable:** Verified working on macOS, Windows, Linux.

- macOS: `smbutil view -G '//guest@<IP>'` completes and lists shares
- macOS: Finder mounts share and allows file operations
- Windows: `net view \\<IP>` lists shares
- Windows: Explorer mounts share and allows file operations
- Linux: `mount -t cifs //<IP>/share /mnt/esp32 -o guest` works
- iOS: FileBrowser app can see and access share

**Estimated lines of code:** 100–200 (test harness + debug logs)

---

## Implementation Constraints

### Filesystems

Support these filesystems only:
- LittleFS
- FatFS

Do NOT implement SPIFFS support.

The SMB layer operates against an ESP-IDF VFS mount point and is filesystem-agnostic.

Typical mount points:
```
/littlefs
/sdcard
```

### Component Independence

The `smb_server` component must NOT:
- Configure WiFi
- Perform WiFi provisioning
- Mount LittleFS or FatFS
- Initialize SD card
- Initialize mDNS

These responsibilities belong to the example application. The reusable component remains independent from networking and filesystem initialization.

### Public API

Keep the public API small and predictable:

```c
typedef struct
{
  const char *share_name;
  const char *mount_point;
  bool read_only;
  size_t max_clients;
  uint16_t port;
} smb_server_config_t;

esp_err_t smb_server_start(const smb_server_config_t *config);
esp_err_t smb_server_stop(void);
bool smb_server_is_running(void);
```

### Memory and Storage

**ESP32 Constraints:**
- Flash: 4 MB (typical)
- SRAM: 520 KB (user-accessible heap)
- Task stack: 12 KB (configurable)

**Component Footprint (target):**
- Binary size: 60–100 KB
- Per-session runtime: 2–4 KB (handles, path buffers)
- Per-file runtime: 1–2 KB (file descriptors, seek positions)

**Feasibility:** Yes. Custom SMB2 implementation (2000–3000 lines) + packet buffers + session state requires ~80 KB total. Ample margin on ESP32.

## Networking and Socket Handling

- Use ESP-IDF lwIP sockets directly
- SMB2 listens on TCP port 445 (standard)
- Support up to `max_clients` simultaneous connections
- Non-blocking or select-based multiplexing (ESP-IDF FreeRTOS-friendly)
- Graceful client disconnect handling

## Protocol Details

### SMB2 Packet Structure

All SMB2 messages follow this structure:

```
[0–3]   SMB2/SMB3 signature (0xFE, 0x53, 0x4D, 0x42 = "SMB")
[4–63]  Fixed header (64 bytes)
[64+]   Variable payload (command-specific)
```

Implement parsing for:
- Negotiate (variable)
- SessionSetup (variable)
- TreeConnect (variable)
- Create (variable)
- All others use fixed structures

### Guest Authentication

No NTLM challenge-response. Accept any SessionSetup request with username=GUEST and reply with STATUS_SUCCESS.

### Share Enumeration (NetrShareEnum)

Implement the remote procedure via `IPC$/srvsvc` named pipe:

```
Operation: NetrShareEnum (0x0F)
Input:
  - Server name (ignored)
  - Level (0, 1, or 2)
Output:
  - Share count
  - Array of SHARE_INFO_1 or SHARE_INFO_2 structures (NDR encoded)
  - Status code (0 = SUCCESS)
```

Encode share names and remarks in UTF-16LE with NDR referent pointers.

For initial release: Enumerate a single share (the configured `share_name`).

## Error Handling and Robustness

- Invalid SMB packet: Reply with STATUS_INVALID_PARAMETER or close connection
- File not found: Reply with STATUS_OBJECT_NAME_NOT_FOUND
- Access denied: Reply with STATUS_ACCESS_DENIED
- Out of memory: Reply with STATUS_INSUFFICIENT_RESOURCES
- Malformed DCE/RPC: Reply with fault response (status code 0x1c010002)

Log all errors with ESP_LOGE() for debugging. Do not crash on malformed client input.

## Validation Criteria (Mandatory Before Completion)

**All of the following must pass on hardware:**

### macOS Validation

1. `smbutil view -G '//guest@<ESP_IP>'` 
   - Completes without hanging
   - Lists the configured share name (e.g., "ESP32")
   - No "Broken pipe" error

2. Finder **Go > Connect to Server** with `smb://guest@<ESP_IP>/ESP32`
   - Share mounts successfully
   - Lists directory contents
   - No "connection timeout" or "connection refused" errors

3. File operations on mounted share:
   - List directory: Works
   - Read existing file: Works
   - Create new file: Works
   - Write to file: Works
   - Read back written file: Matches original content
   - Delete file: Works (if not read-only)
   - Delete directory: Works (if not read-only)

### Windows Validation (if available)

1. `net view \\<ESP_IP>` lists the share
2. File Explorer can mount and browse the share
3. Read/write/delete operations work

### Linux Validation (if available)

1. `mount -t cifs //<ESP_IP>/ESP32 /mnt/esp32 -o guest` succeeds
2. File operations work (read, write, delete)
3. `umount /mnt/esp32` succeeds

### Device Logging Validation

- All protocol logs are captured with timestamps
- No memory corruption or stack overflows
- Heap usage remains within 50% of available
- TCP connections close cleanly

## Patch Log

**Update This Patch Log after Every Major Change of Code**

**MIND YOU: The first Column is DATE+TIME**

Phases below are grouped by root-cause area rather than by calendar week: once a group of patches was proven to work together on hardware, its tables were merged under one phase heading. `fase2Plan.md` (an interim scratch-status file) has been fully folded into this log and removed.

### Phase 1 — Protocol Foundation (done)

| Date & Time | Work Done | Evidence | Status |
|-----------|-----------|----------|--------|
|  2026-08-18 08:15 | Decision: Abandon libsmb2, pivot to custom SMB2 | libsmb2 IOCTL output buffer serialization impossible; custom protocol handler required | Decision finalized |
|  2026-08-18 09:30 | Created smb_packet.h/c: SMB2 structures, little-endian codec, header parser/builder | Compiled; validates signature and structure_size | Foundation ✓ |
|  2026-08-18 10:45 | Created smb_protocol.c: TCP listener (port 445), per-client tasks, stack-allocated 8KB buffers | Server binds port 445, accepts connections; heap-safe | Networking ✓ |
|  2026-08-18 11:00 | Implemented Negotiate, SessionSetup, TreeConnect handlers | Handlers compile; build succeeds | Core handlers ✓ |
|  2026-08-18 12:30 | Debugged NetBIOS frame header detection; relaxed structure_size validation (client sends 114 not 64) | smbutil connects, Negotiate response sent (112 bytes) | Handshake works ✓ |
| 2026-08-18 13:00 | Added NetBIOS frame wrapping to responses; adjusted min payload check to 14 bytes | Client receives Negotiate response, progresses to SessionSetup | Protocol OK ✓ |
| 2026-08-18 14:00 | Fixed response header serialization: use smb2_build_header() + little-endian puts for all fields | Negotiate/SessionSetup/TreeConnect responses now properly serialized | Struct alignment ✓ |
| 2026-08-18 14:15 | Added #pragma pack(1) to SMB2 structures to prevent compiler padding/alignment issues | Struct sizeof verified as 64 bytes; all field offsets correct | Alignment fix ✓ |
| 2026-08-18 14:30 | BLOCKER: Client sends repeated Negotiate requests (SMB 3.1.1 Negotiate Context behavior) | Client receives 129-byte Negotiate response but rejects it; retries with different contexts | BLOCKED: Need Negotiate Context support |

### Phase 2 — Disk Share Access, Directory Enumeration & IPC$/NetrShareEnum (done, merged from former Fase2/Fase3/Fase4)

| Date & Time | Work Done | Evidence | Status |
|-----------|-----------|----------|--------|
| 2026-08-18 13:56-14:34 | Implemented disk/session foundation: UTF-16LE path decoding, traversal-safe VFS resolution, file/directory/pipe handles, mutex protection, delete-on-close state, CREATE/CLOSE/READ/WRITE/QUERY_INFO/SET_INFO handlers, NTSTATUS mapping, cleanup, and corrected SMB2 CREATE offsets | Repeated ESP-IDF v6.0.2 builds succeed; authentication and disk-share CREATE/root handling are reached on hardware | Implemented; file I/O and directory listing still needed hardware validation |
| 2026-08-18 13:56-15:02 | Fixed SMB2 wire foundation: true SMB2 signature `fe 53 4d 42`, packed structures, correct negotiate body (`ServerGuid`, sizes, times, offsets), credits, ECHO, and response serialization | `smbutil` progresses beyond negotiate/session setup; previous `RPC struct is bad` and credit stalls are resolved | Implemented |
| 2026-08-18 13:56-14:24 | Added SMB1 multi-protocol negotiate bridge: accept initial SMB1 `ff 53 4d 42` negotiate only when it offers SMB2 (`SMB 2.002`), then continue as SMB2 dialect `0x0202`; SMB1 operations remain unsupported | Device logs `SMB1 negotiate offered SMB2`; SMB2 response uses `fe 53 4d 42` | Implemented by design |
| 2026-08-18 14:07-14:31 | Implemented guest authentication interoperability: raw NTLMSSP type-1 detection, raw type-2 challenge, target name `ESP32`, target-info AV-pairs, two-step status flow, final `IS_GUEST` flag, and diagnostic token logging | Hardware reaches `STATUS_MORE_PROCESSING_REQUIRED`, receives NTLMSSP type 3, then gets `STATUS_SUCCESS` and proceeds to Tree Connect | Implemented; cryptographic validation is intentionally guest-only |
| 2026-08-18 14:45-15:02 | Added IPC$ routing: recognize `\\host\IPC$`, return pipe share type, and allocate `srvsvc` as a named-pipe handle instead of `/littlefs/srvsvc` | Hardware reaches `CREATE srvsvc pipe` and continues to `FSCTL_PIPE_TRANSCEIVE` | Implemented |
| 2026-08-18 14:47-15:15 | Added SMB2 IOCTL/pipe flow and DCE/RPC BIND support: log IOCTL input, recognize `0x0011c017`, return a 56-byte NDR32 `BIND_ACK`, handle ECHO/credits, and avoid abrupt socket closes | Hardware logs `DCE/RPC BIND acknowledged` and sends a 168-byte IOCTL response | Implemented; pipe buffering/REQUEST response still pending |
| 2026-08-18 15:12-15:15 | Blocker before the NDR slice: DCE/RPC REQUEST for `NetrShareEnum` was not implemented; empty pipe READ returned EOF, so `smbutil` showed the share header but ended with `Broken pipe` or waited | BIND was reached and acknowledged, but no share row was returned; request opnum is `0x000f` | Superseded by NDR implementation |
| 2026-08-19 14:30 | Implemented first NDR32 `NetrShareEnum` response path for DCE/RPC REQUEST opnum `0x000f`; encodes one configured `SHARE_INFO_1` share (`ESP32`) and returns it through SMB2 `FSCTL_PIPE_TRANSCEIVE` output | ESP-IDF v6.0.2 `idf.py build` succeeds; binary generated; hardware validation and NDR interoperability remained pending | Implemented, hardware validation pending |
| 2026-08-19 14:44 | Corrected NDR `SHARE_INFO_1` deferred-pointer ordering: name pointer, share type, remark pointer now precede deferred UTF-16 string data | Previous hardware run sent `NetrShareEnum response` but macOS returned `Broken pipe` after waiting; ESP-IDF v6.0.2 build succeeds | Implemented, hardware validation pending |
| 2026-08-19 14:49 | Added temporary full DCE/RPC response dump for `NetrShareEnum` to diagnose the remaining macOS NDR parsing failure | ESP-IDF v6.0.2 `idf.py build` succeeds; hardware validation pending | Diagnostic probe |
| 2026-08-19 14:53 | Corrected NDR `SHARE_INFO_1` share-name encoding to include the required null-terminated UTF-16LE code unit and adjusted conformant string counts | ESP-IDF v6.0.2 `idf.py build` succeeds; hardware validation pending | Implemented, hardware validation pending |
| 2026-08-19 15:13 | Rebuilt the NetrShareEnum stub from Samba `srvsvc.idl`: level 1, `NetShareCtr1`/`NetShareInfo1`, deferred name/comment strings, totalentries, null resume handle, and WERROR in IDL order | ESP-IDF v6.0.2 `idf.py build` succeeds; hardware validation pending | Implemented from reference, hardware validation pending |
| 2026-08-19 15:45 | Fixed remark string NDR encoding: changed from `(max_count=1, offset=0, actual_count=1)` + null terminator to `(max_count=0, offset=0, actual_count=0)` for empty string conformant varying array | Build succeeds; hardware test shows NetrShareEnum response sent (104 bytes) but macOS still reports `Broken pipe` after close, suggesting NDR unmarshaling still fails | Attempt 1: response structure correct but content rejected |
| 2026-08-19 16:00 | Revised deferred pointer strategy: changed all pointer markers from incrementing values `(0x00020000, 0x00020004, 0x00020008, 0x0002000c)` to uniform `0x00020000` for all union/struct pointers | Build succeeds; hardware test shows identical response but macOS still returns `Broken pipe`; client closes pipe immediately after receiving response instead of parsing it | Attempt 2: pointer uniformity did not fix NDR unmarshaling rejection |
| 2026-08-19 16:15 | Implemented pipe response buffering: (1) IOCTL handler queues NetrShareEnum response into `pipe_response` buffer instead of returning in IOCTL output; (2) READ handler checks buffer and returns data in chunks; (3) CLOSE handler frees buffer via existing `smb_session_release()`. Rationale: macOS pipes expect stream semantics (fragments), not one-shot responses | ESP-IDF v6.0.2 `idf.py build` succeeds | Attempt 3: buffering strategy rejected by client. Client sees IOCTL output_count=0 and closes pipe immediately without READ. Reverted. |
| 2026-08-19 16:30 | Reverted buffering; returned to direct IOCTL response (92-byte NDR NetrShareEnum). Built and flashed. | Device logs: NetrShareEnum response sent (92 bytes); client responds with ECHO pings (cmd=0x0d) then timeout disconnect. smbutil output: still "Broken pipe" | **BLOCKING ISSUE CONFIRMED**: NDR response structure is sent (92 bytes) but macOS NDR unmarshaler rejects it. Client cannot parse the response and closes connection. Root cause: NDR encoding mismatch with Samba/Windows expectations. Proceeding with QUERY_DIRECTORY/disk operations; returned to NetrShareEnum debugging after validating core file I/O. |
| 2026-08-19 17:45 | **Attempt 4 (Complete MS-SRVS Rewrite):** Rewrote NetrShareEnum from MS-SRVS specification: proper SHARE_ENUM_STRUCT with level discriminator, union discriminator, SHARE_CTR1 pointer to array, SHARE_INFO_1 base (NetName ptr, Type=0, Remark ptr), deferred conformant varying arrays for strings, output parameters (TotalEntries, ResumeHandle, Status), and reconstructed DCE/RPC RESPONSE header | Build succeeds (925 KB); hardware test: protocol succeeds NEGOTIATE→SESSION_SETUP→TREE_CONNECT→CREATE; Finder error "There was a problem connecting to the server"; share does not appear in browser | Attempt 4: FAILED — macOS still rejected the NDR response despite following the MS-SRVS spec; fixed in the row below |
| 2026-08-19 17:15 | QUERY_DIRECTORY handler (0x0e) implemented | SMB2 command routing added; FILE_ID_BOTH_DIRECTORY_INFORMATION (level 104) encoding with readdir(); Unix-to-FILETIME conversion; 8-byte entry alignment; STATUS_NO_MORE_FILES (0x80000006); path length validation | ✅ Build succeeds; firmware 925 KB; ready for hardware test |
| 2026-08-19 17:30 | QUERY_DIRECTORY stack-optimized & hardware validated | Stack overflow fixed: reduced buffers from ~1KB to ~256 bytes per loop. Direct UTF-16LE encoding to response buffer instead of intermediate 256-byte buffer. Client successfully connects and mounts share. No crash. | ✅ Finder mounts smb://192.168.12.2/ESP32 successfully; ECHO keepalives working; clean disconnect |
| 2026-08-19 18:00 | **Tree Connect path validation fix:** Added share name validation to Tree Connect handler. Disk shares now MUST contain the configured share name (`ESP32`). Return STATUS_OBJECT_NAME_NOT_FOUND (0xc0000034) for invalid paths. Assign tree_id=0 on error, tree_id=1 on success. Send header-only response on errors. | Build succeeds; hardware test: Tree Connect correctly accepts `\\ESP32 SMB Server._smb._tcp.local\ESP32` (status=0x00000000, tree_id=1); mount_smbfs still failed with "Operation not permitted" | ✅ Tree Connect validation working; mount_smbfs still blocked pending the NetrShareEnum fix below |
| 2026-08-21 09:15 | **NDR `SHARE_INFO_1_CONTAINER` layout fix:** Corrected the `NetrShareEnum` IOCTL response encoding to include the previously-missing `EntriesRead` field and `Buffer` conformant-array `MaximumCount` header before the `SHARE_INFO_1` array (both had been skipped, shifting every following field by 8 bytes and corrupting the NDR stream) | Build succeeds; hardware test: `smbutil view -G '//guest@192.168.12.2'` now completes and prints `ESP32  Disk` — "1 shares listed", no Broken pipe | ✅ **RESOLVED** — NetrShareEnum NDR encoding now interoperable with macOS |
| 2026-08-21 09:45 | **Stack overflow crash fix:** `smb_protocol_client_handler` task was created with only 6144-byte stack but allocated two 8192-byte buffers (16 KB) plus context on the stack — guaranteed overflow causing `Guru Meditation Error (InstrFetchProhibited)` crashes in `lwip_recvfrom` on client connect. Changed `request_buffer`/`response_buffer` to heap allocation (`malloc`/`free`) instead of stack arrays | Build succeeds; hardware test: `smbutil view -G '//guest@192.168.12.2'` completed cleanly (msg_id 0-20, ECHO keepalives from t=24885ms to t=134705ms), no crash, no Guru Meditation | ✅ **RESOLVED** — hardware validated, no more stack-overflow crash |

### Phase 3 — Finder/macOS Kernel-Mount (`mount_smbfs`) Interoperability & Full Disk I/O Validation (done, merged from former Fase4 continuation)

| Date & Time | Work Done | Evidence | Status |
|-----------|-----------|----------|--------|
| 2026-08-21 13:10 | **Investigated `mount_smbfs`/Finder-sidebar mount failures** ("Operation not permitted" / "Operation timed out") despite Tree Connect + CREATE succeeding on the wire (confirmed via tcpdump capture and macOS unified log). macOS's kernel `smbfs` mount path (`smb_mount()`) fails/times out client-side even though our SMB2 responses are well-formed; a wire capture showed the CREATE request includes an `"MxAc"` (Query Maximal Access) create-context that our server silently ignored (spec-legal, but a plausible reason the kernel client stalls). Added CREATE-context parsing + an `MxAc` response (`smb_protocol_create_request_wants_mxac`, `smb_protocol_append_mxac_context`) returning `MaximalAccess=0x001f01ff` when requested | Build succeeds; hardware validation of whether this resolves `mount_smbfs`/Finder-sidebar mounting is pending | Implemented from wire-capture evidence, hardware validation pending |
| 2026-08-21 13:20 | **MxAc fix retested — did not resolve `mount_smbfs` timeout.** CREATE response now correctly includes the 32-byte MxAc context (184 bytes total sent), but `mount_smbfs` still fails identically. Diagnosed with `log stream --predicate 'process == "mount_smbfs"'`: `smb_mount()` is called, then **exactly 122 seconds later** fails with `syserr = Operation timed out`, with **zero** further client-side log activity or wire traffic in between (ESP32 session stays healthy with ECHO keepalives throughout) | Confirms this is a fixed ~122s internal timeout in the macOS kernel `smbfs` mount(2) path itself, not caused by any specific missing SMB2 response field | ⚠️ Root cause still open at this point; fixed in the row below |
| 2026-08-22 | **Root cause found: SMB2 request compounding was not implemented.** Wire log showed the kernel `mount_smbfs` path sends chained sub-commands (e.g. CREATE+QUERY_INFO+CLOSE) in a single TCP payload via each header's `next_command` offset; the server only ever processed the first sub-command and silently dropped the rest, so the client waited forever for a response to the chained command it never got — explaining the fixed ~122s kernel timeout. Refactored `smb_protocol_process_request` into a loop over chained sub-commands: added `smb_protocol_related_file_id_offset()` to substitute the FileId of `SMB2_FLAGS_RELATED_OPERATIONS` sub-commands with the FileId from the preceding CREATE in the same chain, built padded (8-byte aligned) chained responses with correct `next_command` offsets | Build succeeds; hardware test: device log shows CREATE(compound)+QUERY_INFO(compound)+CLOSE all parsed and answered in one 372-byte response; no more 122s hang, clean TREE_DISCONNECT within ~300ms | ✅ **RESOLVED** — compounding hang fixed; `mount_smbfs` now fails fast with a new, different error: `"Operation not supported"` |
| 2026-08-22 14:00 | **Diagnosed new fast-fail error via added diagnostic log.** Added a log line printing `info_type`/`info_class` in `smb_protocol_handle_query_info()`. Confirmed the chained QUERY_INFO in the CREATE+QUERY_INFO+CLOSE sequence requests `info_type=0x02` (`SMB2_0_INFO_FILESYSTEM`), `info_class=3` (`FileFsSizeInformation`) — a filesystem/volume-size query the handler didn't support at all, unconditionally returning `STATUS_NOT_SUPPORTED` for any non-`SMB2_0_INFO_FILE` request, which macOS surfaces verbatim as `"Operation not supported"` | Diagnostic log confirmed exact info_type/info_class values from hardware before implementing a fix | Diagnosis confirmed; root cause identified |
| 2026-08-23 11:25 | **Implemented `FileFsSizeInformation` support and validated full `mount_smbfs` mount.** Since ESP-IDF's VFS layer has no generic `statvfs()` API for an arbitrary mount point, added a `SMB2_0_INFO_FILESYSTEM`/`FileFsSizeInformation` branch in `smb_protocol_handle_query_info()` that reports static placeholder volume-size values (512 MB total / 256 MB free, 512-byte sectors) — a deliberate design choice (confirmed with user) to keep the component filesystem-agnostic rather than depending on a specific backing FS (e.g. LittleFS) or changing the public `smb_server_config_t` API | Build succeeds; hardware test: `mount_smbfs -N 'smb://guest@192.168.12.2/ESP32' /tmp/esp32test` now succeeds — `mount` shows `//guest:@192.168.12.2/ESP32 on /private/tmp/esp32test (smbfs, ...)`; subsequent traffic shows healthy repeating CREATE+QUERY_DIRECTORY+CLOSE and CREATE+QUERY_INFO+CLOSE polling with no errors | ✅ **RESOLVED** — `mount_smbfs` kernel-path mount fully working; both the compounding hang and the FileFsSizeInformation gap are fixed |
| 2026-08-23 11:31 | **Validated real disk file I/O over the mounted share.** With `/tmp/esp32test` mounted via `mount_smbfs`, ran `ls -la`, `echo "hello esp32" > test.txt`, `cat test.txt`, and `rm test.txt` from the macOS client | Client-side transcript: `ls -la` showed the empty root; `echo`+`cat` round-tripped `hello esp32` correctly; after `rm`, `ls -la` showed the directory empty again | ✅ **RESOLVED** — CREATE (with write access), WRITE, READ, and delete-on-close (SET_INFO `FileDispositionInformation` + CLOSE) all validated end-to-end on hardware |
| 2026-08-23 11:35 | **Validated directory create/delete and multi-chunk file I/O over the mounted share.** Ran `mkdir subdir`, `dd` a 100 KB file, `cp`+`diff` to verify byte-exact readback, then `rm`/`rmdir` from the macOS client | Client-side transcript: `mkdir` and `ls -la` showed the new `subdir`; `dd` wrote 102400 bytes; `diff` against the local copy reported `MATCH`; `rm`/`rmdir` cleaned up successfully | ✅ **RESOLVED** — directory CREATE/QUERY_DIRECTORY/delete and multi-PDU READ/WRITE (100 KB spans several SMB2 READ/WRITE requests) validated end-to-end on hardware |

### Phase 4 — Finder GUI Directory Listing Bug (in progress — command-line `mount_smbfs` works, Finder GUI does not yet show files)

Despite Phase 3's `mount_smbfs`/command-line validation passing, the user reported that files placed in the `ESP32` share (`hello.txt`, `notes/`, `welcome.txt`) still do not appear when browsing the mounted share through the Finder GUI, even though the device log shows correct QUERY_DIRECTORY responses being built and sent.

| Date & Time | Work Done | Evidence | Status |
|-----------|-----------|----------|--------|
| 2026-08-23 (session) | Fixed invalid `file_info_class` check and two response-corruption bugs (a broken `NextEntryOffset` backpatch loop, and a mis-positioned `FileId` field) in the QUERY_DIRECTORY response encoder | Build succeeds | Fixed, but user reported "Helaas! Nog steeds niet!" (still not working) — Finder still showed no files |
| 2026-08-23 (session) | Root-caused and fixed: QUERY_DIRECTORY handler ignored the `SL_RETURN_SINGLE_ENTRY` (0x02) request flag (MS-SMB2 2.2.33) and always packed every directory entry into one response, even when the client's first query explicitly asked for exactly one entry (`flags=0x03`) — a protocol violation that is a plausible reason for macOS to silently discard the response. Added `SL_RESTART_SCAN`/`SL_RETURN_SINGLE_ENTRY` flag handling and a `break` after the first entry when single-entry mode is requested | Build succeeds; latest hardware log confirms the fix is active (`flags=0x03` now correctly returns exactly 1 entry / 128 bytes instead of all 3) | Confirmed on the wire; user reports the overall symptom ("still not working") persists — root cause of the remaining Finder GUI display issue is still open |
| 2026-08-23 14:27 | Documentation consolidation: merged `fase2Plan.md` into this Patch Log, renamed `Fase*` headings to `Phase *`, combined phases that are proven to work into single tables, removed `fase2Plan.md` | N/A (docs only) | Done |
| 2026-08-24 11:54 | **Root-caused Finder GUI directory-listing bug: invalid `FileAttributes` value in QUERY_DIRECTORY entries.** `smb_protocol_handle_query_directory()` set `FileAttributes = 0` for regular files (`smb_protocol.c:840`), which is not a valid Windows/SMB2 attribute value — a plain file must have at least `FILE_ATTRIBUTE_NORMAL` (`0x80`) set. The existing QUERY_INFO/CREATE code path (`smb_protocol.c:585`) already used `S_ISDIR(...) ? 0x10 : 0x80` correctly; the directory-listing encoder was inconsistent with it. Changed line 840 to match. Command-line `mount_smbfs`/`ls` tolerated the invalid value (explaining why Phase 3 validation passed), but Finder's own GUI listing silently discarded every entry with attributes=0 | `idf.py build` succeeds in `examples/basic` (53% partition free); hardware re-test in Finder GUI still pending | Fix applied, hardware validation pending |
| 2026-08-24 (session) | **FileAttributes fix retested on hardware — GUI mount now succeeds, but multi-entry `ls` fails with `fts_read: RPC struct is bad`.** With 3 root entries (`hello.txt`, `notes`, `welcome.txt`), the kernel `mount` succeeded (`//guest:@192.168.12.2/ESP32 on /Volumes/ESP32`), but `ls -la` returned `total 0` then `fts_read: RPC struct is bad` (EBADRPC) — the same generic macOS SMB "malformed response" error previously seen during `NetrShareEnum`, now surfacing on QUERY_DIRECTORY with >1 entry. Wire-level math for the 376-byte, 3-entry `FILE_ID_BOTH_DIR_INFORMATION` buffer and `NextEntryOffset` backpatch chain checked out correctly by hand (128+120+128=376). Found and fixed one genuine wire defect: the 8-byte alignment gap after each entry's filename (e.g. 4 padding bytes after `hello.txt`, 4 after `notes`) was never zeroed — `response_buffer` is a heap buffer reused across requests without clearing, so those "unspecified" padding bytes carried leftover garbage from a prior response onto the wire. Added a `memset` of the gap in `smb_protocol_handle_query_directory()` right after each entry's filename is written | `idf.py build` succeeds in `examples/basic` (53% partition free, binary 0xe1f90 bytes); hardware re-test of `mount` + `ls -la` with all 3 entries still pending | Fix applied, hardware validation pending — this is the first case multi-entry QUERY_DIRECTORY responses have been exercised via the kernel mount path (earlier Phase 3 multi-entry listings likely only had 1 entry present at test time) |
| 2026-08-24 12:10 | **Root-caused via packet capture: `smb_protocol_build_header_response()`'s internal `memset(body, 0, body_length)` wiped out response bodies that were written into the buffer *before* the helper was called with the real body length.** Hit in three handlers — `smb_protocol_handle_query_directory` (directory entries), `smb_protocol_handle_read` (file data), and `smb_protocol_handle_query_info` (both the `FileFsSizeInformation` and generic-file-info branches) — explaining the persistent `fts_read: RPC struct is bad` / empty Finder listings, and would also have zeroed all file-read content. Fixed all three call sites by passing `body_length=0` and setting `*response_length` manually after writing the body | `idf.py build` succeeds; hand-decoded `~/tmp/smb_capture.txt` (tcpdump `-X -nn`) confirmed the zeroed bytes before the fix | ✅ **RESOLVED** — hardware retest: Finder shows real file listings for the first time |
| 2026-08-24 12:40 | **Fixed TCP partial-frame data loss in the client receive loop.** After the memset fix, browsing triggered a reconnect loop with `"Incomplete trailing NetBIOS frame ... discarding"` — the receive loop discarded any SMB2 request that arrived split across multiple `recv()` calls instead of buffering the partial frame. Added persistent `buffered_len` tracking across loop iterations with `memmove()`-based preservation of the leftover partial frame, plus a full-buffer-with-no-complete-frame disconnect guard | `idf.py build` succeeds | ✅ **RESOLVED** — no more reconnect loop on multi-segment requests |
| 2026-08-24 13:05 | **Fixed ignored QUERY_DIRECTORY search pattern.** `SL_RESTART_SCAN\|SL_RETURN_SINGLE_ENTRY` (flags=0x03) probes carry a client search filename (MS-SMB2 2.2.33 `FileName`/`FileNameLength`), which was parsed into the wire struct but never applied — every single-entry probe returned whatever `readdir()` yielded first, so Finder polling for a specific not-yet-seen file spun forever. Added `smb_protocol_wildcard_match()` (case-insensitive DOS `*`/`?` matching) and filtered `readdir()` entries against the parsed search pattern | `idf.py build` succeeds; hardware log confirms probes for `hello.txt`/`welcome.txt` now match correctly instead of always returning the first directory entry | ✅ **RESOLVED** |
| 2026-08-24 13:35 | **Fixed delete failing with `esp_littlefs: Has open FD`.** `smb_protocol_handle_close()` called `unlink()`/`rmdir()` on a delete-pending handle *before* releasing the session handle — but `smb_session_release()` is what closes the underlying fd, so the delete ran while the file was still open and `esp_littlefs` correctly refused. Reordered to release (closing the fd) first, then delete | `idf.py build` succeeds | ✅ **RESOLVED** — delete no longer logs the LittleFS "Has open FD" error |
| 2026-08-24 13:50 | **Fixed `rm` still reporting `RPC struct is bad` after a successful delete.** Once delete-then-release order was fixed, the CLOSE response for a just-deleted file zeroed its attribute fields (`have_stat = false` after a successful unlink) — the very case the handler's own comment warns about ("macOS's kernel client rejects a CLOSE response with all-zero attributes"). Kept sending the pre-delete `stat()` already captured earlier in the function instead of discarding it | `idf.py build` succeeds | Fix applied; retest still showed the error, root cause found in next row |
| 2026-08-24 14:05 | **Found the actual `RPC struct is bad` root cause via a second packet capture: `smb_protocol_handle_set_info()` never wrote the required `StructureSize=2` field into its SET_INFO response body**, leaving it zeroed by the header helper's memset — a spec violation (MS-SMB2 2.2.39) that macOS surfaces as a malformed-response error. Since `rm` is the only client operation that goes through SET_INFO (`FileDispositionInformation`), this explains why deletes specifically failed while every other operation (browsing, reading, CREATE/CLOSE) worked. Added the missing `smb2_put_u16_le(body, 2)` write | `idf.py build` succeeds; hand-decoded `~/tmp/smb_capture2.txt` showed bytes `00 00` where `02 00` was required; hardware retest: `rm` on root-level and nested files now completes cleanly with no client-side error | ✅ **RESOLVED** — delete (`rm`) fully working end-to-end |

**Next diagnostic steps (continuing next session):** all files/dates in `ls -la` currently show identical epoch timestamps (`Jan 1 1970`) instead of real mtimes — parked, not yet investigated; likely in how `smb_vfs_stat()`/ESP-IDF's LittleFS VFS layer reports `st_mtime`, since `smb_vfs_stat()` itself is a bare passthrough to POSIX `stat()`.

### Phase 5 — Cross-Platform Validation & Remaining Protocol Robustness (pending)

Backlog carried over from `fase2Plan.md`'s "remaining protocol robustness" and "not yet done" sections, plus the original cross-platform milestone. Suggested logical order:

1. Resolve the open Finder GUI directory-listing issue (Phase 4) and the "copy does nothing / no WRITE command" symptom.
2. Add a proper FLUSH handler (header-only success response).
3. Handle currently-unsupported SMB2 commands with a well-formed protocol response instead of silent drops, where the spec expects one.
4. Review compound-request/credit handling and partial-TCP-read robustness under load (multiple concurrent clients, larger compound chains).
5. Trim the temporary diagnostic packet dumps that were added while debugging NDR/compounding issues, now that those are resolved.
6. Add full DCE/RPC REQUEST/RESPONSE pipeline test coverage beyond `NetrShareEnum` (e.g. additional opnums if/when needed).
7. SMB 3.1.1 Negotiate Context support (currently out of scope; dialect stays pinned to SMB 2.0.2) — revisit only if a target client requires it.
8. Cross-platform validation: Windows `net view`/Explorer, Linux `mount -t cifs`, iOS SMB clients (FileBrowser, etc.) — per the Validation Criteria section above.

| Date & Time | Work Done | Evidence | Status |
|-----------|-----------|----------|--------|
| 2026-08-24 15:10 | **iOS SESSION_SETUP fix: wrapped the raw NTLM challenge in a proper SPNEGO/GSS-API `NegTokenResp` ASN.1 envelope.** macOS's `smbfs` tolerated the raw, unwrapped NTLMSSP blob sent by `smb_protocol_handle_session_setup()`, but iOS's stricter SMB client rejected it outright (`"Unknown ASN1 Class identifier"`) and dropped the connection before completing auth. Added the `[1] NegTokenResp { negState, supportedMech (NTLMSSP OID), responseToken }` wrapper around the existing NTLM challenge bytes | `idf.py build` succeeds; hardware retest: iOS `SESSION_SETUP` now completes (`status=0x00000000`) and proceeds through `IPC$`/DCE-RPC/`NetrShareEnum` cleanly | ✅ **RESOLVED** — iOS auth handshake works |
| 2026-08-24 15:40 | **Added the mandatory 8-byte MS-SMB2 Error Response body to all non-success responses.** `smb_protocol_build_header_response()` was sending header-only (64-byte) responses for every error status, omitting the required `StructureSize=9/ErrorContextCount/Reserved/ByteCount` tail (MS-SMB2 2.2.2). macOS tolerated this; suspected as the source of iOS's on-screen `"Data loop, have N bytes, need 72"` client error. Fixed centrally in the shared helper so every error path benefits | `idf.py build` succeeds | Fix applied; did **not** resolve the iOS `TREE_CONNECT`→disconnect symptom on retest (that TREE_CONNECT actually returned `STATUS_SUCCESS`, no error body involved) — real root cause found in the row below. Kept as a genuine spec-compliance fix regardless |
| 2026-08-24 16:10 | **Root-caused the iOS (and Mac) "crash"/disconnect right after `TREE_CONNECT` to the real `ESP32` disk share: the legacy SMB1→SMB2 negotiate handshake was pinning every connection to the oldest SMB2 dialect (0x0202).** Nearly all modern clients start with an SMB1-framed multi-protocol negotiate offering the generic `"SMB 2.???"` wildcard; `smb_protocol_handle_legacy_negotiate()` treated *any* `"SMB 2.*"` offer as a hard commitment to dialect 0x0202 instead of replying with the standard wildcard `0x02FF` (which should prompt the client to send a real `NEGOTIATE` with its full dialect list). Apple's SMB client (shared between iOS/macOS) accepts 0x0202 for anonymous share browsing (`IPC$`) but refuses real file-data access over it, silently abandoning the connection right after a successful `TREE_CONNECT` — matching every capture exactly (`IPC$` always fully works; the `ESP32` disk-share `TREE_CONNECT` succeeds, then the client vanishes before `CREATE`). Added `SMB2_DIALECT_2FF` and changed the legacy path to reply with it, letting the client's follow-up real `NEGOTIATE` select a modern dialect (up to 0x0302) via the already-working selection logic | `idf.py build` succeeds (0xe2200 bytes, 53% free) | Fix applied; hardware retest **falsified this hypothesis** — added diagnostic dialect logging confirmed the client now genuinely selects `0x0210` (not `0x0202`), yet the identical `TREE_CONNECT`→silent-disconnect symptom persisted. Kept as a genuine spec-compliance fix regardless; real root cause found in the row below |
| 2026-08-24 16:45 | **Root-caused (log-evidenced, but ultimately falsified): `smb_protocol_handle_tree_connect()` hardcoded `tree_id = 1` for every successful `TREE_CONNECT`, and a single global `bool ipc_tree` flag on the connection tracked "is the current tree IPC$?" instead of per-tree state.** Hardware log showed the iPhone opening **two** `IPC$` `TREE_CONNECT`s (msg_id 4 and 5), both receiving `tree_id=1`, with only **one** `TREE_DISCONNECT` (msg_id 10) sent back before the `ESP32` disk-share `TREE_CONNECT` (msg_id 11) reused that same colliding `tree_id=1` — a genuine MS-SMB2 2.2.9 violation, plausible cause of the client aborting right after that response. Replaced the single global flag with a `smb_protocol_tree_t trees[SMB_SERVER_MAX_TREES]` per-connection table (`tree_id`, `in_use`, `is_ipc`) plus a monotonic `next_tree_id` counter; `TREE_CONNECT` now allocates a free slot with a unique id, `TREE_DISCONNECT` frees the matching slot, `CREATE`'s `srvsvc`-pipe check looks up the table instead of the stale global flag | `idf.py build` succeeds (0xe22f0 bytes, 53% free) | Fix applied; hardware retest **falsified this hypothesis too** — tree ids came back correctly unique (1, 2, 3) but the identical disconnect persisted. Kept as a genuine spec-compliance fix; real root cause found in the row below |
| 2026-08-24 17:15 | **Root-caused via a cheap own-side hex dump (no packet capture needed): `smb_protocol_handle_tree_connect()` builds its own `smb2_header_t` from scratch and never sets `session_id`, so every `TREE_CONNECT` response — including the two working `IPC$` ones — was sent with `session_id=0` instead of echoing the real session id.** Every other response path (`smb_protocol_build_header_response()`) correctly echoes `ctx->last_request_header.session_id`; only this one hand-built header skipped it. Apple's SMB client evidently tolerates `session_id=0` on anonymous `IPC$` tree responses but rejects it once it's about to trust a tree for real file I/O, silently closing the connection right after `TREE_CONNECT` — matching every capture exactly. Confirmed via `ESP_LOG_BUFFER_HEXDUMP` of the outgoing response bytes on our own side (added, then compared the working vs. failing 80-byte responses field-by-field): bytes 40–47 (SessionId) were `00 00 00 00 00 00 00 00` in both. Fixed by adding `resp_header.session_id = ctx->last_request_header.session_id;` | `idf.py build` succeeds (0xe25d0 bytes, 53% free) | Fix applied; hardware retest **falsified this hypothesis too** — hex dump confirms `session_id=1` is now correctly set in every `TREE_CONNECT` response, but the identical "Data loop, have 72 bytes, need 72" disconnect on the iOS client persists unchanged. Kept as a genuine spec-compliance fix; real root cause still open (see below) |
| 2026-08-24 (session) | **Client identified: the failing iOS app is "File Browser" (third-party App Store app), not Apple's native Files/SMBClient framework.** Re-scoping the investigation — prior rows' assumption of "Apple's SMB client" behavior does not apply here; this app has its own SMB2 client implementation of unknown provenance, so Apple SMBClient/smbfs kernel source is not a valid reference for its parsing logic. All 5 prior hypotheses (dialect pinning, missing error body, tree_id collision, session_id=0) are hardware-falsified. The outgoing `TREE_CONNECT` response is now confirmed byte-correct against the MS-SMB2 spec and format-identical to the working `IPC$` responses (only `tree_id`/`message_id`/`share_type` legitimately differ). No further server-side hypothesis is evidenced by current logs | N/A (investigation checkpoint, no code change) | **Paused by user decision** — no more code-only leads; user chose to pause this specific bug (iOS "File Browser" app disconnecting after real disk-share `TREE_CONNECT`) rather than keep spending tokens on unverified guesses. Resume with either a different iOS SMB client, a macOS Finder GUI retest, or a targeted capture, if/when the user wants to pick it back up |
| 2026-08-24 (session) | **Found and fixed a new regression via the "Filer" app and `mount_smbfs` both failing after `SESSION_SETUP`: `smb_protocol_handle_session_setup()` computed `security_token_offset = SMB2_HEADER_SIZE + 9`, but the fixed SESSION_SETUP response body (StructureSize+Flags+SecurityBufferOffset+SecurityBufferLength) is only 8 bytes — the `9` is the *declared* `StructureSize` field value (spec convention: fixed-size+1), mistakenly reused as a byte offset.** Confirmed via `ESP_LOG_BUFFER_HEXDUMP` of the outgoing response: body byte 8 (absolute offset 72) was never written (leftover stack garbage, `0x53` in the capture), and the real SPNEGO/NTLM challenge blob (`a1 77 30 75...`) was shifted one byte late to offset 73. A client that trusts the `SecurityBufferOffset` field (iOS Files app) still finds it fine; a client that assumes the buffer starts immediately after the fixed body (`mount_smbfs`, "Filer") reads the garbage byte first, fails ASN.1 parsing, and aborts with `LOGOFF` — matching every symptom from both clients. Also separately fixed: `ctx->session_setup_started` was never reset on `LOGOFF`, so a retry `SESSION_SETUP` on the same TCP connection was wrongly treated as leg-2 and got a premature `STATUS_SUCCESS`; added `ctx->session_setup_started = false` in the `LOGOFF` case | `idf.py build` succeeds (0xe25e0 bytes, 53% free) | Both fixes confirmed byte-correct via a second hex dump (no gap byte, SPNEGO token starts exactly at the declared offset) — but `mount_smbfs`/"Filer" still sent `LOGOFF` immediately after this now-correct leg-1 response, never attempting leg-2. Real root cause found in the row below |
| 2026-08-25 (session) | **Root-caused: the server always replied to `SESSION_SETUP` with a SPNEGO/GSS-API-wrapped NTLM challenge, but `mount_smbfs` and "Filer" send a bare, unwrapped `NTLMSSP\0` negotiate token (confirmed via a hex dump of the client's own incoming security buffer) — mismatched envelope format, not a byte-offset error.** iOS "Files" needs the SPNEGO wrapper (rejects raw NTLMSSP); `mount_smbfs`/"Filer" need the raw form (as in the original Phase 3 implementation, before the SPNEGO wrap was added for iOS). Fixed by detecting which form the client sent (`memcmp` of the first 8 bytes against `"NTLMSSP\0"`) and mirroring it back: SPNEGO-wrapped `NegTokenResp` for SPNEGO-wrapped requests, the same 94-byte NTLM Challenge unwrapped for bare-NTLMSSP requests | `idf.py build` succeeds (0xe26a0 bytes, 53% free) | ✅ **RESOLVED** — hardware retest: `mount_smbfs` mounts, browses, and reads files; "Filer" completes auth, connects, and lists all folders/files |
| 2026-08-25 11:45 | **Implemented real, spec-correct `SMB2_CHANGE_NOTIFY` (0x0f) async support — a deliberate scope expansion beyond the original "Explicitly Out of Scope" list (removed from that list above), requested by the user after a hardware log showed the "Filer" app's continuous CREATE+QUERY_DIRECTORY+CLOSE polling caused by the command returning `STATUS_NOT_SUPPORTED`.** Added a small fixed-size global pending-watch table (`SMB_SERVER_MAX_NOTIFY_WATCHES=8`) protected by its own mutex. `CHANGE_NOTIFY` registers a watch on the given directory handle and replies immediately with the MS-SMB2 interim `STATUS_PENDING` async response (`AsyncId` packed into the same wire bytes the sync header uses for `Reserved`/`TreeId`, confirmed via `smb_packet.c`'s codec). `CREATE` (on genuine new-object creation) and `CLOSE` (on a successful delete) call `smb_protocol_notify_fire()`, which marks matching watches fired. Since the ESP-IDF VFS has no filesystem-change-event API and each client connection has only one blocking `recv()`, added a 1-second `SO_RCVTIMEO` to the client socket; a receive timeout now polls the table (`smb_protocol_notify_poll()`) for this connection's fired watches and sends the real final async response (`FILE_NOTIFY_INFORMATION`, MS-FSCC 2.7.1) instead of treating the timeout as a disconnect. Also implemented real `SMB2_CANCEL` (0x0c) handling (previously `STATUS_NOT_SUPPORTED`) so a client-cancelled watch frees its slot immediately rather than waiting for disconnect, and watch cleanup on `TREE_DISCONNECT`/`LOGOFF`/connection-end. **Three accepted spec deviations** (documented in the implementation plan): (1) firing all matching watches on an event rather than strict FIFO-per-handle ordering; (2) `TREE_DISCONNECT` cleanup is connection-wide, not tree-scoped (slots don't track `tree_id`); (3) no `CompletionFilter` bit-matching — fires on any watched-path match regardless of which change types were requested | `idf.py build` succeeds (0xe3140 bytes, 53% free) | Implemented and build-verified; hardware retest with "Filer" (confirm interim `STATUS_PENDING`, real create/delete notifications, and that the CREATE/QUERY_DIRECTORY busy-poll pattern disappears) still pending |
| 2026-08-25 12:33 | **Fixed two CHANGE_NOTIFY bugs found via hardware capture with "Filer" (create+delete round trips): (1) `create_action` was unconditionally forced to `3` (FILE_OVERWRITTEN) for `FILE_OVERWRITE`/`FILE_OVERWRITE_IF`/`FILE_SUPERSEDE` dispositions in the CREATE handler, clobbering the correct `create_action=2` for genuinely new files and silently skipping the ADDED fire-hook; gated the override on `if (exists)`. (2) `smb_protocol_notify_fire()`/`_poll()` used `result_status != 0` as the "has this watch fired?" test, but `STATUS_SUCCESS` is `0x00000000` — the same value as the "still pending" sentinel — so a fired watch was indistinguishable from a never-fired one and `notify_poll()` never delivered the final async response. Added an explicit `bool fired` field to `smb_protocol_notify_watch_t` and updated `notify_register`/`notify_fire`/`notify_cancel`/`notify_poll` to use it instead of the overloaded zero-check.** Root-caused bug (2) required temporary `ESP_LOGI` DEBUG lines at register/fire/poll (added, then fully removed and grep-verified) — evidence showed `matches=1` fires that never changed `result_status` on later poll ticks, and the same watch slot matching two unrelated fire events. See the new "CHANGE_NOTIFY invariants" note under Notes for Developers for the do-not-repeat contract | `idf.py build` succeeds (fixes applied, user builds/flashes manually); hardware retest with a post-fix capture (confirming `"Sent CHANGE_NOTIFY final response"` actually appears) still pending | Fix applied, hardware validation of this specific fix pending |
| 2026-08-25 13:24 | **Phase 5 backlog: fixed a cross-client concurrency bug and added two compound-request hardening guards.** (1) **Concurrency bug**: `s_handles[]` in `smb_session.c` (open file/directory/pipe handles) is a global table, and `SMB2_TREE_DISCONNECT`/`SMB2_LOGOFF` both called the global `smb_session_reset()` — so any one connected client's tree-disconnect or logoff silently closed every *other* client's open handles too, since the server spawns one task per connection but shared this state. Added `owner_socket` to `smb_session_handle_t`, threaded `ctx->socket`/`client_socket` through `smb_session_allocate_file/_directory/_pipe`, and added `smb_session_release_by_socket(int owner_socket)` (mirroring the existing `smb_protocol_notify_release_by_socket()` pattern) to replace the two problematic `smb_session_reset()` call sites (TREE_DISCONNECT/LOGOFF and end-of-connection cleanup). `smb_session_reset()` itself is untouched and still used once at server startup (`smb_server.c`), before any client connects, where a full wipe is correct. (2) **Compound-chain cap**: added `SMB_SERVER_MAX_COMPOUND_COMMANDS=16` and an iteration counter in `smb_protocol_process_request()`'s compound loop, truncating gracefully (same path used for a failed sub-parse) if a malformed/hostile `next_command` chain exceeds it. (3) **`smb2_parse_header()` bounds fix**: the function checked `length < 14` but then unconditionally read fields up to byte 63; gated each field read past byte 14 on `length >= N`, relying on the existing `memset()` zero-fill for unread fields — fixes an out-of-bounds-within-buffer read for short compound sub-frames. (4) Removed three leftover always-on `ESP_LOG_BUFFER_HEXDUMP(..., ESP_LOG_INFO)` diagnostic dumps (Session Setup request/response, Tree Connect response) left over from now-resolved bugs; `smb_protocol_dump_packet()` (already `ESP_LOGD`-gated) remains available on demand. Also confirmed during this pass that the FLUSH handler and graceful `STATUS_NOT_SUPPORTED` responses for unsupported commands were already implemented — no change needed for those two backlog items | `idf.py build` succeeds (user builds/flashes manually) | Fix applied; hardware validation (ideally two clients connected simultaneously, e.g. `mount_smbfs` + "Filer") still pending |
| [to be filled in] | Further cross-platform validation (Windows/Linux) | [Windows/Linux testing] | Pending |

---

## Milestones and Go/No-Go Checkpoints

**End of Phase 1:** ✅ SMB2 packets parse correctly; sessions/trees/files can be allocated and released.

**End of Phase 2:** ✅ `smbutil view -G '//guest@<ESP_IP>'` completes and enumerates shares without `RPC struct is bad`; directory listing and NetrShareEnum work over the wire.

**End of Phase 3:** ✅ `mount_smbfs`/Finder kernel-path mounting works end-to-end; file/directory read, write, create, and delete validated on hardware from the command line.

**End of Phase 4:** ⏳ Files are visible and usable through the Finder **GUI** (not just command-line tools) — currently blocked, see Phase 4 above.

**End of Phase 5:** All validation criteria pass on Windows, Linux, and iOS, and the remaining protocol-robustness backlog is cleared.

---

## Notes for Developers

- Keep protocol implementation independent from VFS layer (swap VFS for LittleFS, FatFS or other FS later)
- Use ESP_LOGI/ESP_LOGW/ESP_LOGE for all logging (no printf)
- Prefix comments with `//--` (project convention)
- Use Allman brace style and 2-space indentation
- Test frequently on hardware; do not assume compilation implies correctness
- Do NOT skip security validation (path traversal checks, buffer overflows, etc.)

### CHANGE_NOTIFY invariants (do not reintroduce these two bugs)

The `SMB2_CHANGE_NOTIFY` pipeline (`smb_protocol_notify_register/_fire/_cancel/_poll` in
`smb_protocol.c`) has two invariants that were each broken once and are easy to break again
while working on unrelated CREATE/CLOSE code:

1. **A notify watch's "has this fired?" state MUST be tracked with the dedicated `bool fired`
   field on `smb_protocol_notify_watch_t` — never by checking `result_status` against `0`.**
   `STATUS_SUCCESS` is `0x00000000`, so a zero-check collides with "still pending" and silently
   swallows every final CHANGE_NOTIFY response. If you touch `notify_register`/`notify_fire`/
   `notify_cancel`/`notify_poll`, all four must keep reading/writing `fired`, and `result_status`
   must only be read once `fired == true`.
2. **`create_action` in the CREATE handler must stay `2` (FILE_CREATED) for a genuinely new file,
   even when the request's disposition is `FILE_OVERWRITE`/`FILE_OVERWRITE_IF`/`FILE_SUPERSEDE`.**
   Only force `create_action = 3` (FILE_OVERWRITTEN) when the file already `exists`. The
   fire-on-create hook (`if (create_action == 2) smb_protocol_notify_fire(..., FILE_ACTION_ADDED, ...)`)
   depends on this value being accurate — an unconditional override here silently breaks ADDED
   notifications for any client that opens new files with an overwrite-style disposition (e.g.
   the "Filer" iOS app).
