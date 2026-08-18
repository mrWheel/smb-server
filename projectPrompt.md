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
- Change notifications
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

### Fase1 (Patches)

| Date/Time | Work Done | Evidence | Status |
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

### Fase2 (Patches)

| Date/Time | Work Done | Evidence | Status |
|-----------|-----------|----------|--------|
| 2026-08-18 13:56-14:34 | Implemented Phase 2 disk/session foundation: UTF-16LE path decoding, traversal-safe VFS resolution, file/directory/pipe handles, mutex protection, delete-on-close state, CREATE/CLOSE/READ/WRITE/QUERY_INFO/SET_INFO handlers, NTSTATUS mapping, cleanup, and corrected SMB2 CREATE offsets | Repeated ESP-IDF v6.0.2 builds succeed; authentication and disk-share CREATE/root handling are reached on hardware | Implemented; file I/O and directory listing still need hardware validation |
| 2026-08-18 13:56-15:02 | Fixed SMB2 wire foundation: true SMB2 signature `fe 53 4d 42`, packed structures, correct negotiate body (`ServerGuid`, sizes, times, offsets), credits, ECHO, and response serialization | `smbutil` progresses beyond negotiate/session setup; previous `RPC struct is bad` and credit stalls are resolved | Implemented |
| 2026-08-18 13:56-14:24 | Added SMB1 multi-protocol negotiate bridge: accept initial SMB1 `ff 53 4d 42` negotiate only when it offers SMB2 (`SMB 2.002`), then continue as SMB2 dialect `0x0202`; SMB1 operations remain unsupported | Device logs `SMB1 negotiate offered SMB2`; SMB2 response uses `fe 53 4d 42` | Implemented by design |
| 2026-08-18 14:07-14:31 | Implemented guest authentication interoperability: raw NTLMSSP type-1 detection, raw type-2 challenge, target name `ESP32`, target-info AV-pairs, two-step status flow, final `IS_GUEST` flag, and diagnostic token logging | Hardware reaches `STATUS_MORE_PROCESSING_REQUIRED`, receives NTLMSSP type 3, then gets `STATUS_SUCCESS` and proceeds to Tree Connect | Implemented; cryptographic validation is intentionally guest-only |
| 2026-08-18 14:45-15:02 | Added IPC$ routing: recognize `\\host\IPC$`, return pipe share type, and allocate `srvsvc` as a named-pipe handle instead of `/littlefs/srvsvc` | Hardware reaches `CREATE srvsvc pipe` and continues to `FSCTL_PIPE_TRANSCEIVE` | Implemented |
| 2026-08-18 14:47-15:15 | Added SMB2 IOCTL/pipe flow and DCE/RPC BIND support: log IOCTL input, recognize `0x0011c017`, return a 56-byte NDR32 `BIND_ACK`, handle ECHO/credits, and avoid abrupt socket closes | Hardware logs `DCE/RPC BIND acknowledged` and sends a 168-byte IOCTL response | Implemented; pipe buffering/REQUEST response still pending |
| 2026-08-18 15:12-15:15 | Current blocker: DCE/RPC REQUEST for `NetrShareEnum` is not implemented; empty pipe READ currently returns EOF, so `smbutil` can show the share header but ends with `Broken pipe` or waits | BIND is reached and acknowledged, but no share row is returned; next request is RPC opnum `0x000f` | Next: implement NDR `NetrShareEnum` response |

### Fase3 (Patches)

| Date/Time | Work Done | Evidence | Status |
|-----------|-----------|----------|--------|
| [to be filled in] | Phase 2: Disk share access (CREATE, CLOSE, READ, WRITE, QUERY_INFO) | [smbutil view completion, Finder mount] | Pending |

### Fase4 (Patches)

| Date/Time | Work Done | Evidence | Status |
|-----------|-----------|----------|--------|
| [to be filled in] | Phase 3: Directory enumeration (QUERY_DIRECTORY) | [Finder directory listing] | Pending |

### Fase5 (Patches)

| Date/Time | Work Done | Evidence | Status |
|-----------|-----------|----------|--------|
| [to be filled in] | Phase 4: srvsvc/DCE-RPC/NetrShareEnum | [smbutil share enumeration, complete output] | Pending |

### Fase6 (Patches)

| Date/Time | Work Done | Evidence | Status |
|-----------|-----------|----------|--------|
| [to be filled in] | Phase 5: Cross-platform validation | [Windows/Linux/iOS testing] | Pending |

---

## Milestones and Go/No-Go Checkpoints

**End of Phase1:** SMB2 packets parse correctly; sessions/trees/files can be allocated and released.

**End of Phase2:** `smbutil view -G '//guest@<ESP_IP>'` completes without `RPC struct is bad`; the share mounts in Finder and file read/write works. Current status: not yet reached; the client disconnects after negotiate with `RPC struct is bad`.

**End of Phase3:** Directory listing works in Finder.

**End of Phase4:** `smbutil view -G '//guest@<ESP_IP>'` completes and enumerates shares.

**End of Phase5:** All validation criteria pass.

---

## Notes for Developers

- Keep protocol implementation independent from VFS layer (swap VFS for SPIFFS or other FS later)
- Use ESP_LOGI/ESP_LOGW/ESP_LOGE for all logging (no printf)
- Prefix comments with `//--` (project convention)
- Use Allman brace style and 2-space indentation
- Test frequently on hardware; do not assume compilation implies correctness
- Do NOT skip security validation (path traversal checks, buffer overflows, etc.)
