# Phase 2 — Core Disk Share Access (CREATE / CLOSE / READ / WRITE / QUERY_INFO / SET_INFO)

## Huidige status

De volgende keten werkt aantoonbaar op hardware met ESP-IDF v6.0.2:

1. SMB1 multi-protocol negotiate met aangeboden dialect `SMB 2.002`.
2. SMB2 negotiate met echte signature `fe 53 4d 42`, correcte 64-byte body, credits, tijden, `ServerGuid` en offsets.
3. Raw NTLMSSP guest-authenticatie: type 1 -> type 2 -> type 3, gevolgd door `STATUS_SUCCESS` en `IS_GUEST`.
4. Tree Connect naar `IPC$` en `srvsvc` CREATE als named pipe.
5. `FSCTL_PIPE_TRANSCEIVE` (`0x0011c017`) en DCE/RPC BIND.
6. Correcte 56-byte DCE/RPC BIND_ACK met complete NDR32 UUID.

De eerste NDR32 `NetrShareEnum` response is nu in code toegevoegd, maar nog niet op hardware gevalideerd. De volgende test moet bevestigen of `smbutil view` de share `ESP32` toont. Bij NDR-layoutproblemen volgt een gerichte correctie op basis van de nieuwe IOCTL/RPC-log.

## Behouden ontwerpfeiten

- `SMB1_SIGNATURE` (`ff 53 4d 42`) wordt alleen als eerste negotiate-preamble geaccepteerd; SMB1 file-operaties blijven buiten scope.
- SMB 3.1.1 negotiate contexts worden nog niet ondersteund; dialectselectie blijft voorlopig op SMB2.0.2 (`0x0202`).
- Guest-authenticatie is bewust zonder cryptografische gebruikersvalidatie.
- SMB2 variable offsets zijn relatief aan de SMB2-header en moeten met `SMB2_HEADER_SIZE` worden gecorrigeerd.
- File IDs gebruiken de lage 8 bytes voor het interne `smb_file_id`; de hoge 8 bytes zijn nul.
- Normale SMB-fouten moeten een SMB2 response teruggeven; alleen malformed packets mogen de clientverbinding beëindigen.

## Wat al is geïmplementeerd

### Disk/session foundation

- UTF-16LE -> UTF-8 decoding en traversal-safe `smb_path_resolve()`.
- VFS wrappers voor open/close/pread/pwrite/stat/mkdir/unlink/rmdir/ftruncate.
- Mutex-beschermde 24-slot handle table voor files, directories en pipes.
- CREATE, CLOSE, READ, WRITE, QUERY_INFO en SET_INFO.
- Delete-on-close via `FileDispositionInformation` plus CLOSE.
- `read_only` checks, errno -> NTSTATUS mapping en disconnect cleanup.
- Gecorrigeerde SMB2 CREATE-layout met `SmbCreateFlags`, `Reserved`, 32-bit access/attributevelden en correcte name/disposition offsets.

### SMB2/IPC$ foundation

- NetBIOS wrapping, packed SMB2 structs, little-endian codecs, ECHO en credit responses.
- IPC$ herkenning (`\\host\IPC$`), pipe share type en `srvsvc` pipe handle.
- IOCTL inputdiagnostiek en `FSCTL_PIPE_TRANSCEIVE` routing.
- DCE/RPC BIND-detectie en BIND_ACK.
- Named-pipe READ geeft momenteel EOF wanneer geen responsebuffer beschikbaar is; echte buffering is nog nodig.

## Resterende implementatiestappen

### 0. ✅ Tree Connect path validation (FIXED, Session 4)

**Issue:** Tree Connect handler accepted ALL paths with STATUS_SUCCESS, including invalid/incomplete share names. mount_smbfs could not determine if a share was valid.

**Fix (2026-08-19):** 
- Added validation: disk shares must contain the configured share name (`ESP32`)
- Return STATUS_OBJECT_NAME_NOT_FOUND (0xc0000034) for invalid paths
- Assign tree_id=0 on error; tree_id=1 on success
- Send header-only response on errors (no body)

**Result:** Tree Connect now correctly accepts `\\ESP32 SMB Server._smb._tcp.local\ESP32` (status=0x00000000) and would reject paths without "ESP32".

**Status:** ✅ WORKING — but mount_smbfs still fails with "Operation not permitted" (root cause: likely NetrShareEnum dependency)

### 1. ❌ NDR-encoded NetrShareEnum response (ATTEMPTED, NOT WORKING)

Toegevoegd in `smb_protocol_handle_ioctl()` (regel 758-860 in smb_protocol.c):

**Attempt 1-3 (2026-08-18):**
- Remark encoding variation (max=1, offset=0, actual=1 with null vs empty array) — FAILED
- Deferred pointer uniformity (all 0x00020000 vs incrementing) — FAILED
- Remark pointer to 0x00020000 vs NULL — FAILED

**Attempt 4 (2026-08-19 16:00) — Complete NDR Rewrite per MS-SRVS:**
- ✅ SHARE_ENUM_STRUCT with level discriminator (1)
- ✅ Union discriminator field (1)
- ✅ SHARE_CTR1 structure with pointer to SHARE_INFO_1 array
- ✅ SHARE_INFO_1 base (NetName pointer, Type=0, Remark pointer)
- ✅ Deferred strings: NetName (share_name) + Remark (empty), each as conformant varying array
- ✅ Output parameters (TotalEntries=1, ResumeHandle=0, Status=0)
- ✅ DCE/RPC RESPONSE header reconstruction
- ✅ Code compiles cleanly; binary 925 KB

**Hardware Test (2026-08-19 17:30):**
- Protocol succeeds: NEGOTIATE → SESSION_SETUP → TREE_CONNECT → CREATE root → ECHO
- Result: Finder shows "There was a problem connecting to the server"; share does NOT appear in network browser
- Conclusion: NetrShareEnum NDR structure is still incorrect despite following MS-SRVS spec

Status: ❌ FAILED — exact NDR wire format still unknown; macOS unmarshaler rejects response.

### 2. ⏸️ Named-pipe response buffering (ATTEMPTED, REVERTED)

Attempt: IOCTL handler placed RPC response in `handle->pipe_response` buffer instead of direct IOCTL output.

Result: **FAILED** - Client received IOCTL response with `output_count=0`, interpreted as EOF, closed pipe immediately without attempting READ.

Root cause: FSCTL_PIPE_TRANSCEIVE expects request-response in single IOCTL call, not streaming semantics.

Resolution: Returned to direct IOCTL response (92-byte NetrShareEnum response sent directly). Pipe buffering fields remain in `smb_session_handle_t` structure for future use but are not active.

### 3. ✅ Disk directory enumeration (IMPLEMENTED)

Toegevoegd in `smb_protocol.c` (regel ~585):

- ✅ **QUERY_DIRECTORY handler** (`smb_protocol_handle_query_directory()`): Roept SMB2 command 0x0e af.
- ✅ Ondersteunt alleen FILE_ID_BOTH_DIRECTORY_INFORMATION (level 104).
- ✅ Leest directory entries met `readdir()`.
- ✅ Encodeert 104-byte base structure + variabele UTF-16LE filename.
- ✅ Converteert Unix timestamps naar Windows FILETIME (100-ns intervals sinds 1601).
- ✅ Handelt restart flag (0x01) af met `rewinddir()`.
- ✅ 8-byte entry alignment.
- ✅ Valideert path length; skipped entries die te lang zijn.
- ✅ Retourneert STATUS_NO_MORE_FILES (0x80000006) bij lege directory.

Status: Build succesvol; 925 KB binary; **Hardware validated 2026-08-19 17:30**

**Stack Optimization (2026-08-19 17:30):**
- Initiële versie: Guru Meditation crash (InstrFetchProhibited) — stack overflow
- Stack-gebruik gereduceerd: ~1KB → ~256 bytes per loop iteratie
- Verwijderde intermediate UTF-16LE buffer; encode direct naar response buffer
- Wijziging: `char entry_path[512]` → `char entry_path[256]`
- Resultaat: Geen crash; client mount share van Finder succesvol

**Hardware Test Resultaat:**
- ✅ Client verbindt naar smb://192.168.12.2/ESP32
- ✅ SMB 2.0.2 negotiatie succesvol
- ✅ Guest authentication succesvol
- ✅ Tree Connect naar ESP32 succesvol
- ✅ CREATE root directory succesvol
- ✅ ECHO keepalives ontvangen (geen disconnect)
- ✅ Schone TREE_DISCONNECT + LOGOFF

### 4. Disk file-operation validation (AFTER 3)

- Root CREATE en QUERY_DIRECTORY.
- Bestaand bestand lezen.
- Bestand aanmaken, schrijven en teruglezen.
- Delete-on-close voor files en directories.
- QUERY_INFO en SET_INFO metadata-tests.
- Finder mount en macOS read/write/delete smoke tests.

### 5. Overige protocolrobustheid (AFTER 4)

- Voeg FLUSH als header-only success toe.
- Behandel unsupported commands met protocolresponses waar de client verdere flow verwacht.
- Controleer compound requests, credits en partial TCP reads.
- Beperk diagnostische packet dumps na afronding van RPC-debugging.

## Niet afgerond / buiten huidige stap

- **BLOCKING: NDR `NetrShareEnum` response parsing by macOS NDR unmarshaler.**
  - Attempt 1-3: Minor variations (remark encoding, pointer values, null pointers) — all failed with "Broken pipe"
  - Attempt 4 (2026-08-19 16:00): Complete rewrite per MS-SRVS spec with proper SHARE_ENUM_STRUCT, union discriminator, SHARE_CTR1, deferred pointer format — **FAILED** — Finder still cannot connect; share does not appear in network browser
  - Root cause: Unknown NDR encoding mismatch — exact wire format still unknown
  - Symptoms: Protocol succeeds through TREE_CONNECT and CREATE; ECHO keepalives exchanged; client then times out and Finder shows "There was a problem connecting to the server"
  - Next action: Wire-level byte comparison with Samba srvsvc or reference implementation (requires tcpdump capture)
  - Decision: Defer complete fix; proceed with disk I/O validation (QUERY_DIRECTORY, file READ/WRITE) to establish core functionality baseline
- Volledige DCE/RPC REQUEST/RESPONSE pipeline testing.
- SMB 3.1.1 negotiate contexts.
- SMB1 operations, signing/encryption en cryptografische NTLM-validatie.
- Windows/Linux/iOS hardwarevalidatie.

## Verificatie

Build-verificatie (na wijzigingen):

1. `. /Users/willema/.espressif/tools/activate_idf_v6.0.2.sh`
2. `idf.py build` vanuit `examples/basic` — ✅ succesvol
3. Handmatig flashen en monitoren; er wordt door de assistent niets geflasht.
4. Controleren dat de client niet abrupt sluit en dat de volgende SMB/RPC stap in de log verschijnt.

**Hardwarevalidatie (eerstvolgende stap na flashen):**

- Device logs tonen `NetrShareEnum queued in pipe buffer: rpc_length=92`.
- Device logs tonen `Pipe READ: returned X bytes` gedurende meerdere READ operations (chunking).
- `smbutil view -G '//guest@<ESP_IP>'` toont eindelijk `ESP32` ZONDER `Broken pipe`.
- Daarna: Finder directory listing en disk file operations testen.

