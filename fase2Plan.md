# Phase 2 — Core Disk Share Access (CREATE / CLOSE / READ / WRITE / QUERY_INFO / SET_INFO)

## Huidige status

De volgende keten werkt aantoonbaar op hardware met ESP-IDF v6.0.2:

1. SMB1 multi-protocol negotiate met aangeboden dialect `SMB 2.002`.
2. SMB2 negotiate met echte signature `fe 53 4d 42`, correcte 64-byte body, credits, tijden, `ServerGuid` en offsets.
3. Raw NTLMSSP guest-authenticatie: type 1 -> type 2 -> type 3, gevolgd door `STATUS_SUCCESS` en `IS_GUEST`.
4. Tree Connect naar `IPC$` en `srvsvc` CREATE als named pipe.
5. `FSCTL_PIPE_TRANSCEIVE` (`0x0011c017`) en DCE/RPC BIND.
6. Correcte 56-byte DCE/RPC BIND_ACK met complete NDR32 UUID.

De huidige blokkade is de DCE/RPC REQUEST voor `NetrShareEnum`. De client stuurt na BIND een RPC REQUEST met `ptype=0x00` en `opnum=0x000f`, maar de server retourneert nog geen NDR share-enumeration response. Daarom eindigt `smbutil view` met `Broken pipe` of blijft de client wachten.

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

### 1. NDR-encoded NetrShareEnum response

Begin hier. In `smb_protocol_handle_ioctl()`:

- Detecteer DCE/RPC REQUEST (`ptype=0x00`) in de IOCTL input.
- Lees `call_id`, alloc hint en `opnum` uit de RPC header.
- Behandel `opnum=0x000f` als `NetrShareEnum`.
- Bouw een DCE/RPC RESPONSE PDU met correcte version, data representation, flags, fragment length en call ID.
- Encodeer NDR32 uitlijning en de minimale response voor level 1.
- Encodeer precies de geconfigureerde share (`ESP32`) als `SHARE_INFO_1`: UTF-16LE share name, share type `STYPE_DISKTREE`, UTF-16LE remark en correcte referent pointers.
- Voeg `share_count=1` en status `0` toe.
- Plaats de RPC response in de SMB2 IOCTL output buffer met correcte output offset/count.
- Log tijdelijk `ptype`, `call_id`, `opnum`, fragmentlengte en response status.

Verwachte eerstvolgende hardware-uitkomst:

```text
IOCTL input ... ptype=0x00 opnum=0x000f
NetrShareEnum response sent
```

Daarna moet dit zonder `Broken pipe` eindigen:

```sh
smbutil view -G '//guest@<ESP_IP>'
```

### 2. Named-pipe response buffering

- Queue RPC responsebytes in `pipe_response` per pipe-handle.
- Laat SMB2 READ partial reads uit deze queue leveren.
- Gebruik EOF pas wanneer de queue leeg is en de RPC request afgehandeld is.
- Vrijgeven bij CLOSE, LOGOFF en disconnect.

### 3. Disk directory enumeration

- Implementeer QUERY_DIRECTORY (`0x0e`) met `readdir()`.
- Encodeer `FILE_ID_BOTH_DIRECTORY_INFORMATION`.
- Ondersteun pagination en zoekpatronen.
- Valideer de bestaande directory handles en path security.

### 4. Disk file-operation validation

- Root CREATE en QUERY_DIRECTORY.
- Bestaand bestand lezen.
- Bestand aanmaken, schrijven en teruglezen.
- Delete-on-close voor files en directories.
- QUERY_INFO en SET_INFO metadata-tests.
- Finder mount en macOS read/write/delete smoke tests.

### 5. Overige protocolrobustheid

- Voeg FLUSH als header-only success toe.
- Behandel unsupported commands met protocolresponses waar de client verdere flow verwacht.
- Controleer compound requests, credits en partial TCP reads.
- Beperk diagnostische packet dumps na afronding van RPC-debugging.

## Niet afgerond / buiten huidige stap

- NDR `NetrShareEnum` response.
- Volledige DCE/RPC REQUEST/RESPONSE en pipe buffering.
- QUERY_DIRECTORY.
- SMB 3.1.1 negotiate contexts.
- SMB1 operations, signing/encryption en cryptografische NTLM-validatie.
- Windows/Linux/iOS hardwarevalidatie.

## Verificatie

Elke codewijziging:

1. `. /Users/willema/.espressif/tools/activate_idf_v6.0.2.sh`
2. `idf.py build` vanuit `examples/basic`.
3. Handmatig flashen en monitoren; er wordt door de assistent niets geflasht.
4. Controleren dat de client niet abrupt sluit en dat de volgende SMB/RPC stap in de log verschijnt.

De eerstvolgende succescriteria zijn:

- `smbutil view` toont `ESP32`.
- Geen `RPC struct is bad`, `Authentication error`, `Resource temporarily unavailable` of `Broken pipe`.
- Daarna Finder directory listing en disk file operations.

