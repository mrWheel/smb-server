<!--
smb-server - documentation of the smb_server component
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

# smb_server

SMB2/SMB3 file server component for ESP-IDF. It exposes an **already
mounted** ESP-IDF VFS filesystem (LittleFS, FatFS, SD card, ...) as an SMB
network share over TCP (port 445 by default).

The SMB2 protocol is implemented directly in this component's C sources -
there is no dependency on libsmb2 or any other external SMB stack.

## Installation

From the ESP Component Registry (once published, namespace `mrWheel` is the
planned one - see repository):

```bash
idf.py add-dependency "mrWheel/smb_server"
```

From a Git checkout of this repository, add the component through
`EXTRA_COMPONENT_DIRS` or declare it as a managed dependency with an
`override_path` in your application's `main/idf_component.yml`:

```yaml
dependencies:
  mrWheel/smb_server:
    override_path: "../../components/smb_server"
```

(The path is relative to the manifest file that declares the dependency.)

### Requirements

- ESP-IDF **>= 6.0**
- Supported targets (declared): `esp32`, `esp32s2`, `esp32s3`, `esp32c3`.
  Verified by build: `esp32s3` (see repository patch log). The other
  declared targets are expected to work but were not individually verified.

## Public API

```c
#include "smb_server.h"

typedef struct
{
  const char *share_name;    // 1..31 characters, e.g. "ESP32"
  const char *mount_point;   // absolute VFS path, e.g. "/littlefs"
  bool read_only;
  size_t max_clients;        // 1..4
  uint16_t port;             // 445 by default
} smb_server_config_t;

esp_err_t smb_server_start(const smb_server_config_t *config);
esp_err_t smb_server_stop(void);
bool smb_server_is_running(void);
esp_err_t smb_server_get_config(smb_server_config_t *config);
```

Minimal usage (network and filesystem setup must already be done):

```c
smb_server_config_t config = SMB_SERVER_DEFAULT_CONFIG();
config.share_name = "ESP32";
config.mount_point = "/littlefs";
config.read_only = false;
ESP_ERROR_CHECK(smb_server_start(&config));
```

`smb_server_stop()` requests a graceful stop of the listener task.
`SMB_SERVER_DEFAULT_CONFIG()` fills share name, client count and port from
Kconfig; `mount_point` is always `NULL` and must be set by the application.

## Filesystem mount requirements

The component never mounts or formats anything, never touches WiFi/mDNS/SD
drivers and is filesystem-agnostic. Before calling `smb_server_start()`:

1. Register the backing filesystem in the ESP-IDF VFS (e.g.
   `esp_vfs_littlefs_register()`), so `config->mount_point` resolves.
2. The mount point must be an absolute path (`'/'`-prefixed) shorter than
   128 characters.

All paths are normalized and constrained to stay inside the configured
mount point (`..` traversal, drive letters and alternate-data-stream-style
paths are rejected).

## Configuration (Kconfig)

| Option | Default | Purpose |
|---|---|---|
| `SMB_SERVER_DEFAULT_SHARE_NAME` | `ESP32` | Share name used by `SMB_SERVER_DEFAULT_CONFIG()` |
| `SMB_SERVER_MAX_CLIENTS` | 1 (range 1-4) | Maximum simultaneous TCP clients |
| `SMB_SERVER_TASK_STACK_SIZE` | 12288 | Server/listener task stack |
| `SMB_SERVER_TASK_PRIORITY` | 5 | Server task priority |
| `SMB_SERVER_PORT` | 445 | TCP listen port |
| `SMB_SERVER_VERBOSE_LOGGING` | n | Verbose protocol logging |

## Protocol behaviour (as implemented)

- **Dialects:** SMB 2.0.2, 2.1, 3.0 and 3.0.2. The server selects the
  highest dialect offered by the client; SMB 3.1.1 (and its Negotiate
  Contexts) is **not** offered or supported. An initial SMB1-framed
  negotiate is accepted only as a bridge to SMB2 (the server replies with
  the `SMB 2.???` wildcard and expects the client's real SMB2 NEGOTIATE);
  SMB1 operations themselves are not supported.
- **Authentication:** guest only. Any `SESSION_SETUP` is accepted; the
  NTLMSSP (or SPNEGO-wrapped NTLMSSP) challenge is mirrored in the form the
  client used but is never cryptographically verified, and the session is
  flagged `IS_GUEST`.
- **Shares:** one disk share (the configured `share_name`) mapped to the
  VFS mount point, plus `IPC$` with a `srvsvc` named pipe answering DCE/RPC
  `NetrShareEnum` (NDR32) so clients can browse the share.
- **Commands:** NEGOTIATE, SESSION_SETUP, LOGOFF, TREE_CONNECT,
  TREE_DISCONNECT, CREATE, CLOSE, READ, WRITE, FLUSH, ECHO, QUERY_INFO,
  SET_INFO, QUERY_DIRECTORY, CHANGE_NOTIFY, CANCEL and IOCTL
  (`FSCTL_PIPE_TRANSCEIVE`). Compound (chained) requests are processed.
- **Query Info:** `FileBasicInformation`, `FileStandardInformation`,
  `FileNetworkOpenInformation`, `FileAllInformation`, and
  `FileFsSizeInformation` (static placeholder volume size, 512 MB total /
  256 MB free).
- **Set Info:** `FileEndOfFileInformation` (truncate),
  `FileDispositionInformation` (delete on close) and
  `FileBasicInformation` (accepted, attributes/timestamps are not changed).
- **Query Directory:** `FileIdBothDirectoryInformation` with wildcard and
  single-entry/restart-scan flag support.
- **Change Notify:** directory create/delete notifications with interim
  `STATUS_PENDING` responses; see the documented deviations below.

## Known limitations

- **No signing and no encryption.** The NEGOTIATE response advertises
  signing-enabled, but requests/responses are never signed or encrypted -
  do not rely on transport security.
- **Guest access only:** no user accounts, no per-user permissions. Anyone
  on the network can read (and, unless `read_only` is set, write and
  delete) everything under the mount point.
- No oplocks/batch leases, no durable or resilient handles, no
  multi-channel, no symbolic links or security descriptors, no ACLs.
- `CHANGE_NOTIFY` deviations (documented in the implementation plan):
  watches fire on any change under a watched directory regardless of the
  requested `CompletionFilter`; `TREE_DISCONNECT` cleanup is
  connection-wide rather than tree-scoped.
- Volume size reported to clients is a placeholder, not the real backing
  filesystem usage.
- Maximum 4 simultaneous clients (per-client task with heap buffers).
- Filesystems: validated on LittleFS; any VFS-mounted filesystem should
  work but only LittleFS has been exercised on hardware.

## Example

A self-contained demo (WiFi provisioning, mDNS advertisement, LittleFS
image with sample files) lives in
[`examples/basic/`](examples/basic/README.md).

## License

GPL-3.0-or-later - see [LICENSE](LICENSE).
