<!--
smb-server - README of the smb-server repository and root test application
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

# smb-server

ESP-IDF component that turns an ESP32 into a guest-accessible SMB2/SMB3 file
server, exposing an already-mounted ESP-IDF VFS filesystem (LittleFS, FatFS,
...) as a network share.

The SMB2 protocol is implemented directly in the `smb_server` component - no
libsmb2 or other external SMB stack is used.

## Contents

- Repository root - a test application (`main/`) that builds the basic
  example straight from the checkout, same layout as the ringFileStore
  repository.
- [`components/smb_server/`](components/smb_server/) - the reusable component
  (public API, Kconfig options, installation and usage documentation in its
  [README](components/smb_server/README.md)).
- [`components/smb_server/examples/basic/`](components/smb_server/examples/basic/) -
  self-contained LittleFS + WiFi + mDNS demo, buildable from a Git checkout
  or from the published component. The root application reuses its `main.c`,
  partition table and `sdkconfig.defaults`, so there is a single source.
- [`protocolReferences.md`](protocolReferences.md) - protocol specification
  notes used while implementing the handlers.

## Build and flash the demo

From the repository root:

```bash
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/tty.usbserial-1430 flash monitor
```

Then provision WiFi via the `ESP-SMB-Setup` access point and connect to the
`ESP32` share (see the [example README](components/smb_server/examples/basic/README.md)).

## Quick start

```c
#include "smb_server.h"

smb_server_config_t config = SMB_SERVER_DEFAULT_CONFIG();
config.share_name = "ESP32";
config.mount_point = "/littlefs";
ESP_ERROR_CHECK(smb_server_start(&config));
```

See the [component README](components/smb_server/README.md) for installation,
configuration and the list of protocol limitations.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) and
[components/smb_server/LICENSE](components/smb_server/LICENSE).
