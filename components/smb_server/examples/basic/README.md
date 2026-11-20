<!--
smb-server - documentation of the basic SMB share example
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

# Basic SMB share example

Self-contained example that mounts a LittleFS image, provisions WiFi with
`michmich/esp-idf-wifi-provisioner`, advertises the share over mDNS as
`esp-smb.local` (`_smb._tcp`, port 445) and starts `smb_server` exposing the
`ESP32` share.

The example is fully self-contained: it declares all managed dependencies in
its own [main/idf_component.yml](main/idf_component.yml) and uses the local
`smb_server` sources in a Git checkout (via `override_path`), or the published
component when downloaded from the ESP Component Registry. The sample files
that are baked into the LittleFS image live in
[littlefs_assets/](littlefs_assets/).

## Build and flash

```bash
cd examples/basic
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/tty.usbserial-1430 flash monitor
```

Use `esp32`, `esp32s2` or `esp32c3` instead of `esp32s3` for other supported
targets.

## WiFi setup

On first boot (or when no credentials are stored in NVS) connect to the
`ESP-SMB-Setup` access point and use the provisioner's captive portal to
enter your WiFi credentials. The serial monitor prints the assigned IP
address once connected.

## Connecting to the share

The share is guest-accessible; any (or no) username works.

- macOS: `smbutil view -G '//guest@<IP>'` lists `ESP32`, then
  `open smb://guest@<IP>/ESP32` (or Finder → Connect to Server).
- Linux: `mount -t cifs //<IP>/ESP32 /mnt/esp32 -o guest`
- Windows: `net view \\<IP>` / map network drive in Explorer.

The mounted share should show the sample files from `littlefs_assets/`
(`welcome.txt`, `notes/todo1.txt`, `notes/todo2.txt`). Reading, writing and
deleting files is supported (the example runs with `read_only = false`).
