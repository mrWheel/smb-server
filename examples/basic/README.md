# Basic LittleFS example

This example mounts LittleFS, provisions WiFi with
`michmich/esp-idf-wifi-provisioner`, prints the assigned IP address, starts
mDNS as `esp-smb.local`, advertises `_smb._tcp` on port 445 and starts
`smb_server`.

## Build

```bash
idf.py set-target esp32
idf.py build
idf.py flash monitor
```

If no WiFi credentials are stored, connect to the `ESP-SMB-Setup` access point
and use the provisioner's captive portal.

## Important

The current upstream `libsmb2` server bootstrap is real, but the final
CREATE/file-id/VFS mapping is intentionally still guarded in `smb_protocol.c`.
The example therefore serves as a development and integration project, not yet
as a production file server.
