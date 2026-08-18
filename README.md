# smb_server project

This version uses a local vendored `libsmb2_port` component instead of the old
Espressif Registry `sahlberg/libsmb2` 3.0.1 package or a moving Git dependency.

## Repository structure

```text
components/
├── smb_server/
└── libsmb2_port/
    └── vendor/
        └── libsmb2/      <- imported upstream source

examples/
└── basic/
```

## First-time setup

Obtain current upstream `sahlberg/libsmb2` source and import it once:

```bash
./tools/vendor_libsmb2.sh /path/to/libsmb2
```

This copies the source into the project and records the exact Git commit when
available.

After that, the build does not need a Git dependency for libsmb2.

## Why the upstream source is local

Upstream currently documents:

- SMB2/SMB3 client/server support
- a synchronous SMB server API
- an `examples/smb2-server-sync.c` implementation
- direct ESP-IDF support

The upstream CMake project currently reports version 6.1.0.

The old Registry package 3.0.1 is therefore not used.

## Build

```bash
cd examples/basic
idf.py set-target esp32
idf.py build
```

The basic example still uses managed Registry dependencies for the WiFi
provisioner, mDNS and LittleFS, but `libsmb2` is entirely local.

## Important

The vendor directory intentionally starts empty in this distribution. The
upstream LGPL source must be imported with `tools/vendor_libsmb2.sh`.

The script copies the **complete upstream source tree**. Do not prematurely strip
client or protocol files merely to save space: first obtain a working SMB server
build, measure flash/RAM usage, and only then remove proven-unused code.

See `components/libsmb2_port/VENDORING.md`.
