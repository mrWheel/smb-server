# Changelog

## 0.2.0

- Reorganized project into local ESP-IDF components.
- Added `components/libsmb2_port`.
- Removed the `sahlberg/libsmb2` Registry dependency.
- Removed the moving upstream Git dependency from `smb_server`.
- Added controlled local vendoring through `tools/vendor_libsmb2.sh`.
- Added upstream revision tracking.
- Kept WiFi provisioner, mDNS and filesystem mounting outside the reusable
  `smb_server` component.

## 0.1.0

- Initial project scaffold.
