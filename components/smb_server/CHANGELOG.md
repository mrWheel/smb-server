# Changelog

## 0.1.0 - development

- Initial `smb_server` component structure.
- Added ESP-IDF public API and Kconfig.
- Added bounded server state and FreeRTOS task.
- Added safe SMB path normalization and traversal prevention.
- Added ESP-IDF VFS/POSIX helpers.
- Added bounded session/file-handle table.
- Added current upstream `libsmb2` synchronous server bootstrap.
- Added guest access configuration and SMB2/SMB3 negotiation setup.
- Added LittleFS/WiFi/mDNS basic example.
- Documented Registry blocker caused by the required Git `libsmb2` dependency.
