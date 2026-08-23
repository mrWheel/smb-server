# SMB2 and srvsvc Protocol References

This file records the authoritative references used for the custom SMB2 server implementation.

## Microsoft Open Specifications

### MS-SRVS: Server Service Remote Protocol

- Overview: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/
- Current published specification: revision 39.0, 2024-09-16
- PDF: https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-SRVS/%5bMS-SRVS%5d.pdf
- DOCX: https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-SRVS/%5bMS-SRVS%5d-240916.docx

Use MS-SRVS for:

- NetrShareEnum operation and opnum mapping
- SHARE_ENUM_STRUCT and SHARE_INFO containers
- SHARE_INFO_1 fields: name, share type, and comment
- srvsvc named-pipe behavior and result status
- NDR pointer and string requirements for srvsvc data

### MS-RPCE: Remote Procedure Call Protocol Extensions

- Overview: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/
- Current published specification: revision 35.0, 2024-09-16
- PDF: https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-RPCE/%5bMS-RPCE%5d.pdf
- DOCX: https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-RPCE/%5bMS-RPCE%5d-240916.docx

Use MS-RPCE for:

- DCE/RPC request and response PDU headers
- BIND and BIND_ACK packet fields
- NDR32 transfer syntax and data representation
- Fragment length, call ID, allocation hint, context ID, and PDU flags
- Presentation context and transfer syntax validation

## Samba Interoperability References

Samba contains a mature interoperable srvsvc implementation and generated NDR bindings. It is useful as an implementation reference, not as a library dependency for this project.

- Samba repository: https://github.com/samba-team/samba
- srvsvc server implementation: https://github.com/samba-team/samba/tree/master/source4/rpc_server/srvsvc/dcesrv_srvsvc.c
- Samba3 srvsvc implementation: https://github.com/samba-team/samba/tree/master/source3/rpc_server/srvsvc/srv_srvsvc_nt.c
- Samba srvsvc client tests: https://github.com/samba-team/samba/tree/master/source4/torture/rpc/srvsvc.c
- Samba NetAPI share mapping: https://github.com/samba-team/samba/tree/master/source3/lib/netapi/share.c
- Samba srvsvc client share listing: https://github.com/samba-team/samba/tree/master/source3/rpcclient/cmd_srvsvc.c
- Samba IDL build list: https://github.com/samba-team/samba/blob/master/librpc/idl/wscript_build

Relevant Samba symbols:

- `srvsvc_NetShareEnum`
- `srvsvc_NetShareInfoCtr`
- `srvsvc_NetShareCtr1`
- `srvsvc_NetShareInfo1`
- `ndr_table_srvsvc`
- `NDR_SRVSVC_NETSHAREENUM`

## Hardware-observed wire facts

These facts are captured from macOS `smbutil` against this ESP32 server:

- macOS begins with SMB1 multi-protocol negotiate: signature `ff 53 4d 42`.
- The SMB1 request offers `NT LM 0.12` and `SMB 2.002`.
- The server bridges only this negotiate preamble and then uses SMB2 signature `fe 53 4d 42`.
- macOS sends raw NTLMSSP type 1, receives a raw type 2 challenge, and sends raw type 3.
- SMB2 Session Setup completes with guest flag `IS_GUEST`.
- macOS connects to `IPC$`, creates `srvsvc`, and sends `FSCTL_PIPE_TRANSCEIVE` (`0x0011c017`).
- The first RPC PDU is DCE/RPC BIND (`ptype 0x0b`).
- The server returns a 56-byte NDR32 BIND_ACK and macOS proceeds to an RPC REQUEST.
- The observed NetrShareEnum request has `ptype 0x00` and `opnum 0x000f`.
- The current hand-written NDR response is sent, but macOS still rejects it and eventually reports `Broken pipe` after ECHO retries.
- Samba's `librpc/idl/srvsvc.idl` is the concrete IDL reference for the current encoder: `srvsvc_NetShareInfoCtr` level 1, `srvsvc_NetShareCtr1`, `srvsvc_NetShareInfo1`, and `srvsvc_NetShareEnum` function 0x24.

## Current implementation rule

Do not make further NetrShareEnum byte-layout changes from memory alone. Derive the response from MS-SRVS and the generated Samba srvsvc NDR model, then validate the exact DCE/RPC response bytes on hardware.

The next response must contain:

- A valid DCE/RPC RESPONSE PDU
- The observed request call ID
- Correct NDR32 data representation and fragment length
- Correct `SHARE_ENUM_STRUCT` level/union layout
- One `SHARE_INFO_1` entry for the configured share
- Correct deferred UTF-16LE strings, including null termination
- `totalentries`, resume handle semantics, and final `WERROR` status in the specified order
