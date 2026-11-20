//-- smb_server - SMB2 packet framing, parsing and serialization
//-- Copyright (C) 2026 Willem Aandewiel (mrWheel)
//-- This program is free software: you can redistribute it and/or modify
//-- it under the terms of the GNU General Public License as published by
//-- the Free Software Foundation, either version 3 of the License, or
//-- (at your option) any later version.
//--
//-- This program is distributed in the hope that it will be useful,
//-- but WITHOUT ANY WARRANTY; without even the implied warranty of
//-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//-- GNU General Public License for more details.
//--
//-- You should have received a copy of the GNU General Public License
//-- along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <string.h>
#include "esp_log.h"
#include "smb_packet.h"

static const char *TAG = "smb_packet";

uint16_t smb2_get_u16_le(const uint8_t *data)
{
  return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

uint32_t smb2_get_u32_le(const uint8_t *data)
{
  return (uint32_t)data[0] |
    ((uint32_t)data[1] << 8) |
    ((uint32_t)data[2] << 16) |
    ((uint32_t)data[3] << 24);
}

uint64_t smb2_get_u64_le(const uint8_t *data)
{
  return (uint64_t)data[0] |
    ((uint64_t)data[1] << 8) |
    ((uint64_t)data[2] << 16) |
    ((uint64_t)data[3] << 24) |
    ((uint64_t)data[4] << 32) |
    ((uint64_t)data[5] << 40) |
    ((uint64_t)data[6] << 48) |
    ((uint64_t)data[7] << 56);
}

void smb2_put_u16_le(uint8_t *data, uint16_t value)
{
  data[0] = (uint8_t)value;
  data[1] = (uint8_t)(value >> 8);
}

void smb2_put_u32_le(uint8_t *data, uint32_t value)
{
  data[0] = (uint8_t)value;
  data[1] = (uint8_t)(value >> 8);
  data[2] = (uint8_t)(value >> 16);
  data[3] = (uint8_t)(value >> 24);
}

void smb2_put_u64_le(uint8_t *data, uint64_t value)
{
  data[0] = (uint8_t)value;
  data[1] = (uint8_t)(value >> 8);
  data[2] = (uint8_t)(value >> 16);
  data[3] = (uint8_t)(value >> 24);
  data[4] = (uint8_t)(value >> 32);
  data[5] = (uint8_t)(value >> 40);
  data[6] = (uint8_t)(value >> 48);
  data[7] = (uint8_t)(value >> 56);
}

const char *smb2_command_name(uint16_t command)
{
  switch (command)
  {
    case SMB2_NEGOTIATE:       return "NEGOTIATE";
    case SMB2_SESSION_SETUP:   return "SESSION_SETUP";
    case SMB2_LOGOFF:          return "LOGOFF";
    case SMB2_TREE_CONNECT:    return "TREE_CONNECT";
    case SMB2_TREE_DISCONNECT: return "TREE_DISCONNECT";
    case SMB2_CREATE:          return "CREATE";
    case SMB2_CLOSE:           return "CLOSE";
    case SMB2_FLUSH:           return "FLUSH";
    case SMB2_READ:            return "READ";
    case SMB2_WRITE:           return "WRITE";
    case SMB2_LOCK:            return "LOCK";
    case SMB2_IOCTL:           return "IOCTL";
    case SMB2_CANCEL:          return "CANCEL";
    case SMB2_ECHO:            return "ECHO";
    case SMB2_QUERY_DIRECTORY: return "QUERY_DIRECTORY";
    case SMB2_CHANGE_NOTIFY:   return "CHANGE_NOTIFY";
    case SMB2_QUERY_INFO:      return "QUERY_INFO";
    case SMB2_SET_INFO:        return "SET_INFO";
    default:                   return "UNKNOWN";
  }
}

int smb2_parse_header(const uint8_t *data, size_t length, smb2_header_t *header)
{
  //-- Minimum: need signature (4) + command field (2 bytes at offset 12)
  //-- Some SMB2 responses may be shorter than 64 bytes
  if (length < 14)
  {
    ESP_LOGI(TAG, "Parse header: buffer too short (%zu < 14)", length);
    return -1;
  }

  memset(header, 0, sizeof(*header));

  header->signature = smb2_get_u32_le(data);
  header->structure_size = smb2_get_u16_le(data + 4);
  header->credit_charge = smb2_get_u16_le(data + 6);
  header->status = smb2_get_u32_le(data + 8);
  header->command = smb2_get_u16_le(data + 12);
  //-- Fields below sit past the 14-byte minimum; unread fields stay
  //-- zeroed by the memset above rather than reading past `length`.
  if (length >= 16)  header->credit_requested = smb2_get_u16_le(data + 14);
  if (length >= 20)  header->flags = smb2_get_u32_le(data + 16);
  if (length >= 24)  header->next_command = smb2_get_u32_le(data + 20);
  if (length >= 32)  header->message_id = smb2_get_u64_le(data + 24);
  if (length >= 36)  header->reserved = smb2_get_u32_le(data + 32);
  if (length >= 40)  header->tree_id = smb2_get_u32_le(data + 36);
  if (length >= 48)  header->session_id = smb2_get_u64_le(data + 40);
  if (length >= 64)  memcpy(header->signature_bytes, data + 48, 16);

  ESP_LOGI(TAG, "Parsed: sig=0x%08x, struct_size=%u, cmd=0x%04x (%s), msg_id=%llu",
    header->signature, header->structure_size, header->command, smb2_command_name(header->command), header->message_id);

  //-- Validate signature
  if (header->signature != SMB2_SIGNATURE)
  {
    ESP_LOGI(TAG, "Invalid signature: 0x%08x (expected 0x%08x)", header->signature, SMB2_SIGNATURE);
    return -1;
  }

  //-- Log structure size warning if not 64
  //-- Some older SMB2 implementations may send different values, but we continue parsing
  if (header->structure_size != SMB2_HEADER_SIZE)
  {
    ESP_LOGW(TAG, "Unexpected structure_size: %u (expected %u, but will continue)", header->structure_size, SMB2_HEADER_SIZE);
  }

  return 0;
}

int smb2_build_header(uint8_t *data, size_t length, const smb2_header_t *header)
{
  if (length < SMB2_HEADER_SIZE)
  {
    return -1;
  }

  memset(data, 0, SMB2_HEADER_SIZE);

  smb2_put_u32_le(data, header->signature);
  smb2_put_u16_le(data + 4, header->structure_size);
  smb2_put_u16_le(data + 6, header->credit_charge);
  smb2_put_u32_le(data + 8, header->status);
  smb2_put_u16_le(data + 12, header->command);
  smb2_put_u16_le(data + 14, header->credit_requested);
  smb2_put_u32_le(data + 16, header->flags);
  smb2_put_u32_le(data + 20, header->next_command);
  smb2_put_u64_le(data + 24, header->message_id);
  smb2_put_u32_le(data + 32, header->reserved);
  smb2_put_u32_le(data + 36, header->tree_id);
  smb2_put_u64_le(data + 40, header->session_id);
  memcpy(data + 48, header->signature_bytes, 16);

  return SMB2_HEADER_SIZE;
}
