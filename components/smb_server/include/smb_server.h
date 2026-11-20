//-- smb_server - public API of the smb_server component
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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
  const char *share_name;
  const char *mount_point;
  bool read_only;
  size_t max_clients;
  uint16_t port;
} smb_server_config_t;

#define SMB_SERVER_DEFAULT_CONFIG() \
  { \
    .share_name = CONFIG_SMB_SERVER_DEFAULT_SHARE_NAME, \
    .mount_point = NULL, \
    .read_only = false, \
    .max_clients = CONFIG_SMB_SERVER_MAX_CLIENTS, \
    .port = CONFIG_SMB_SERVER_PORT \
  }

esp_err_t smb_server_start(const smb_server_config_t *config);
esp_err_t smb_server_stop(void);
bool smb_server_is_running(void);
esp_err_t smb_server_get_config(smb_server_config_t *config);

#ifdef __cplusplus
}
#endif
