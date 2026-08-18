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
