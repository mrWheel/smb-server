//-- smb_server - SMB2/SMB3 server lifecycle, listener and client tasks
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
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "smb_internal.h"

static const char *TAG = "smb_server";

smb_server_state_t g_smb_server_state = {0};

static esp_err_t smb_server_validate_config(const smb_server_config_t *config)
{
  if (config == NULL)
  {
    return ESP_ERR_INVALID_ARG;
  }

  if (config->share_name == NULL || config->share_name[0] == '\0')
  {
    return ESP_ERR_INVALID_ARG;
  }

  if (strlen(config->share_name) >= SMB_SERVER_SHARE_NAME_MAX)
  {
    return ESP_ERR_INVALID_SIZE;
  }

  if (config->mount_point == NULL || config->mount_point[0] != '/')
  {
    return ESP_ERR_INVALID_ARG;
  }

  if (strlen(config->mount_point) >= SMB_SERVER_MOUNT_POINT_MAX)
  {
    return ESP_ERR_INVALID_SIZE;
  }

  if (config->max_clients == 0 || config->max_clients > 4)
  {
    return ESP_ERR_INVALID_ARG;
  }

  if (config->port == 0)
  {
    return ESP_ERR_INVALID_ARG;
  }

  return smb_vfs_validate_mount_point(config->mount_point);
}

static void smb_server_task(void *argument)
{
  (void)argument;

  ESP_LOGI(
    TAG,
    "Starting SMB server: share=%s mount=%s port=%u max_clients=%u read_only=%s",
    g_smb_server_state.share_name,
    g_smb_server_state.mount_point,
    (unsigned)g_smb_server_state.config.port,
    (unsigned)g_smb_server_state.config.max_clients,
    g_smb_server_state.config.read_only ? "yes" : "no");

  ESP_LOGI(
    TAG,
    "Free heap before SMB protocol loop: %u bytes",
    (unsigned)esp_get_free_heap_size());

  g_smb_server_state.running = true;

  esp_err_t err = smb_protocol_run();

  g_smb_server_state.running = false;
  g_smb_server_state.task_handle = NULL;

  if (err != ESP_OK && !g_smb_server_state.stop_requested)
  {
    ESP_LOGE(TAG, "SMB protocol loop stopped: %s", esp_err_to_name(err));
  }
  else
  {
    ESP_LOGI(TAG, "SMB server stopped");
  }

  vTaskDelete(NULL);
}

esp_err_t smb_server_start(const smb_server_config_t *config)
{
  if (g_smb_server_state.task_handle != NULL || g_smb_server_state.running)
  {
    return ESP_ERR_INVALID_STATE;
  }

  esp_err_t err = smb_server_validate_config(config);
  if (err != ESP_OK)
  {
    ESP_LOGE(TAG, "Invalid SMB server configuration: %s", esp_err_to_name(err));
    return err;
  }

  memset(&g_smb_server_state, 0, sizeof(g_smb_server_state));

  strlcpy(
    g_smb_server_state.share_name,
    config->share_name,
    sizeof(g_smb_server_state.share_name));

  strlcpy(
    g_smb_server_state.mount_point,
    config->mount_point,
    sizeof(g_smb_server_state.mount_point));

  g_smb_server_state.config.share_name = g_smb_server_state.share_name;
  g_smb_server_state.config.mount_point = g_smb_server_state.mount_point;
  g_smb_server_state.config.read_only = config->read_only;
  g_smb_server_state.config.max_clients = config->max_clients;
  g_smb_server_state.config.port = config->port;
  g_smb_server_state.stop_requested = false;

  smb_session_reset();

  BaseType_t result = xTaskCreate(
    smb_server_task,
    "smb_server",
    CONFIG_SMB_SERVER_TASK_STACK_SIZE,
    NULL,
    CONFIG_SMB_SERVER_TASK_PRIORITY,
    &g_smb_server_state.task_handle);

  if (result != pdPASS)
  {
    g_smb_server_state.task_handle = NULL;
    return ESP_ERR_NO_MEM;
  }

  return ESP_OK;
}

esp_err_t smb_server_stop(void)
{
  if (g_smb_server_state.task_handle == NULL && !g_smb_server_state.running)
  {
    return ESP_ERR_INVALID_STATE;
  }

  g_smb_server_state.stop_requested = true;
  smb_protocol_request_stop();

  return ESP_OK;
}

bool smb_server_is_running(void)
{
  return g_smb_server_state.running;
}

esp_err_t smb_server_get_config(smb_server_config_t *config)
{
  if (config == NULL)
  {
    return ESP_ERR_INVALID_ARG;
  }

  if (g_smb_server_state.config.mount_point == NULL)
  {
    return ESP_ERR_INVALID_STATE;
  }

  *config = g_smb_server_state.config;
  return ESP_OK;
}
