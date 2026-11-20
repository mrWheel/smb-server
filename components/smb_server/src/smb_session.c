//-- smb_server - session, tree-connect and file-handle tables
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

#include <dirent.h>
#include <string.h>
#include <unistd.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "smb_internal.h"

static const char *TAG = "smb_session";
static smb_session_handle_t s_handles[SMB_SERVER_HANDLE_COUNT];
static uint64_t s_next_file_id = 1;
static SemaphoreHandle_t s_handles_mutex;

static SemaphoreHandle_t smb_session_get_mutex(void)
{
  if (s_handles_mutex == NULL)
  {
    s_handles_mutex = xSemaphoreCreateMutex();
  }

  return s_handles_mutex;
}

static smb_session_handle_t *smb_session_find_locked(uint64_t smb_file_id)
{
  for (size_t index = 0; index < SMB_SERVER_HANDLE_COUNT; index++)
  {
    if (s_handles[index].in_use &&
        s_handles[index].smb_file_id == smb_file_id)
    {
      return &s_handles[index];
    }
  }

  return NULL;
}

void smb_session_reset(void)
{
  SemaphoreHandle_t mutex = smb_session_get_mutex();
  if (mutex != NULL)
  {
    xSemaphoreTake(mutex, portMAX_DELAY);
  }

  for (size_t index = 0; index < SMB_SERVER_HANDLE_COUNT; index++)
  {
    if (!s_handles[index].in_use)
    {
      continue;
    }

    if (s_handles[index].is_directory)
    {
      if (s_handles[index].dir != NULL)
      {
        closedir((DIR *)s_handles[index].dir);
      }
    }
    else if (s_handles[index].fd >= 0)
    {
      close(s_handles[index].fd);
    }

    free(s_handles[index].pipe_response);
  }

  memset(s_handles, 0, sizeof(s_handles));

  for (size_t index = 0; index < SMB_SERVER_HANDLE_COUNT; index++)
  {
    s_handles[index].fd = -1;
  }

  s_next_file_id = 1;

  if (mutex != NULL)
  {
    xSemaphoreGive(mutex);
  }
}

esp_err_t smb_session_allocate_file(
  int owner_socket,
  const char *path,
  int fd,
  uint64_t *smb_file_id)
{
  if (path == NULL || fd < 0 || smb_file_id == NULL)
  {
    return ESP_ERR_INVALID_ARG;
  }

  SemaphoreHandle_t mutex = smb_session_get_mutex();
  if (mutex == NULL || xSemaphoreTake(mutex, portMAX_DELAY) != pdTRUE)
  {
    return ESP_ERR_NO_MEM;
  }

  for (size_t index = 0; index < SMB_SERVER_HANDLE_COUNT; index++)
  {
    if (s_handles[index].in_use)
    {
      continue;
    }

    smb_session_handle_t *handle = &s_handles[index];
    memset(handle, 0, sizeof(*handle));

    handle->in_use = true;
    handle->is_directory = false;
    handle->fd = fd;
    handle->smb_file_id = s_next_file_id++;
    handle->owner_socket = owner_socket;

    strlcpy(handle->path, path, sizeof(handle->path));

    *smb_file_id = handle->smb_file_id;
    xSemaphoreGive(mutex);
    return ESP_OK;
  }

  ESP_LOGW(TAG, "No free SMB file handles");
  xSemaphoreGive(mutex);
  return ESP_ERR_NO_MEM;
}

esp_err_t smb_session_allocate_directory(
  int owner_socket,
  const char *path,
  void *dir,
  uint64_t *smb_file_id)
{
  if (path == NULL || dir == NULL || smb_file_id == NULL)
  {
    return ESP_ERR_INVALID_ARG;
  }

  SemaphoreHandle_t mutex = smb_session_get_mutex();
  if (mutex == NULL || xSemaphoreTake(mutex, portMAX_DELAY) != pdTRUE)
  {
    return ESP_ERR_NO_MEM;
  }

  for (size_t index = 0; index < SMB_SERVER_HANDLE_COUNT; index++)
  {
    if (s_handles[index].in_use)
    {
      continue;
    }

    smb_session_handle_t *handle = &s_handles[index];
    memset(handle, 0, sizeof(*handle));
    handle->in_use = true;
    handle->is_directory = true;
    handle->fd = -1;
    handle->dir = dir;
    handle->smb_file_id = s_next_file_id++;
    handle->owner_socket = owner_socket;
    strlcpy(handle->path, path, sizeof(handle->path));
    *smb_file_id = handle->smb_file_id;
    xSemaphoreGive(mutex);
    return ESP_OK;
  }

  xSemaphoreGive(mutex);
  return ESP_ERR_NO_MEM;
}

esp_err_t smb_session_allocate_pipe(int owner_socket, uint64_t *smb_file_id)
{
  if (smb_file_id == NULL)
  {
    return ESP_ERR_INVALID_ARG;
  }

  SemaphoreHandle_t mutex = smb_session_get_mutex();
  if (mutex == NULL || xSemaphoreTake(mutex, portMAX_DELAY) != pdTRUE)
  {
    return ESP_ERR_NO_MEM;
  }

  for (size_t index = 0; index < SMB_SERVER_HANDLE_COUNT; index++)
  {
    if (s_handles[index].in_use)
    {
      continue;
    }

    smb_session_handle_t *handle = &s_handles[index];
    memset(handle, 0, sizeof(*handle));

    handle->in_use = true;
    handle->is_pipe = true;
    handle->fd = -1;
    handle->smb_file_id = s_next_file_id++;
    handle->owner_socket = owner_socket;

    *smb_file_id = handle->smb_file_id;
    xSemaphoreGive(mutex);
    return ESP_OK;
  }

  ESP_LOGW(TAG, "No free SMB file handles");
  xSemaphoreGive(mutex);
  return ESP_ERR_NO_MEM;
}

esp_err_t smb_session_lookup(
  uint64_t smb_file_id,
  smb_session_handle_t **handle)
{
  if (handle == NULL || smb_file_id == 0)
  {
    return ESP_ERR_INVALID_ARG;
  }

  SemaphoreHandle_t mutex = smb_session_get_mutex();
  if (mutex == NULL || xSemaphoreTake(mutex, portMAX_DELAY) != pdTRUE)
  {
    return ESP_ERR_NO_MEM;
  }

  smb_session_handle_t *found = smb_session_find_locked(smb_file_id);
  if (found != NULL)
  {
    *handle = found;
    xSemaphoreGive(mutex);
    return ESP_OK;
  }

  xSemaphoreGive(mutex);
  return ESP_ERR_NOT_FOUND;
}

esp_err_t smb_session_release(uint64_t smb_file_id)
{
  SemaphoreHandle_t mutex = smb_session_get_mutex();
  if (mutex == NULL || xSemaphoreTake(mutex, portMAX_DELAY) != pdTRUE)
  {
    return ESP_ERR_NO_MEM;
  }

  smb_session_handle_t *handle = smb_session_find_locked(smb_file_id);
  if (handle == NULL)
  {
    xSemaphoreGive(mutex);
    return ESP_ERR_NOT_FOUND;
  }

  if (handle->is_directory)
  {
    if (handle->dir != NULL)
    {
      closedir((DIR *)handle->dir);
    }
  }
  else if (handle->fd >= 0)
  {
    close(handle->fd);
  }

  free(handle->pipe_response);

  memset(handle, 0, sizeof(*handle));
  handle->fd = -1;
  xSemaphoreGive(mutex);

  return ESP_OK;
}

void smb_session_release_by_socket(int owner_socket)
{
  SemaphoreHandle_t mutex = smb_session_get_mutex();
  if (mutex == NULL || xSemaphoreTake(mutex, portMAX_DELAY) != pdTRUE)
  {
    return;
  }

  for (size_t index = 0; index < SMB_SERVER_HANDLE_COUNT; index++)
  {
    smb_session_handle_t *handle = &s_handles[index];
    if (!handle->in_use || handle->owner_socket != owner_socket)
    {
      continue;
    }

    if (handle->is_directory)
    {
      if (handle->dir != NULL)
      {
        closedir((DIR *)handle->dir);
      }
    }
    else if (handle->fd >= 0)
    {
      close(handle->fd);
    }

    free(handle->pipe_response);

    memset(handle, 0, sizeof(*handle));
    handle->fd = -1;
  }

  xSemaphoreGive(mutex);
}
