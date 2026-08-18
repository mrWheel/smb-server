#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "smb_server.h"

#define SMB_SERVER_SHARE_NAME_MAX 32
#define SMB_SERVER_MOUNT_POINT_MAX 128
#define SMB_SERVER_PATH_MAX 512
#define SMB_SERVER_HANDLE_COUNT 24

typedef struct
{
  bool running;
  bool stop_requested;
  smb_server_config_t config;
  char share_name[SMB_SERVER_SHARE_NAME_MAX];
  char mount_point[SMB_SERVER_MOUNT_POINT_MAX];
  TaskHandle_t task_handle;
} smb_server_state_t;

typedef struct
{
  bool in_use;
  bool is_directory;
  bool is_pipe;
  bool delete_pending;
  int fd;
  void *dir;
  uint64_t smb_file_id;
  void *pipe_response;
  size_t pipe_response_length;
  size_t pipe_response_offset;
  char path[SMB_SERVER_PATH_MAX];
} smb_session_handle_t;

extern smb_server_state_t g_smb_server_state;

esp_err_t smb_protocol_run(void);
void smb_protocol_request_stop(void);

esp_err_t smb_path_utf16le_to_utf8(
  const uint8_t *utf16,
  size_t utf16_length,
  char *output,
  size_t output_size);

esp_err_t smb_path_resolve(
  const char *mount_point,
  const char *smb_path,
  char *output,
  size_t output_size);

esp_err_t smb_vfs_validate_mount_point(const char *mount_point);
int smb_vfs_open(const char *path, int flags, int mode);
int smb_vfs_close(int fd);
ssize_t smb_vfs_pread(int fd, void *buffer, size_t length, off_t offset);
ssize_t smb_vfs_pwrite(int fd, const void *buffer, size_t length, off_t offset);
int smb_vfs_ftruncate(int fd, off_t length);
int smb_vfs_fsync(int fd);
int smb_vfs_stat(const char *path, struct stat *st);
int smb_vfs_mkdir(const char *path, mode_t mode);
int smb_vfs_unlink(const char *path);
int smb_vfs_rmdir(const char *path);
int smb_vfs_rename(const char *old_path, const char *new_path);

void smb_session_reset(void);
esp_err_t smb_session_allocate_file(
  const char *path,
  int fd,
  uint64_t *smb_file_id);
esp_err_t smb_session_allocate_directory(
  const char *path,
  void *dir,
  uint64_t *smb_file_id);
esp_err_t smb_session_allocate_pipe(uint64_t *smb_file_id);
esp_err_t smb_session_lookup(
  uint64_t smb_file_id,
  smb_session_handle_t **handle);
esp_err_t smb_session_release(uint64_t smb_file_id);
