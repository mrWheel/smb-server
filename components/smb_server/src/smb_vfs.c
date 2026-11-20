//-- smb_server - VFS bridge implementing SMB file operations
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
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "esp_log.h"

#include "smb_internal.h"

static const char *TAG = "smb_vfs";

esp_err_t smb_vfs_validate_mount_point(const char *mount_point)
{
  struct stat st = {0};

  if (mount_point == NULL || mount_point[0] != '/')
  {
    return ESP_ERR_INVALID_ARG;
  }

  if (stat(mount_point, &st) != 0)
  {
    ESP_LOGE(
      TAG,
      "Mount point '%s' is not accessible: errno=%d",
      mount_point,
      errno);
    return ESP_ERR_NOT_FOUND;
  }

  if (!S_ISDIR(st.st_mode))
  {
    ESP_LOGE(TAG, "Mount point '%s' is not a directory", mount_point);
    return ESP_ERR_INVALID_ARG;
  }

  return ESP_OK;
}

int smb_vfs_open(const char *path, int flags, int mode)
{
  return open(path, flags, mode);
}

int smb_vfs_close(int fd)
{
  return close(fd);
}

ssize_t smb_vfs_pread(int fd, void *buffer, size_t length, off_t offset)
{
  if (lseek(fd, offset, SEEK_SET) < 0)
  {
    return -1;
  }

  return read(fd, buffer, length);
}

ssize_t smb_vfs_pwrite(int fd, const void *buffer, size_t length, off_t offset)
{
  if (lseek(fd, offset, SEEK_SET) < 0)
  {
    return -1;
  }

  return write(fd, buffer, length);
}

int smb_vfs_ftruncate(int fd, off_t length)
{
  return ftruncate(fd, length);
}

int smb_vfs_fsync(int fd)
{
  return fsync(fd);
}

int smb_vfs_stat(const char *path, struct stat *st)
{
  return stat(path, st);
}

int smb_vfs_mkdir(const char *path, mode_t mode)
{
  return mkdir(path, mode);
}

int smb_vfs_unlink(const char *path)
{
  return unlink(path);
}

int smb_vfs_rmdir(const char *path)
{
  return rmdir(path);
}

int smb_vfs_rename(const char *old_path, const char *new_path)
{
  return rename(old_path, new_path);
}
