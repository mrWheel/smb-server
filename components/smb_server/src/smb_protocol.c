#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "smb_internal.h"
#include "smb_packet.h"

static const char *TAG = "smb_protocol";

//-- Placeholder volume-size values reported for FileFsSizeInformation queries.
//-- ESP-IDF's VFS layer has no generic statvfs() API, so real free/total space
//-- cannot be queried for an arbitrary mount point; report plausible static values.
#define SMB_FS_SECTOR_SIZE 512
#define SMB_FS_TOTAL_BYTES (512ULL * 1024 * 1024)
#define SMB_FS_FREE_BYTES (256ULL * 1024 * 1024)

//-- Max SMB2 credits granted per response. macOS's kernel SMB2 client requests a
//-- growing credit window as it issues concurrent requests (Finder browsing does
//-- this heavily); always granting only 1 starves that window, the client stalls
//-- waiting for credits, and its reconnect attempts then fail with "Insufficient
//-- credits after reconnect", leaving the session permanently dead.
#define SMB_SERVER_MAX_CREDITS 32

static void smb_protocol_dump_packet(const char *label, const uint8_t *data, size_t length)
{
  //-- Verbose per-packet hex dump; kept at DEBUG level so it does not flood
  //-- the serial monitor buffer and push more targeted INFO/WARN diagnostics
  //-- out of the scrollback during interactive debugging.
  ESP_LOGD(TAG, "%s (%zu bytes):", label, length);
  for (size_t i = 0; i < (length > 200 ? 200 : length); i += 16)
  {
    ESP_LOGD(TAG, "  [%02zu] %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
      i,
      (i + 0 < length) ? data[i + 0] : 0,
      (i + 1 < length) ? data[i + 1] : 0,
      (i + 2 < length) ? data[i + 2] : 0,
      (i + 3 < length) ? data[i + 3] : 0,
      (i + 4 < length) ? data[i + 4] : 0,
      (i + 5 < length) ? data[i + 5] : 0,
      (i + 6 < length) ? data[i + 6] : 0,
      (i + 7 < length) ? data[i + 7] : 0,
      (i + 8 < length) ? data[i + 8] : 0,
      (i + 9 < length) ? data[i + 9] : 0,
      (i + 10 < length) ? data[i + 10] : 0,
      (i + 11 < length) ? data[i + 11] : 0,
      (i + 12 < length) ? data[i + 12] : 0,
      (i + 13 < length) ? data[i + 13] : 0,
      (i + 14 < length) ? data[i + 14] : 0,
      (i + 15 < length) ? data[i + 15] : 0);
  }
}

//-- Protocol state machine
typedef struct
{
  int socket;
  uint64_t message_id;
  bool session_setup_started;
  bool ipc_tree;
  smb2_header_t last_request_header;
} smb_protocol_context_t;

static uint32_t smb_protocol_status_from_errno(int error_number)
{
  switch (error_number)
  {
    case ENOENT:
      return STATUS_OBJECT_NAME_NOT_FOUND;
    case ENOTDIR:
      return STATUS_NOT_A_DIRECTORY;
    case EISDIR:
      return STATUS_FILE_IS_A_DIRECTORY;
    case EEXIST:
      return STATUS_OBJECT_NAME_COLLISION;
    case EACCES:
    case EPERM:
    case EBADF:
      return STATUS_ACCESS_DENIED;
    case ENOSPC:
      return STATUS_DISK_FULL;
    case ENOTEMPTY:
      return STATUS_DIRECTORY_NOT_EMPTY;
    default:
      return STATUS_INVALID_PARAMETER;
  }
}

//-- Grant back at least what the client asked for (SMB2 spec: CreditsGranted
//-- should track CreditsRequested), capped so a single client can't claim the
//-- whole credit pool.
static uint16_t smb_protocol_grant_credits(const smb_protocol_context_t *ctx)
{
  uint16_t requested = ctx->last_request_header.credit_requested;
  if (requested == 0) requested = 1;
  if (requested > SMB_SERVER_MAX_CREDITS) requested = SMB_SERVER_MAX_CREDITS;
  return requested;
}

static int smb_protocol_build_header_response(
  smb_protocol_context_t *ctx,
  uint8_t *response,
  size_t response_capacity,
  uint32_t status,
  size_t body_length,
  size_t *response_length)
{
  if (response_capacity < SMB2_HEADER_SIZE + body_length)
  {
    return -ENOMEM;
  }

  smb2_header_t header = {0};
  header.signature = SMB2_SIGNATURE;
  header.structure_size = SMB2_HEADER_SIZE;
  header.credit_requested = smb_protocol_grant_credits(ctx);
  header.command = ctx->last_request_header.command;
  header.flags = SMB2_FLAGS_SERVER_TO_REDIR;
  header.status = status;
  header.message_id = ctx->last_request_header.message_id;
  header.tree_id = ctx->last_request_header.tree_id;
  header.session_id = ctx->last_request_header.session_id;
  smb2_build_header(response, response_capacity, &header);
  memset(response + SMB2_HEADER_SIZE, 0, body_length);
  *response_length = SMB2_HEADER_SIZE + body_length;
  return 0;
}

static int smb_protocol_variable_data(
  const uint8_t *payload,
  size_t payload_length,
  uint16_t offset,
  uint32_t length,
  const uint8_t **data)
{
  if (offset < SMB2_HEADER_SIZE ||
      (size_t)(offset - SMB2_HEADER_SIZE) > payload_length ||
      length > payload_length - (size_t)(offset - SMB2_HEADER_SIZE))
  {
    return -EINVAL;
  }

  *data = payload + offset - SMB2_HEADER_SIZE;
  return 0;
}

static uint64_t smb_protocol_filetime(time_t seconds)
{
  if (seconds < 0)
  {
    return 0;
  }

  return ((uint64_t)seconds + 11644473600ULL) * 10000000ULL;
}

static void smb_protocol_put_file_id(uint8_t *file_id, uint64_t smb_file_id)
{
  memset(file_id, 0, 16);
  smb2_put_u64_le(file_id, smb_file_id);
}

static uint64_t smb_protocol_get_file_id(const uint8_t *file_id)
{
  return smb2_get_u64_le(file_id);
}

static void smb_protocol_fill_create_response(
  uint8_t *body,
  const struct stat *st,
  uint64_t smb_file_id,
  uint32_t create_action)
{
  smb2_put_u16_le(body, 89);
  body[2] = 0;
  smb2_put_u32_le(body + 4, create_action);
  smb2_put_u64_le(body + 8, smb_protocol_filetime(st->st_ctime));
  smb2_put_u64_le(body + 16, smb_protocol_filetime(st->st_atime));
  smb2_put_u64_le(body + 24, smb_protocol_filetime(st->st_mtime));
  smb2_put_u64_le(body + 32, smb_protocol_filetime(st->st_ctime));
  smb2_put_u64_le(body + 40, (uint64_t)st->st_size);
  smb2_put_u64_le(body + 48, (uint64_t)st->st_size);
  smb2_put_u32_le(body + 56, S_ISDIR(st->st_mode) ? 0x10 : 0x80);
  smb_protocol_put_file_id(body + 64, smb_file_id);
}

//-- Scan the CREATE request's create-context chain for a context named "MxAc"
//-- (Query Maximal Access). Many macOS kernel smbfs mount attempts request
//-- this and stall waiting for a reply, even though it is optional per spec.
static bool smb_protocol_create_request_wants_mxac(
  const uint8_t *request, size_t request_length,
  uint32_t contexts_offset, uint32_t contexts_length)
{
  if (contexts_offset < SMB2_HEADER_SIZE ||
      (size_t)(contexts_offset - SMB2_HEADER_SIZE) > request_length ||
      contexts_length > request_length - (size_t)(contexts_offset - SMB2_HEADER_SIZE))
  {
    return false;
  }

  const uint8_t *chain = request + contexts_offset - SMB2_HEADER_SIZE;
  size_t remaining = contexts_length;
  size_t ctx_offset = 0;

  while (ctx_offset + 16 <= remaining)
  {
    const uint8_t *ctx = chain + ctx_offset;
    uint32_t next = smb2_get_u32_le(ctx);
    uint16_t name_offset = smb2_get_u16_le(ctx + 4);
    uint16_t name_length = smb2_get_u16_le(ctx + 6);

    if (name_length == 4 && (size_t)(name_offset + 4) <= (remaining - ctx_offset))
    {
      if (memcmp(ctx + name_offset, "MxAc", 4) == 0)
      {
        return true;
      }
    }

    if (next == 0) break;
    ctx_offset += next;
  }

  return false;
}

//-- Appends a 32-byte "MxAc" (Query Maximal Access) create-context response
//-- after the fixed 88-byte CREATE response body, and updates its
//-- CreateContextsOffset/Length fields accordingly.
static size_t smb_protocol_append_mxac_context(uint8_t *body, size_t body_offset)
{
  uint8_t *ctx = body + body_offset;
  smb2_put_u32_le(ctx + 0, 0);        //-- Next (last context)
  smb2_put_u16_le(ctx + 4, 16);       //-- NameOffset (right after fixed header)
  smb2_put_u16_le(ctx + 6, 4);        //-- NameLength ("MxAc")
  smb2_put_u16_le(ctx + 8, 0);        //-- Reserved
  smb2_put_u16_le(ctx + 10, 24);      //-- DataOffset
  smb2_put_u32_le(ctx + 12, 8);       //-- DataLength
  memcpy(ctx + 16, "MxAc", 4);
  smb2_put_u32_le(ctx + 24, 0);              //-- QueryStatus = STATUS_SUCCESS
  smb2_put_u32_le(ctx + 28, 0x001f01ff);     //-- MaximalAccess (full access)

  //-- CreateContextsOffset/Length live in the fixed body at offsets 80/84
  smb2_put_u32_le(body + 80, (uint32_t)(SMB2_HEADER_SIZE + body_offset));
  smb2_put_u32_le(body + 84, 32);

  return 32;
}

static int smb_protocol_handle_create(
  smb_protocol_context_t *ctx,
  const uint8_t *request,
  size_t request_length,
  uint8_t *response,
  size_t response_capacity,
  size_t *response_length)
{
  if (request_length < sizeof(smb2_create_request_t))
  {
    return -EINVAL;
  }

  const smb2_create_request_t *req = (const smb2_create_request_t *)request;
  uint16_t name_offset = smb2_get_u16_le((const uint8_t *)&req->name_offset);
  uint16_t name_length = smb2_get_u16_le((const uint8_t *)&req->name_length);
  uint32_t disposition = smb2_get_u32_le((const uint8_t *)&req->create_disposition);
  uint32_t options = smb2_get_u32_le((const uint8_t *)&req->create_options);
  uint32_t contexts_offset = smb2_get_u32_le((const uint8_t *)&req->create_contexts_offset);
  uint32_t contexts_length = smb2_get_u32_le((const uint8_t *)&req->create_contexts_length);
  bool wants_mxac = contexts_offset != 0 && contexts_length != 0 &&
    smb_protocol_create_request_wants_mxac(request, request_length, contexts_offset, contexts_length);
  ESP_LOGI(TAG, "CREATE fields: struct=%u name_offset=%u name_length=%u disposition=%u options=0x%08x",
    smb2_get_u16_le(request), name_offset, name_length, disposition, options);
  const uint8_t *name_data = NULL;
  if (smb_protocol_variable_data(request, request_length, name_offset, name_length, &name_data) != 0)
  {
    return -EINVAL;
  }

  char smb_name[SMB_SERVER_PATH_MAX];
  if (smb_path_utf16le_to_utf8(name_data, name_length, smb_name, sizeof(smb_name)) != ESP_OK)
  {
    return -EINVAL;
  }

  if (ctx->ipc_tree && strcasecmp(smb_name, "srvsvc") == 0)
  {
    uint64_t smb_file_id = 0;
    if (smb_session_allocate_pipe(&smb_file_id) != ESP_OK)
    {
      return smb_protocol_build_header_response(ctx, response, response_capacity,
        STATUS_INSUFFICIENT_RESOURCES, 0, response_length);
    }

    struct stat pipe_stat = {0};
    pipe_stat.st_mode = S_IFIFO | 0666;
    size_t body_length = wants_mxac ? 88 + 32 : 88;
    if (smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_SUCCESS, body_length, response_length) != 0)
    {
      smb_session_release(smb_file_id);
      return -ENOMEM;
    }
    smb_protocol_fill_create_response(response + SMB2_HEADER_SIZE, &pipe_stat, smb_file_id, 1);
    if (wants_mxac)
    {
      smb_protocol_append_mxac_context(response + SMB2_HEADER_SIZE, 88);
    }
    ESP_LOGI(TAG, "CREATE srvsvc pipe: file_id=%llu", smb_file_id);
    return 0;
  }

  char path[SMB_SERVER_PATH_MAX];
  if (smb_path_resolve(g_smb_server_state.mount_point, smb_name, path, sizeof(path)) != ESP_OK)
  {
    return smb_protocol_build_header_response(ctx, response, response_capacity,
      STATUS_ACCESS_DENIED, 0, response_length);
  }

  bool directory_requested = (options & FILE_DIRECTORY_FILE) != 0;
  struct stat st = {0};
  bool exists = smb_vfs_stat(path, &st) == 0;
  uint32_t status = STATUS_SUCCESS;
  uint32_t create_action = exists ? 1 : 2;
  smb_session_handle_t *unused_handle = NULL;
  (void)unused_handle;
  uint64_t smb_file_id = 0;

  if (exists && disposition == FILE_CREATE)
  {
    status = STATUS_OBJECT_NAME_COLLISION;
  }
  else if (!exists && (disposition == FILE_OPEN || disposition == FILE_OVERWRITE))
  {
    status = smb_protocol_status_from_errno(errno);
  }
  else if (exists && directory_requested && !S_ISDIR(st.st_mode))
  {
    status = STATUS_NOT_A_DIRECTORY;
  }
  else if (exists && !directory_requested && S_ISDIR(st.st_mode))
  {
    status = STATUS_FILE_IS_A_DIRECTORY;
  }
  else if (g_smb_server_state.config.read_only &&
           (!exists || disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF ||
            disposition == FILE_SUPERSEDE || disposition == FILE_CREATE))
  {
    status = STATUS_ACCESS_DENIED;
  }
  else if (directory_requested)
  {
    if (!exists && smb_vfs_mkdir(path, 0777) != 0)
    {
      status = smb_protocol_status_from_errno(errno);
    }
    else
    {
      DIR *directory = opendir(path);
      if (directory == NULL)
      {
        status = smb_protocol_status_from_errno(errno);
      }
      else if (smb_session_allocate_directory(path, directory, &smb_file_id) != ESP_OK)
      {
        closedir(directory);
        status = STATUS_INSUFFICIENT_RESOURCES;
      }
      else
      {
        smb_vfs_stat(path, &st);
      }
    }
  }
  else
  {
    int flags = O_RDONLY;
    if (!exists || disposition == FILE_OPEN_IF || disposition == FILE_CREATE ||
        disposition == FILE_OVERWRITE_IF)
    {
      flags |= O_CREAT;
    }
    if (disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF || disposition == FILE_SUPERSEDE)
    {
      flags |= O_TRUNC;
      create_action = 3;
    }
    if (!g_smb_server_state.config.read_only)
    {
      flags = (flags & ~O_ACCMODE) | O_RDWR;
    }

    int fd = smb_vfs_open(path, flags, 0666);
    if (fd < 0)
    {
      status = smb_protocol_status_from_errno(errno);
    }
    else if (smb_session_allocate_file(path, fd, &smb_file_id) != ESP_OK)
    {
      smb_vfs_close(fd);
      status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
      smb_vfs_stat(path, &st);
    }
  }

  if (status != STATUS_SUCCESS)
  {
    ESP_LOGW(TAG, "CREATE failed: path='%s' status=0x%08x", path, status);
    return smb_protocol_build_header_response(ctx, response, response_capacity, status, 0, response_length);
  }

  if (options & FILE_DELETE_ON_CLOSE)
  {
    smb_session_handle_t *handle = NULL;
    if (smb_session_lookup(smb_file_id, &handle) == ESP_OK)
    {
      handle->delete_pending = true;
    }
  }

  if (smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_SUCCESS,
      wants_mxac ? 88 + 32 : 88, response_length) != 0)
  {
    return -ENOMEM;
  }
  smb_protocol_fill_create_response(response + SMB2_HEADER_SIZE, &st, smb_file_id, create_action);
  if (wants_mxac)
  {
    smb_protocol_append_mxac_context(response + SMB2_HEADER_SIZE, 88);
  }
  return 0;
}

static int smb_protocol_handle_close(
  smb_protocol_context_t *ctx, const uint8_t *request, size_t request_length,
  uint8_t *response, size_t response_capacity, size_t *response_length)
{
  if (request_length < sizeof(smb2_close_request_t))
  {
    return -EINVAL;
  }

  const smb2_close_request_t *req = (const smb2_close_request_t *)request;
  uint64_t file_id = smb_protocol_get_file_id(req->file_id);
  smb_session_handle_t *handle = NULL;
  uint32_t status = STATUS_SUCCESS;
  struct stat st = {0};
  bool have_stat = false;
  if (smb_session_lookup(file_id, &handle) != ESP_OK)
  {
    status = STATUS_INVALID_PARAMETER;
  }
  else
  {
    //-- Capture attributes before releasing the handle; macOS's kernel client
    //-- rejects a CLOSE response with all-zero attributes ("did not return
    //-- close attributes") and logs a "Bad SMB 2/3 Server" kernel error.
    have_stat = smb_vfs_stat(handle->path, &st) == 0;
    if (handle->delete_pending)
    {
      int result = handle->is_directory ? smb_vfs_rmdir(handle->path) : smb_vfs_unlink(handle->path);
      if (result != 0)
      {
        status = smb_protocol_status_from_errno(errno);
      }
      else
      {
        have_stat = false;
      }
    }
    smb_session_release(file_id);
  }

  if (smb_protocol_build_header_response(ctx, response, response_capacity, status,
      status == STATUS_SUCCESS ? 60 : 0, response_length) != 0)
  {
    return -ENOMEM;
  }
  if (status == STATUS_SUCCESS)
  {
    uint8_t *body = response + SMB2_HEADER_SIZE;
    smb2_put_u16_le(body, 60);
    if (have_stat)
    {
      smb2_put_u64_le(body + 8, smb_protocol_filetime(st.st_ctime));
      smb2_put_u64_le(body + 16, smb_protocol_filetime(st.st_atime));
      smb2_put_u64_le(body + 24, smb_protocol_filetime(st.st_mtime));
      smb2_put_u64_le(body + 32, smb_protocol_filetime(st.st_ctime));
      smb2_put_u64_le(body + 40, (uint64_t)st.st_size);
      smb2_put_u64_le(body + 48, (uint64_t)st.st_size);
      smb2_put_u32_le(body + 56, S_ISDIR(st.st_mode) ? 0x10 : 0x80);
    }
  }
  return 0;
}

static int smb_protocol_handle_read(
  smb_protocol_context_t *ctx, const uint8_t *request, size_t request_length,
  uint8_t *response, size_t response_capacity, size_t *response_length)
{
  if (request_length < sizeof(smb2_read_request_t)) return -EINVAL;
  const smb2_read_request_t *req = (const smb2_read_request_t *)request;
  smb_session_handle_t *handle = NULL;
  if (smb_session_lookup(smb_protocol_get_file_id(req->file_id), &handle) != ESP_OK)
    return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_INVALID_PARAMETER, 0, response_length);
  if (handle->is_pipe)
  {
    if (smb_protocol_build_header_response(ctx, response, response_capacity,
        STATUS_END_OF_FILE, 0, response_length) != 0)
    {
      return -ENOMEM;
    }
    return 0;
  }
  if (handle->is_directory)
    return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_FILE_IS_A_DIRECTORY, 0, response_length);

  uint32_t requested = smb2_get_u32_le((const uint8_t *)&req->length);
  size_t capacity = response_capacity - SMB2_HEADER_SIZE - 16;
  size_t length = requested < capacity ? requested : capacity;
  uint64_t offset = smb2_get_u64_le((const uint8_t *)&req->offset);
  ssize_t read_length = smb_vfs_pread(handle->fd, response + SMB2_HEADER_SIZE + 16, length, (off_t)offset);
  if (read_length < 0)
    return smb_protocol_build_header_response(ctx, response, response_capacity, smb_protocol_status_from_errno(errno), 0, response_length);
  if (read_length == 0)
    return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_END_OF_FILE, 0, response_length);
  if (smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_SUCCESS, 16 + (size_t)read_length, response_length) != 0)
    return -ENOMEM;
  uint8_t *body = response + SMB2_HEADER_SIZE;
  smb2_put_u16_le(body, 17);
  body[2] = SMB2_HEADER_SIZE + 16;
  smb2_put_u32_le(body + 4, (uint32_t)read_length);
  return 0;
}

static int smb_protocol_handle_write(
  smb_protocol_context_t *ctx, const uint8_t *request, size_t request_length,
  uint8_t *response, size_t response_capacity, size_t *response_length)
{
  if (request_length < sizeof(smb2_write_request_t)) return -EINVAL;
  const smb2_write_request_t *req = (const smb2_write_request_t *)request;
  uint16_t data_offset = smb2_get_u16_le((const uint8_t *)&req->data_offset);
  uint32_t data_length = smb2_get_u32_le((const uint8_t *)&req->data_length);
  const uint8_t *data = NULL;
  if (smb_protocol_variable_data(request, request_length, data_offset, data_length, &data) != 0) return -EINVAL;
  smb_session_handle_t *handle = NULL;
  if (smb_session_lookup(smb_protocol_get_file_id(req->file_id), &handle) != ESP_OK)
    return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_INVALID_PARAMETER, 0, response_length);
  if (g_smb_server_state.config.read_only) return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_ACCESS_DENIED, 0, response_length);
  if (handle->is_directory || handle->is_pipe) return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_FILE_IS_A_DIRECTORY, 0, response_length);
  ssize_t written = smb_vfs_pwrite(handle->fd, data, data_length, (off_t)smb2_get_u64_le((const uint8_t *)&req->offset));
  if (written < 0) return smb_protocol_build_header_response(ctx, response, response_capacity, smb_protocol_status_from_errno(errno), 0, response_length);
  if (smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_SUCCESS, 16, response_length) != 0) return -ENOMEM;
  smb2_put_u16_le(response + SMB2_HEADER_SIZE, 17);
  smb2_put_u32_le(response + SMB2_HEADER_SIZE + 4, (uint32_t)written);
  return 0;
}

static size_t smb_protocol_fill_file_info(
  uint8_t *output,
  size_t capacity,
  uint8_t info_class,
  const struct stat *st,
  const char *path)
{
  uint64_t creation_time = smb_protocol_filetime(st->st_ctime);
  uint64_t access_time = smb_protocol_filetime(st->st_atime);
  uint64_t write_time = smb_protocol_filetime(st->st_mtime);
  uint64_t size = (uint64_t)st->st_size;
  uint32_t attributes = S_ISDIR(st->st_mode) ? 0x10 : 0x80;
  size_t name_length = strlen(path) * 2;

  if (info_class == FileBasicInformation)
  {
    if (capacity < 40) return 0;
    smb2_put_u64_le(output, creation_time);
    smb2_put_u64_le(output + 8, access_time);
    smb2_put_u64_le(output + 16, write_time);
    smb2_put_u64_le(output + 24, creation_time);
    smb2_put_u32_le(output + 32, attributes);
    return 40;
  }
  if (info_class == FileStandardInformation)
  {
    if (capacity < 24) return 0;
    smb2_put_u64_le(output, size);
    smb2_put_u64_le(output + 8, size);
    smb2_put_u32_le(output + 16, 1);
    output[20] = 0;
    output[21] = S_ISDIR(st->st_mode) ? 1 : 0;
    return 24;
  }
  if (info_class == FileNetworkOpenInformation)
  {
    if (capacity < 56) return 0;
    smb2_put_u64_le(output, creation_time);
    smb2_put_u64_le(output + 8, access_time);
    smb2_put_u64_le(output + 16, write_time);
    smb2_put_u64_le(output + 24, creation_time);
    smb2_put_u64_le(output + 32, size);
    smb2_put_u64_le(output + 40, size);
    smb2_put_u32_le(output + 48, attributes);
    return 56;
  }
  if (info_class == FileAllInformation)
  {
    if (capacity < 100 + name_length) return 0;
    size_t basic_length = smb_protocol_fill_file_info(output, capacity, FileBasicInformation, st, path);
    smb_protocol_fill_file_info(output + basic_length, capacity - basic_length, FileStandardInformation, st, path);
    memset(output + 64, 0, 36);
    smb2_put_u32_le(output + 96, (uint32_t)name_length);
    for (size_t index = 0; index < strlen(path); index++)
    {
      output[100 + index * 2] = (uint8_t)path[index];
    }
    return 100 + name_length;
  }

  return 0;
}

static int smb_protocol_handle_query_info(
  smb_protocol_context_t *ctx, const uint8_t *request, size_t request_length,
  uint8_t *response, size_t response_capacity, size_t *response_length)
{
  if (request_length < sizeof(smb2_query_info_request_t)) return -EINVAL;
  const smb2_query_info_request_t *req = (const smb2_query_info_request_t *)request;
  uint8_t info_type = req->info_type;
  uint8_t info_class = req->file_info_class;
  ESP_LOGI(TAG, "QUERY_INFO: info_type=0x%02x, info_class=%u", info_type, info_class);
  if (info_type == SMB2_0_INFO_FILESYSTEM)
  {
    if (info_class != FileFsSizeInformation)
      return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_NOT_SUPPORTED, 0, response_length);
    uint32_t requested = smb2_get_u32_le((const uint8_t *)&req->output_buffer_length);
    size_t capacity = response_capacity - SMB2_HEADER_SIZE - 8;
    if (requested < capacity) capacity = requested;
    if (capacity < 24)
      return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_NOT_SUPPORTED, 0, response_length);
    uint8_t *info = response + SMB2_HEADER_SIZE + 8;
    smb2_put_u64_le(info, SMB_FS_TOTAL_BYTES / SMB_FS_SECTOR_SIZE);
    smb2_put_u64_le(info + 8, SMB_FS_FREE_BYTES / SMB_FS_SECTOR_SIZE);
    smb2_put_u32_le(info + 16, 1);
    smb2_put_u32_le(info + 20, SMB_FS_SECTOR_SIZE);
    if (smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_SUCCESS, 8 + 24, response_length) != 0) return -ENOMEM;
    smb2_put_u16_le(response + SMB2_HEADER_SIZE, 9);
    smb2_put_u16_le(response + SMB2_HEADER_SIZE + 2, SMB2_HEADER_SIZE + 8);
    smb2_put_u32_le(response + SMB2_HEADER_SIZE + 4, 24);
    return 0;
  }
  if (info_type != SMB2_0_INFO_FILE)
    return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_NOT_SUPPORTED, 0, response_length);
  smb_session_handle_t *handle = NULL;
  if (smb_session_lookup(smb_protocol_get_file_id(req->file_id), &handle) != ESP_OK)
    return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_INVALID_PARAMETER, 0, response_length);
  struct stat st = {0};
  if (smb_vfs_stat(handle->path, &st) != 0)
    return smb_protocol_build_header_response(ctx, response, response_capacity, smb_protocol_status_from_errno(errno), 0, response_length);
  uint32_t requested = smb2_get_u32_le((const uint8_t *)&req->output_buffer_length);
  size_t capacity = response_capacity - SMB2_HEADER_SIZE - 8;
  if (requested < capacity) capacity = requested;
  size_t info_length = smb_protocol_fill_file_info(response + SMB2_HEADER_SIZE + 8, capacity, info_class, &st, handle->path);
  if (info_length == 0)
    return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_NOT_SUPPORTED, 0, response_length);
  if (smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_SUCCESS, 8 + info_length, response_length) != 0) return -ENOMEM;
  smb2_put_u16_le(response + SMB2_HEADER_SIZE, 9);
  smb2_put_u16_le(response + SMB2_HEADER_SIZE + 2, SMB2_HEADER_SIZE + 8);
  smb2_put_u32_le(response + SMB2_HEADER_SIZE + 4, (uint32_t)info_length);
  return 0;
}

static int smb_protocol_handle_set_info(
  smb_protocol_context_t *ctx, const uint8_t *request, size_t request_length,
  uint8_t *response, size_t response_capacity, size_t *response_length)
{
  if (request_length < sizeof(smb2_set_info_request_t)) return -EINVAL;
  const smb2_set_info_request_t *req = (const smb2_set_info_request_t *)request;
  smb_session_handle_t *handle = NULL;
  if (smb_session_lookup(smb_protocol_get_file_id(req->file_id), &handle) != ESP_OK)
    return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_INVALID_PARAMETER, 0, response_length);
  uint16_t buffer_offset = smb2_get_u16_le((const uint8_t *)&req->buffer_offset);
  uint32_t buffer_length = smb2_get_u32_le((const uint8_t *)&req->buffer_length);
  const uint8_t *buffer = NULL;
  if (buffer_length != 0 && smb_protocol_variable_data(request, request_length, buffer_offset, buffer_length, &buffer) != 0) return -EINVAL;
  uint32_t status = STATUS_SUCCESS;
  if (req->info_type != SMB2_0_INFO_FILE)
  {
    status = STATUS_NOT_SUPPORTED;
  }
  else if (req->file_info_class == FileDispositionInformation)
  {
    if (g_smb_server_state.config.read_only || buffer == NULL || buffer_length < 1)
      status = STATUS_ACCESS_DENIED;
    else
      handle->delete_pending = buffer[0] != 0;
  }
  else if (req->file_info_class == FileEndOfFileInformation)
  {
    if (g_smb_server_state.config.read_only || handle->is_directory || handle->is_pipe || buffer == NULL || buffer_length < 8)
      status = STATUS_ACCESS_DENIED;
    else if (smb_vfs_ftruncate(handle->fd, (off_t)smb2_get_u64_le(buffer)) != 0)
      status = smb_protocol_status_from_errno(errno);
  }
  else if (req->file_info_class == FileBasicInformation)
  {
    ESP_LOGD(TAG, "FileBasicInformation acknowledged for '%s'", handle->path);
  }
  else
  {
    status = STATUS_NOT_SUPPORTED;
  }
  return smb_protocol_build_header_response(ctx, response, response_capacity, status, status == STATUS_SUCCESS ? 2 : 0, response_length);
}

//-- Convert Unix time to Windows FILETIME (100-nanosecond intervals since 1601-01-01)
static uint64_t smb_protocol_unix_to_filetime(time_t unix_time)
{
  //-- Unix epoch: 1970-01-01, Windows epoch: 1601-01-01
  //-- Difference: 116444736000000000 (100-ns intervals)
  const uint64_t EPOCH_DIFF = 116444736000000000ULL;
  return (uint64_t)unix_time * 10000000ULL + EPOCH_DIFF;
}

static int smb_protocol_handle_query_directory(
  smb_protocol_context_t *ctx, const uint8_t *request, size_t request_length,
  uint8_t *response, size_t response_capacity, size_t *response_length)
{
  if (request_length < sizeof(smb2_query_directory_request_t))
    return -EINVAL;

  const smb2_query_directory_request_t *req = (const smb2_query_directory_request_t *)request;
  uint8_t file_info_class = req->file_information_class;
  uint8_t flags = req->flags;

  ESP_LOGI(TAG, "QUERY_DIRECTORY: file_info_class=%u flags=0x%02x", file_info_class, flags);

  if (file_info_class != FileIdBothDirectoryInformation)
    return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_NOT_SUPPORTED, 0, response_length);

  smb_session_handle_t *handle = NULL;
  if (smb_session_lookup(smb_protocol_get_file_id(req->file_id), &handle) != ESP_OK)
    return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_INVALID_PARAMETER, 0, response_length);

  if (!handle->is_directory)
    return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_NOT_A_DIRECTORY, 0, response_length);

  //-- SMB2 QUERY_DIRECTORY flags (MS-SMB2 2.2.33)
  #define SL_RESTART_SCAN 0x01
  #define SL_RETURN_SINGLE_ENTRY 0x02

  if ((flags & SL_RESTART_SCAN) != 0)
    rewinddir((DIR *)handle->dir);

  bool single_entry_only = (flags & SL_RETURN_SINGLE_ENTRY) != 0;

  uint8_t *buffer = response + SMB2_HEADER_SIZE + 8;
  size_t buffer_size = response_capacity - SMB2_HEADER_SIZE - 8;
  size_t buffer_used = 0;
  size_t entry_count = 0;
  struct dirent *entry;

  ESP_LOGI(TAG, "QUERY_DIRECTORY: listing '%s'", handle->path);

  //-- Offset (within buffer) and aligned size of the previously written entry,
  //-- so its NextEntryOffset can be patched in once the following entry's
  //-- position is known. (size_t)-1 means "no previous entry yet".
  size_t prev_entry_offset = (size_t)-1;
  size_t prev_entry_aligned_size = 0;

  while ((entry = readdir((DIR *)handle->dir)) != NULL && buffer_used < buffer_size)
  {
    ESP_LOGI(TAG, "QUERY_DIRECTORY: readdir -> '%s'", entry->d_name);
    size_t name_len = strlen(entry->d_name);
    if (name_len > 127)
      continue;

    //-- Calculate UTF-16LE length (2 bytes per ASCII char + 2 for null)
    uint16_t file_name_utf16_len = (name_len * 2) + 2;
    size_t entry_size = 104 + file_name_utf16_len;
    size_t next_entry_aligned = (entry_size + 7) & ~7;

    if (buffer_used + next_entry_aligned > buffer_size)
      break;

    //-- Get file stat
    char entry_path[256];
    size_t path_len = strlen(handle->path);
    if (path_len + 1 + name_len >= sizeof(entry_path))
      continue;
    memcpy(entry_path, handle->path, path_len);
    entry_path[path_len] = '/';
    memcpy(entry_path + path_len + 1, entry->d_name, name_len);
    entry_path[path_len + 1 + name_len] = 0;

    struct stat st = {0};
    if (smb_vfs_stat(entry_path, &st) != 0)
    {
      ESP_LOGW(TAG, "QUERY_DIRECTORY: stat('%s') failed: %d", entry_path, errno);
      continue;
    }
    entry_count++;

    //-- Link the previous entry to this one now that its offset is known
    if (prev_entry_offset != (size_t)-1)
      smb2_put_u32_le(buffer + prev_entry_offset, (uint32_t)prev_entry_aligned_size);

    //-- Fill structure in response buffer
    uint8_t *entry_ptr = buffer + buffer_used;
    memset(entry_ptr, 0, 104);

    smb2_put_u32_le(entry_ptr + 0, 0);
    smb2_put_u32_le(entry_ptr + 4, 0);

    uint64_t filetime = smb_protocol_unix_to_filetime(st.st_mtime);
    smb2_put_u64_le(entry_ptr + 8, filetime);
    smb2_put_u64_le(entry_ptr + 16, filetime);
    smb2_put_u64_le(entry_ptr + 24, filetime);
    smb2_put_u64_le(entry_ptr + 32, filetime);

    smb2_put_u64_le(entry_ptr + 40, (uint64_t)st.st_size);

    uint64_t alloc_size = ((st.st_size + 4095) / 4096) * 4096;
    smb2_put_u64_le(entry_ptr + 48, alloc_size);

    uint32_t attrs = S_ISDIR(st.st_mode) ? 0x10 : 0;
    smb2_put_u32_le(entry_ptr + 56, attrs);
    smb2_put_u32_le(entry_ptr + 60, file_name_utf16_len - 2);
    smb2_put_u32_le(entry_ptr + 64, 0);
    entry_ptr[68] = 0;
    entry_ptr[69] = 0;
    //-- ShortName (24 bytes, offset 70-93) and Reserved2 (2 bytes, offset 94-95)
    //-- are left zeroed from the memset above; we don't populate 8.3 names.
    smb2_put_u64_le(entry_ptr + 96, (uint64_t)st.st_ino);

    //-- Encode filename as UTF-16LE directly into response
    uint8_t *fname_ptr = entry_ptr + 104;
    for (size_t i = 0; i < name_len; i++)
    {
      fname_ptr[i * 2] = entry->d_name[i];
      fname_ptr[i * 2 + 1] = 0;
    }
    fname_ptr[name_len * 2] = 0;
    fname_ptr[name_len * 2 + 1] = 0;

    prev_entry_offset = buffer_used;
    prev_entry_aligned_size = next_entry_aligned;

    buffer_used += next_entry_aligned;

    if (single_entry_only)
      break;
  }

  ESP_LOGI(TAG, "QUERY_DIRECTORY: %zu entries returned, %zu bytes", entry_count, buffer_used);

  if (buffer_used == 0)
    return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_NO_MORE_FILES, 0, response_length);

  if (smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_SUCCESS, 8 + buffer_used, response_length) != 0)
    return -ENOMEM;

  smb2_put_u16_le(response + SMB2_HEADER_SIZE, 9);
  smb2_put_u16_le(response + SMB2_HEADER_SIZE + 2, SMB2_HEADER_SIZE + 8);
  smb2_put_u32_le(response + SMB2_HEADER_SIZE + 4, (uint32_t)buffer_used);

  return 0;
}

static int smb_protocol_handle_ioctl(
  smb_protocol_context_t *ctx,
  const uint8_t *request,
  size_t request_length,
  uint8_t *response,
  size_t response_capacity,
  size_t *response_length)
{
  if (request_length < 56)
  {
    return smb_protocol_build_header_response(ctx, response, response_capacity,
      STATUS_INVALID_PARAMETER, 0, response_length);
  }

  uint32_t control_code = smb2_get_u32_le(request + 4);
  uint32_t input_offset = smb2_get_u32_le(request + 24);
  uint32_t input_count = smb2_get_u32_le(request + 28);
  ESP_LOGI(TAG, "IOCTL request: control_code=0x%08x", control_code);
  if (input_offset >= SMB2_HEADER_SIZE &&
      (size_t)(input_offset - SMB2_HEADER_SIZE) <= request_length &&
      input_count <= request_length - (size_t)(input_offset - SMB2_HEADER_SIZE))
  {
    smb_protocol_dump_packet("IOCTL input", request + input_offset - SMB2_HEADER_SIZE, input_count);
  }

  const uint8_t *ioctl_input = NULL;
  if (input_offset >= SMB2_HEADER_SIZE &&
      (size_t)(input_offset - SMB2_HEADER_SIZE) <= request_length &&
      input_count <= request_length - (size_t)(input_offset - SMB2_HEADER_SIZE))
  {
    ioctl_input = request + input_offset - SMB2_HEADER_SIZE;
  }

  static const uint8_t bind_ack_template[] =
    {
      0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00,
      0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
      0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
      0x2b, 0x10, 0x48, 0x60,
      0x02, 0x00, 0x00, 0x00
    };

  if (control_code == 0x0011c017 && ioctl_input != NULL && input_count >= 24 &&
      ioctl_input[2] == 0x00 && smb2_get_u16_le(ioctl_input + 22) == 0x000f)
  {
    uint8_t rpc_response[512] = {0};
    size_t rpc_length = 24;
    size_t share_name_length = strlen(g_smb_server_state.share_name);
    if (share_name_length > SMB_SERVER_SHARE_NAME_MAX - 2)
      share_name_length = SMB_SERVER_SHARE_NAME_MAX - 2;

    //-- SHARE_ENUM_STRUCT { Level (discriminator); union { ... } }
    smb2_put_u32_le(rpc_response + rpc_length, 1);
    rpc_length += 4;

    //-- Union switch_is(Level) discriminator (redundant, repeats Level)
    smb2_put_u32_le(rpc_response + rpc_length, 1);
    rpc_length += 4;

    //-- Level1: unique pointer to SHARE_INFO_1_CONTAINER
    smb2_put_u32_le(rpc_response + rpc_length, 0x00020000);
    rpc_length += 4;

    //-- Deferred SHARE_INFO_1_CONTAINER { EntriesRead; Buffer (ptr to array) }
    smb2_put_u32_le(rpc_response + rpc_length, 1);
    rpc_length += 4;

    //-- Buffer: unique pointer to the SHARE_INFO_1 array
    smb2_put_u32_le(rpc_response + rpc_length, 0x00020004);
    rpc_length += 4;

    //-- Deferred array: conformant array MaximumCount (element count)
    smb2_put_u32_le(rpc_response + rpc_length, 1);
    rpc_length += 4;

    //-- SHARE_INFO_1[0] base structure:
    //--   - NetName (pointer to string)
    //--   - Type (uint32)
    //--   - Remark (pointer to string)
    smb2_put_u32_le(rpc_response + rpc_length, 0x00020008);
    rpc_length += 4;

    smb2_put_u32_le(rpc_response + rpc_length, 0);
    rpc_length += 4;

    smb2_put_u32_le(rpc_response + rpc_length, 0x0002000c);
    rpc_length += 4;

    //-- Deferred data starts: Share name string (ndr_string: max, offset, actual, data)
    smb2_put_u32_le(rpc_response + rpc_length, (uint32_t)(share_name_length + 1));
    rpc_length += 4;
    smb2_put_u32_le(rpc_response + rpc_length, 0);
    rpc_length += 4;
    smb2_put_u32_le(rpc_response + rpc_length, (uint32_t)(share_name_length + 1));
    rpc_length += 4;

    for (size_t i = 0; i < share_name_length; i++)
    {
      smb2_put_u16_le(rpc_response + rpc_length, (uint16_t)g_smb_server_state.share_name[i]);
      rpc_length += 2;
    }
    smb2_put_u16_le(rpc_response + rpc_length, 0);
    rpc_length += 2;

    //-- Align to 4-byte boundary
    while ((rpc_length & 3U) != 0)
      rpc_response[rpc_length++] = 0;

    //-- Remark string (empty: max=1, offset=0, actual=1, single null terminator)
    smb2_put_u32_le(rpc_response + rpc_length, 1);
    rpc_length += 4;
    smb2_put_u32_le(rpc_response + rpc_length, 0);
    rpc_length += 4;
    smb2_put_u32_le(rpc_response + rpc_length, 1);
    rpc_length += 4;
    smb2_put_u16_le(rpc_response + rpc_length, 0);
    rpc_length += 2;

    //-- Align to 4-byte boundary
    while ((rpc_length & 3U) != 0)
      rpc_response[rpc_length++] = 0;

    //-- Output parameters: TotalEntries (out)
    smb2_put_u32_le(rpc_response + rpc_length, 1);
    rpc_length += 4;

    //-- ResumeHandle (out, NULL = 0)
    smb2_put_u32_le(rpc_response + rpc_length, 0);
    rpc_length += 4;

    //-- WERROR return (0 = WERROR_OK = 0x00000000)
    smb2_put_u32_le(rpc_response + rpc_length, 0);
    rpc_length += 4;

    //-- Build DCE/RPC RESPONSE header (24 bytes)
    rpc_response[0] = 5;
    rpc_response[1] = 0;
    rpc_response[2] = 2;
    rpc_response[3] = 3;
    rpc_response[4] = 0x10;
    rpc_response[5] = 0;
    rpc_response[6] = 0;
    rpc_response[7] = 0;
    smb2_put_u16_le(rpc_response + 8, (uint16_t)rpc_length);
    smb2_put_u16_le(rpc_response + 10, 0);
    smb2_put_u32_le(rpc_response + 12, smb2_get_u32_le(ioctl_input + 12));
    smb2_put_u32_le(rpc_response + 16, (uint32_t)(rpc_length - 24));
    smb2_put_u16_le(rpc_response + 20, 0);
    rpc_response[22] = 0;
    rpc_response[23] = 0;

    size_t body_length = 48 + rpc_length;
    if (response_capacity < SMB2_HEADER_SIZE + body_length)
      return -ENOMEM;

    if (smb_protocol_build_header_response(ctx, response, response_capacity,
        STATUS_SUCCESS, body_length, response_length) != 0)
      return -ENOMEM;

    uint8_t *body = response + SMB2_HEADER_SIZE;
    smb2_put_u16_le(body, 49);
    smb2_put_u32_le(body + 4, control_code);
    memcpy(body + 8, request + 8, 16);
    smb2_put_u32_le(body + 32, SMB2_HEADER_SIZE + 48);
    smb2_put_u32_le(body + 36, (uint32_t)rpc_length);
    memcpy(body + 48, rpc_response, rpc_length);

    ESP_LOGI(TAG, "NetrShareEnum: sent %zu bytes", rpc_length);
    return 0;
  }

  if (control_code == 0x0011c017 && ioctl_input != NULL && input_count >= 16 &&
      ioctl_input[2] == 0x0b)
  {
    uint8_t bind_ack[sizeof(bind_ack_template)];
    memcpy(bind_ack, bind_ack_template, sizeof(bind_ack));
    if (input_count >= 16)
    {
      memcpy(bind_ack + 12, ioctl_input + 12, 4);
    }

    const size_t body_length = 48 + sizeof(bind_ack);
    if (response_capacity < SMB2_HEADER_SIZE + body_length)
    {
      return -ENOMEM;
    }
    if (smb_protocol_build_header_response(ctx, response, response_capacity,
        STATUS_SUCCESS, body_length, response_length) != 0)
    {
      return -ENOMEM;
    }
    uint8_t *body = response + SMB2_HEADER_SIZE;
    smb2_put_u16_le(body, 49);
    smb2_put_u32_le(body + 4, control_code);
    memcpy(body + 8, request + 8, 16);
    smb2_put_u32_le(body + 32, SMB2_HEADER_SIZE + 48);
    smb2_put_u32_le(body + 36, sizeof(bind_ack));
    memcpy(body + 48, bind_ack, sizeof(bind_ack));
    ESP_LOGI(TAG, "DCE/RPC BIND acknowledged");
    return 0;
  }

  if (response_capacity < SMB2_HEADER_SIZE + 48)
  {
    return -ENOMEM;
  }

  if (smb_protocol_build_header_response(ctx, response, response_capacity,
      STATUS_NOT_SUPPORTED, 48, response_length) != 0)
  {
    return -ENOMEM;
  }

  uint8_t *body = response + SMB2_HEADER_SIZE;
  smb2_put_u16_le(body, 49);
  smb2_put_u32_le(body + 4, control_code);
  memcpy(body + 8, request + 8, 16);
  smb2_put_u16_le(body + 24, 0);
  smb2_put_u32_le(body + 28, 0);
  smb2_put_u16_le(body + 32, 0);
  smb2_put_u32_le(body + 36, 0);
  smb2_put_u32_le(body + 40, 0);
  return 0;
}

static int smb_protocol_handle_echo(
  smb_protocol_context_t *ctx,
  uint8_t *response,
  size_t response_capacity,
  size_t *response_length)
{
  if (smb_protocol_build_header_response(ctx, response, response_capacity,
      STATUS_SUCCESS, 4, response_length) != 0)
  {
    return -ENOMEM;
  }

  smb2_put_u16_le(response + SMB2_HEADER_SIZE, 4);
  return 0;
}

static int smb_protocol_handle_negotiate(
  smb_protocol_context_t *ctx,
  const uint8_t *request,
  size_t request_length,
  uint8_t *response,
  size_t response_capacity,
  size_t *response_length)
{
  ESP_LOGI(TAG, "Negotiate request: %zu bytes", request_length);

  //-- Minimum: structure_size (2) + dialect_count (2) = 4 bytes
  //-- Full structure is 36 bytes + dialects, but accept partial requests
  if (request_length < 4)
  {
    ESP_LOGW(TAG, "Negotiate request too short: %zu bytes", request_length);
    return -EINVAL;
  }

  const smb2_negotiate_request_t *req = (const smb2_negotiate_request_t *)request;
  uint16_t dialect_count = smb2_get_u16_le((const uint8_t *)&req->dialect_count);
  uint16_t selected_dialect = SMB2_DIALECT_202;

  if (request_length >= sizeof(smb2_negotiate_request_t) + (size_t)dialect_count * sizeof(uint16_t))
  {
    const uint8_t *dialects = request + sizeof(smb2_negotiate_request_t);
    for (uint16_t index = 0; index < dialect_count; index++)
    {
      uint16_t dialect = smb2_get_u16_le(dialects + (size_t)index * sizeof(uint16_t));
        if (dialect == SMB2_DIALECT_202 || dialect == SMB2_DIALECT_210 ||
          dialect == SMB2_DIALECT_300 || dialect == SMB2_DIALECT_302)
      {
        if (dialect > selected_dialect)
        {
          selected_dialect = dialect;
        }
      }
    }
  }

  ESP_LOGI(TAG, "Client offered %u dialects (request body: %zu bytes)", dialect_count, request_length);

  //-- Build negotiate response
  if (response_capacity < SMB2_HEADER_SIZE + 64)
  {
    return -ENOMEM;
  }

  //-- Build header using little-endian serialization
  smb2_header_t resp_header;
  memset(&resp_header, 0, sizeof(resp_header));
  resp_header.signature = SMB2_SIGNATURE;
  resp_header.structure_size = SMB2_HEADER_SIZE;
  resp_header.credit_requested = smb_protocol_grant_credits(ctx);
  resp_header.command = SMB2_NEGOTIATE;
  resp_header.flags = SMB2_FLAGS_SERVER_TO_REDIR;
  resp_header.status = STATUS_SUCCESS;
  resp_header.message_id = ctx->last_request_header.message_id;

  smb2_build_header(response, response_capacity, &resp_header);

  //-- Build negotiate response body (starts after 64-byte header)
  uint8_t *resp_body = response + SMB2_HEADER_SIZE;
  smb2_put_u16_le(resp_body + 0, 65);  //-- structure_size
  smb2_put_u16_le(resp_body + 2, 1);   //-- security_mode: signing enabled
  smb2_put_u16_le(resp_body + 4, selected_dialect);  //-- dialect_revision
  smb2_put_u16_le(resp_body + 6, 0);   //-- reserved
  static const uint8_t server_guid[16] =
    { 0x53, 0x4d, 0x42, 0x32, 0x45, 0x53, 0x50, 0x33,
      0x32, 0x2d, 0x53, 0x45, 0x52, 0x56, 0x52, 0x01 };
  memcpy(resp_body + 8, server_guid, sizeof(server_guid));
  smb2_put_u32_le(resp_body + 24, 0);  //-- capabilities
  smb2_put_u32_le(resp_body + 28, 65536);  //-- max_transact_size
  smb2_put_u32_le(resp_body + 32, 65536);  //-- max_read_size
  smb2_put_u32_le(resp_body + 36, 65536);  //-- max_write_size
  uint64_t server_time = smb_protocol_filetime(time(NULL));
  smb2_put_u64_le(resp_body + 40, server_time);  //-- system_time
  smb2_put_u64_le(resp_body + 48, server_time);  //-- server_start_time
  smb2_put_u16_le(resp_body + 56, SMB2_HEADER_SIZE + 64);  //-- security_buffer_offset
  smb2_put_u16_le(resp_body + 58, 0);  //-- security_buffer_length: guest has no blob

  *response_length = SMB2_HEADER_SIZE + 64;
  ESP_LOGI(TAG, "Negotiate response: %zu bytes (hdr=%u body=64)", *response_length, SMB2_HEADER_SIZE);
  smb_protocol_dump_packet("Negotiate Response", response, (size_t)*response_length);

  return 0;
}

static int smb_protocol_handle_legacy_negotiate(
  smb_protocol_context_t *ctx,
  const uint8_t *request,
  size_t request_length,
  uint8_t *response,
  size_t response_capacity,
  size_t *response_length)
{
  if (request_length < 35 || request[4] != 0x72)
  {
    return -ENOTSUP;
  }

  uint16_t byte_count = smb2_get_u16_le(request + 33);
  if (byte_count > request_length - 35)
  {
    return -EINVAL;
  }

  bool offers_smb2 = false;
  const uint8_t *dialects = request + 35;
  size_t dialects_length = byte_count;
  for (size_t offset = 0; offset + 4 <= dialects_length; )
  {
    const char *dialect = (const char *)(dialects + offset + 1);
    size_t remaining = dialects_length - offset - 1;
    size_t dialect_length = strnlen(dialect, remaining);
    if (dialect_length == remaining)
    {
      break;
    }
    if (dialect_length >= 6 && strncmp(dialect, "SMB 2.", 6) == 0)
    {
      offers_smb2 = true;
      break;
    }
    offset += dialect_length + 2;
  }

  if (!offers_smb2)
  {
    ESP_LOGW(TAG, "SMB1 negotiate did not offer SMB2");
    return -ENOTSUP;
  }

  uint8_t negotiate_request[sizeof(smb2_negotiate_request_t) + sizeof(uint16_t)] = {0};
  smb2_put_u16_le(negotiate_request, 36);
  smb2_put_u16_le(negotiate_request + 2, 1);
  smb2_put_u16_le(negotiate_request + sizeof(smb2_negotiate_request_t), SMB2_DIALECT_202);

  memset(&ctx->last_request_header, 0, sizeof(ctx->last_request_header));
  ctx->last_request_header.signature = SMB2_SIGNATURE;
  ctx->last_request_header.command = SMB2_NEGOTIATE;
  ctx->last_request_header.message_id = smb2_get_u16_le(request + 31);

  ESP_LOGI(TAG, "SMB1 negotiate offered SMB2; continuing with SMB2 dialect 0x0202");
  return smb_protocol_handle_negotiate(
    ctx,
    negotiate_request,
    sizeof(negotiate_request),
    response,
    response_capacity,
    response_length);
}

static int smb_protocol_handle_session_setup(
  smb_protocol_context_t *ctx,
  const uint8_t *request,
  size_t request_length,
  uint8_t *response,
  size_t response_capacity,
  size_t *response_length)
{
  ESP_LOGI(TAG, "Session Setup request: %zu bytes", request_length);

  if (request_length >= 16)
  {
    uint16_t security_buffer_offset = smb2_get_u16_le(request + 12);
    uint16_t security_buffer_length = smb2_get_u16_le(request + 14);
    size_t security_buffer_start = security_buffer_offset >= SMB2_HEADER_SIZE ?
      (size_t)security_buffer_offset - SMB2_HEADER_SIZE : request_length;
    if (security_buffer_start <= request_length &&
        security_buffer_length <= request_length - security_buffer_start)
    {
      ESP_LOGI(TAG, "Session Setup security token: offset=%u length=%u",
        security_buffer_offset, security_buffer_length);
      smb_protocol_dump_packet(
        "Session Setup security token",
        request + security_buffer_start,
        security_buffer_length);
    }
  }

  //-- Accept all session setup requests (guest access)
  //-- Minimal validation; client may send partial requests
   static const uint8_t ntlm_challenge[] =
     {
     0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
     0x02, 0x00, 0x00, 0x00,
     0x0a, 0x00, 0x0a, 0x00, 0x30, 0x00, 0x00, 0x00,
     0x05, 0x02, 0x88, 0x62,
     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x24, 0x00, 0x24, 0x00, 0x3a, 0x00, 0x00, 0x00,
     0x45, 0x00, 0x53, 0x00, 0x50, 0x00, 0x33, 0x00, 0x32, 0x00,
     0x01, 0x00, 0x0a, 0x00, 0x45, 0x00, 0x53, 0x00, 0x50, 0x00, 0x33, 0x00, 0x32, 0x00,
     0x02, 0x00, 0x00, 0x00,
     0x03, 0x00, 0x0a, 0x00, 0x45, 0x00, 0x53, 0x00, 0x50, 0x00, 0x33, 0x00, 0x32, 0x00,
     0x00, 0x00, 0x00, 0x00
     };
  static const uint8_t guest_spnego_complete[] =
    { 0xa1, 0x03, 0x0a, 0x01, 0x00 };
  bool first_session_setup = !ctx->session_setup_started;
  const uint8_t *security_token = first_session_setup ?
    ntlm_challenge : guest_spnego_complete;
  const size_t security_token_length = first_session_setup ?
    sizeof(ntlm_challenge) : 0;
  const size_t security_token_offset = SMB2_HEADER_SIZE + 9;
  if (response_capacity < security_token_offset + security_token_length)
  {
    return -ENOMEM;
  }

  smb2_header_t resp_header;
  memset(&resp_header, 0, sizeof(resp_header));
  resp_header.signature = SMB2_SIGNATURE;
  resp_header.structure_size = SMB2_HEADER_SIZE;
  resp_header.command = SMB2_SESSION_SETUP;
  resp_header.flags = SMB2_FLAGS_SERVER_TO_REDIR;
  resp_header.credit_requested = smb_protocol_grant_credits(ctx);
  ctx->session_setup_started = true;
  resp_header.status = first_session_setup ? STATUS_MORE_PROCESSING_REQUIRED : STATUS_SUCCESS;
  resp_header.message_id = ctx->last_request_header.message_id;
  resp_header.session_id = 0x0000000000000001;  //-- Session ID 1

  smb2_build_header(response, response_capacity, &resp_header);

  //-- Build session setup response body (starts after 64-byte header)
  uint8_t *resp_body = response + SMB2_HEADER_SIZE;
  smb2_put_u16_le(resp_body + 0, 9);   //-- structure_size
  smb2_put_u16_le(resp_body + 2, first_session_setup ? 0 : SMB2_SESSION_FLAG_IS_GUEST);
  smb2_put_u16_le(resp_body + 4, security_token_offset);
  smb2_put_u16_le(resp_body + 6, security_token_length);
  if (security_token_length != 0)
  {
    memcpy(response + security_token_offset, security_token, security_token_length);
  }

  *response_length = security_token_offset + security_token_length;
  ESP_LOGI(TAG, "Session Setup response: %zu bytes, status=0x%08x, session_id=0x%llx",
    *response_length, resp_header.status, resp_header.session_id);

  return 0;
}

static int smb_protocol_handle_tree_connect(
  smb_protocol_context_t *ctx,
  const uint8_t *request,
  size_t request_length,
  uint8_t *response,
  size_t response_capacity,
  size_t *response_length)
{
  ESP_LOGI(TAG, "Tree Connect request: %zu bytes", request_length);

  uint16_t path_offset = request_length >= 8 ? smb2_get_u16_le(request + 4) : 0;
  uint16_t path_length = request_length >= 8 ? smb2_get_u16_le(request + 6) : 0;
  const uint8_t *path_data = NULL;
  char tree_path[SMB_SERVER_PATH_MAX] = {0};
  if (smb_protocol_variable_data(request, request_length, path_offset, path_length, &path_data) == 0)
  {
    smb_path_utf16le_to_utf8(path_data, path_length, tree_path, sizeof(tree_path));
  }
  ctx->ipc_tree = strcasestr(tree_path, "IPC$") != NULL;
  ESP_LOGI(TAG, "Tree Connect path='%s' ipc=%s", tree_path, ctx->ipc_tree ? "yes" : "no");

  //-- Validate share path
  uint32_t status = STATUS_SUCCESS;
  if (!ctx->ipc_tree)
  {
    //-- For disk shares, path MUST contain the share name (ESP32)
    if (strcasestr(tree_path, g_smb_server_state.share_name) == NULL)
    {
      status = STATUS_OBJECT_NAME_NOT_FOUND;
      ESP_LOGI(TAG, "Tree Connect: share '%s' not found", tree_path);
    }
  }

  if (response_capacity < SMB2_HEADER_SIZE + 16)
  {
    return -ENOMEM;
  }

  smb2_header_t resp_header;
  memset(&resp_header, 0, sizeof(resp_header));
  resp_header.signature = SMB2_SIGNATURE;
  resp_header.structure_size = SMB2_HEADER_SIZE;
  resp_header.command = SMB2_TREE_CONNECT;
  resp_header.flags = SMB2_FLAGS_SERVER_TO_REDIR;
  resp_header.credit_requested = smb_protocol_grant_credits(ctx);
  resp_header.status = status;
  resp_header.message_id = ctx->last_request_header.message_id;
  resp_header.tree_id = status == STATUS_SUCCESS ? 1 : 0;

  smb2_build_header(response, response_capacity, &resp_header);

  if (status == STATUS_SUCCESS)
  {
    //-- Build tree connect response body (starts after 64-byte header)
    uint8_t *resp_body = response + SMB2_HEADER_SIZE;
    smb2_put_u16_le(resp_body + 0, 16);  //-- structure_size
    resp_body[2] = ctx->ipc_tree ? 2 : 1; //-- share_type (pipe or disk share)
    resp_body[3] = 0;                    //-- reserved
    smb2_put_u32_le(resp_body + 4, 0);   //-- share_flags
    smb2_put_u32_le(resp_body + 8, 0);   //-- capabilities
    smb2_put_u32_le(resp_body + 12, 0x001f01ff);  //-- maximal_access

    *response_length = SMB2_HEADER_SIZE + 16;
  }
  else
  {
    //-- Error response: header only (no body)
    *response_length = SMB2_HEADER_SIZE;
  }

  ESP_LOGI(TAG, "Tree Connect response: %zu bytes, status=0x%08x, tree_id=%u", *response_length, status, resp_header.tree_id);

  return 0;
}

//-- Byte offset of the file_id field within a request's command-specific body, for
//-- substituting the FileId of related (compounded) operations. -1 if not applicable.
static int smb_protocol_related_file_id_offset(uint16_t command)
{
  switch (command)
  {
    case SMB2_CLOSE:           return offsetof(smb2_close_request_t, file_id);
    case SMB2_READ:            return offsetof(smb2_read_request_t, file_id);
    case SMB2_WRITE:           return offsetof(smb2_write_request_t, file_id);
    case SMB2_QUERY_INFO:      return offsetof(smb2_query_info_request_t, file_id);
    case SMB2_SET_INFO:        return offsetof(smb2_set_info_request_t, file_id);
    case SMB2_QUERY_DIRECTORY: return offsetof(smb2_query_directory_request_t, file_id);
    default:                   return -1;
  }
}

static int smb_protocol_process_request(
  smb_protocol_context_t *ctx,
  const uint8_t *request,
  size_t request_length,
  uint8_t *response,
  size_t response_capacity,
  size_t *response_length)
{
  const uint8_t *payload = request;
  size_t payload_length = request_length;

  //-- Skip NetBIOS frame header (4 bytes: type + length)
  if (payload_length >= 4 && payload[0] == 0x00)
  {
    uint32_t netbios_length = (payload[1] << 16) | (payload[2] << 8) | payload[3];
    ESP_LOGI(TAG, "NetBIOS frame detected: length=%u, skipping 4 bytes", netbios_length);
    payload += 4;
    payload_length -= 4;
  }

  //-- Allow requests smaller than 64 bytes (some SMB2 responses are shorter)
  //-- Minimum: signature (4) + command (2) at offset 12 = 14 bytes
  if (payload_length < 14)
  {
    ESP_LOGE(TAG, "Request too short: %zu bytes (min 14)", payload_length);
    return -EINVAL;
  }

  if (smb2_get_u32_le(payload) == SMB1_SIGNATURE)
  {
    int legacy_result = smb_protocol_handle_legacy_negotiate(
      ctx,
      payload,
      payload_length,
      response,
      response_capacity,
      response_length);
    if (legacy_result != 0)
    {
      ESP_LOGE(TAG, "Unsupported SMB1 request; SMB2 negotiate required");
    }
    return legacy_result;
  }

  //-- Compound requests chain multiple SMB2 commands in one payload via NextCommand.
  //-- Related operations (flags & SMB2_FLAGS_RELATED_OPERATIONS) reuse the FileId
  //-- returned by the previous CREATE in the chain instead of carrying their own.
  uint8_t related_file_id[16] = {0};
  bool have_related_file_id = false;
  uint8_t *prev_response_header = NULL;
  size_t request_offset = 0;
  size_t write_offset = 0;
  int result = 0;

  while (1)
  {
    if (request_offset >= payload_length ||
        smb2_parse_header(payload + request_offset, payload_length - request_offset, &ctx->last_request_header) != 0)
    {
      if (write_offset > 0)
      {
        ESP_LOGW(TAG, "Compound chain truncated: no more valid sub-requests");
        smb2_put_u32_le(prev_response_header + offsetof(smb2_header_t, next_command), 0);
        result = 0;
      }
      else
      {
        ESP_LOGE(TAG, "Failed to parse SMB2 header");
        result = -EINVAL;
      }
      break;
    }

    bool is_last = (ctx->last_request_header.next_command == 0);
    size_t sub_request_length = is_last ? (payload_length - request_offset) : ctx->last_request_header.next_command;

    ESP_LOGI(TAG, "SMB2 Command: 0x%02x (%s), Message ID: %llu%s", ctx->last_request_header.command,
      smb2_command_name(ctx->last_request_header.command), ctx->last_request_header.message_id,
      is_last ? "" : " (compound)");

    //-- Dispatch to handler
    const uint8_t *cmd_payload = payload + request_offset + SMB2_HEADER_SIZE;
    //-- Guard against underflow if payload is shorter than header size
    size_t cmd_payload_length = (sub_request_length > SMB2_HEADER_SIZE) ? (sub_request_length - SMB2_HEADER_SIZE) : 0;

    //-- Related operations reference the FileId from the previous response in the chain
    if ((ctx->last_request_header.flags & SMB2_FLAGS_RELATED_OPERATIONS) && have_related_file_id)
    {
      int file_id_offset = smb_protocol_related_file_id_offset(ctx->last_request_header.command);
      if (file_id_offset >= 0 && cmd_payload_length >= (size_t)file_id_offset + 16)
      {
        memcpy((void *)(cmd_payload + file_id_offset), related_file_id, 16);
      }
    }

    uint8_t *sub_response = response + write_offset;
    size_t sub_response_capacity = (response_capacity > write_offset) ? (response_capacity - write_offset) : 0;
    size_t sub_response_length = 0;

    switch (ctx->last_request_header.command)
    {
      case SMB2_NEGOTIATE:
        result = smb_protocol_handle_negotiate(ctx, cmd_payload, cmd_payload_length, sub_response, sub_response_capacity, &sub_response_length);
        break;

      case SMB2_SESSION_SETUP:
        result = smb_protocol_handle_session_setup(ctx, cmd_payload, cmd_payload_length, sub_response, sub_response_capacity, &sub_response_length);
        break;

      case SMB2_TREE_CONNECT:
        result = smb_protocol_handle_tree_connect(ctx, cmd_payload, cmd_payload_length, sub_response, sub_response_capacity, &sub_response_length);
        break;

      case SMB2_CREATE:
        result = smb_protocol_handle_create(ctx, cmd_payload, cmd_payload_length, sub_response, sub_response_capacity, &sub_response_length);
        break;

      case SMB2_CLOSE:
        result = smb_protocol_handle_close(ctx, cmd_payload, cmd_payload_length, sub_response, sub_response_capacity, &sub_response_length);
        break;

      case SMB2_FLUSH:
        ESP_LOGI(TAG, "Command 0x%02x: FLUSH (header-only success)", ctx->last_request_header.command);
        {
          smb2_header_t *resp_header = (smb2_header_t *)sub_response;
          memset(resp_header, 0, sizeof(*resp_header));
          resp_header->signature = SMB2_SIGNATURE;
          resp_header->structure_size = SMB2_HEADER_SIZE;
          resp_header->command = ctx->last_request_header.command;
          resp_header->flags = SMB2_FLAGS_SERVER_TO_REDIR;
          resp_header->status = STATUS_SUCCESS;
          resp_header->message_id = ctx->last_request_header.message_id;
          resp_header->credit_requested = smb_protocol_grant_credits(ctx);
          sub_response_length = SMB2_HEADER_SIZE;
        }
        break;

      case SMB2_READ:
        result = smb_protocol_handle_read(ctx, cmd_payload, cmd_payload_length, sub_response, sub_response_capacity, &sub_response_length);
        break;

      case SMB2_WRITE:
        result = smb_protocol_handle_write(ctx, cmd_payload, cmd_payload_length, sub_response, sub_response_capacity, &sub_response_length);
        break;

      case SMB2_QUERY_INFO:
        result = smb_protocol_handle_query_info(ctx, cmd_payload, cmd_payload_length, sub_response, sub_response_capacity, &sub_response_length);
        break;

      case SMB2_SET_INFO:
        result = smb_protocol_handle_set_info(ctx, cmd_payload, cmd_payload_length, sub_response, sub_response_capacity, &sub_response_length);
        break;

      case SMB2_QUERY_DIRECTORY:
        result = smb_protocol_handle_query_directory(ctx, cmd_payload, cmd_payload_length, sub_response, sub_response_capacity, &sub_response_length);
        break;

      case SMB2_IOCTL:
        result = smb_protocol_handle_ioctl(ctx, cmd_payload, cmd_payload_length, sub_response, sub_response_capacity, &sub_response_length);
        break;

      case SMB2_ECHO:
        result = smb_protocol_handle_echo(ctx, sub_response, sub_response_capacity, &sub_response_length);
        break;

      case SMB2_LOGOFF:
      case SMB2_TREE_DISCONNECT:
        ESP_LOGI(TAG, "Command 0x%02x: OK (no-op)", ctx->last_request_header.command);
        smb_session_reset();
        {
          smb2_header_t *resp_header = (smb2_header_t *)sub_response;
          memset(resp_header, 0, sizeof(*resp_header));
          resp_header->signature = SMB2_SIGNATURE;
          resp_header->structure_size = SMB2_HEADER_SIZE;
          resp_header->command = ctx->last_request_header.command;
          resp_header->flags = SMB2_FLAGS_SERVER_TO_REDIR;
          resp_header->status = STATUS_SUCCESS;
          resp_header->message_id = ctx->last_request_header.message_id;
          resp_header->credit_requested = smb_protocol_grant_credits(ctx);
          sub_response_length = SMB2_HEADER_SIZE;
        }
        break;

      default:
        //-- Reply gracefully with STATUS_NOT_SUPPORTED instead of dropping the
        //-- connection; e.g. CHANGE_NOTIFY (out of scope) must not kill the
        //-- session, or macOS Finder shows "Server connection interrupted".
        ESP_LOGW(TAG, "Unsupported command: 0x%02x (%s)", ctx->last_request_header.command,
          smb2_command_name(ctx->last_request_header.command));
        result = smb_protocol_build_header_response(ctx, sub_response, sub_response_capacity, STATUS_NOT_SUPPORTED, 0, &sub_response_length);
        break;
    }

    if (result != 0)
    {
      if (write_offset > 0)
      {
        ESP_LOGW(TAG, "Compound sub-command 0x%02x (%s) failed (%d); truncating chain", ctx->last_request_header.command,
          smb2_command_name(ctx->last_request_header.command), result);
        smb2_put_u32_le(prev_response_header + offsetof(smb2_header_t, next_command), 0);
        result = 0;
      }
      break;
    }

    //-- Capture the FileId from a successful CREATE for related operations later in the chain
    if (ctx->last_request_header.command == SMB2_CREATE &&
        sub_response_length >= SMB2_HEADER_SIZE + offsetof(smb2_create_response_t, file_id) + 16 &&
        smb2_get_u32_le(sub_response + offsetof(smb2_header_t, status)) == STATUS_SUCCESS)
    {
      memcpy(related_file_id, sub_response + SMB2_HEADER_SIZE + offsetof(smb2_create_response_t, file_id), 16);
      have_related_file_id = true;
    }

    //-- Non-final chained responses must be padded to an 8-byte boundary
    size_t padded_length = sub_response_length;
    if (!is_last)
    {
      padded_length = (sub_response_length + 7) & ~((size_t)7);
      if (padded_length > sub_response_capacity)
      {
        padded_length = sub_response_capacity;
      }
      if (padded_length > sub_response_length)
      {
        memset(sub_response + sub_response_length, 0, padded_length - sub_response_length);
      }
    }

    //-- Patch this response's NextCommand offset now that its padded length is known
    smb2_put_u32_le(sub_response + offsetof(smb2_header_t, next_command), is_last ? 0 : (uint32_t)padded_length);
    prev_response_header = sub_response;
    write_offset += padded_length;

    if (is_last)
    {
      break;
    }
    request_offset += sub_request_length;
  }

  *response_length = write_offset;
  return result;
}

static void smb_protocol_client_handler(void *arg)
{
  int client_socket = (intptr_t)arg;
  smb_protocol_context_t ctx = {0};
  ctx.socket = client_socket;

  ESP_LOGI(TAG, "Client handler started for socket %d", client_socket);

  //-- Heap-allocated: 2x 8KB on the 6KB task stack caused stack overflow crashes
  #define BUFFER_SIZE 8192
  uint8_t *request_buffer = malloc(BUFFER_SIZE);
  uint8_t *response_buffer = malloc(BUFFER_SIZE);
  if (request_buffer == NULL || response_buffer == NULL)
  {
    ESP_LOGE(TAG, "Failed to allocate client buffers");
    free(request_buffer);
    free(response_buffer);
    close(client_socket);
    ESP_LOGI(TAG, "Client handler ended");
    vTaskDelete(NULL);
    return;
  }

  while (1)
  {
    ssize_t bytes_read = recv(client_socket, request_buffer, BUFFER_SIZE, 0);
    if (bytes_read <= 0)
    {
      ESP_LOGI(TAG, "Client disconnected (bytes_read=%zd)", bytes_read);
      break;
    }

    ESP_LOGD(TAG, "Received %zd bytes from client", bytes_read);
    smb_protocol_dump_packet("Request", request_buffer, (size_t)bytes_read);

    //-- A single recv() may coalesce multiple NetBIOS-framed SMB2 messages
    //-- (e.g. Finder pipelining CREATE+CLOSE immediately followed by
    //-- QUERY_DIRECTORY in the same TCP segment). Process every complete
    //-- frame present in the buffer; otherwise trailing requests are
    //-- silently dropped and the client waits forever for a response that
    //-- never arrives.
    size_t frame_offset = 0;
    bool disconnect = false;

    while (frame_offset + 4 <= (size_t)bytes_read)
    {
      const uint8_t *frame = request_buffer + frame_offset;
      uint32_t netbios_length = ((uint32_t)frame[1] << 16) | ((uint32_t)frame[2] << 8) | frame[3];
      size_t frame_total = 4 + netbios_length;

      if (frame_offset + frame_total > (size_t)bytes_read)
      {
        ESP_LOGW(TAG, "Incomplete trailing NetBIOS frame (%zu bytes available, %zu needed); discarding",
          (size_t)bytes_read - frame_offset, frame_total);
        break;
      }

      size_t response_length = 0;
      int result = smb_protocol_process_request(
        &ctx,
        frame,
        frame_total,
        response_buffer,
        BUFFER_SIZE,
        &response_length);

      if (result == 0 && response_length > 0)
      {
        //-- Add NetBIOS frame header (4 bytes: type + length in big-endian)
        uint8_t netbios_frame[4];
        netbios_frame[0] = 0x00;  //-- Message type
        netbios_frame[1] = (uint8_t)((response_length >> 16) & 0xff);
        netbios_frame[2] = (uint8_t)((response_length >> 8) & 0xff);
        netbios_frame[3] = (uint8_t)(response_length & 0xff);

        //-- Send NetBIOS frame header
        ssize_t frame_sent = send(client_socket, netbios_frame, 4, 0);
        if (frame_sent != 4)
        {
          ESP_LOGE(TAG, "Failed to send NetBIOS frame header (%zd != 4)", frame_sent);
          disconnect = true;
          break;
        }

        //-- Send response
        ssize_t bytes_sent = send(client_socket, response_buffer, response_length, 0);
        if (bytes_sent != (ssize_t)response_length)
        {
          ESP_LOGE(TAG, "Failed to send response (%zd != %zu)", bytes_sent, response_length);
          disconnect = true;
          break;
        }
        ESP_LOGI(TAG, "Sent %zd bytes response (+ 4-byte NetBIOS frame)", bytes_sent);
      }
      else if (result != 0)
      {
        ESP_LOGE(TAG, "Request processing failed: %d", result);
        disconnect = true;
        break;
      }

      frame_offset += frame_total;
    }

    if (disconnect)
      break;
  }

  smb_session_reset();
  free(request_buffer);
  free(response_buffer);
  close(client_socket);
  ESP_LOGI(TAG, "Client handler ended");
  vTaskDelete(NULL);
}

static volatile bool s_stop_requested = false;
static int s_listen_socket = -1;

void smb_protocol_listener_task(void *arg)
{
  (void)arg;

  s_listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s_listen_socket < 0)
  {
    ESP_LOGE(TAG, "Failed to create socket");
    goto end;
  }

  int reuse = 1;
  if (setsockopt(s_listen_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
  {
    ESP_LOGW(TAG, "Failed to set SO_REUSEADDR");
  }

  struct sockaddr_in server_addr = {0};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(445);

  if (bind(s_listen_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
  {
    ESP_LOGE(TAG, "Failed to bind to port 445");
    goto cleanup_socket;
  }

  if (listen(s_listen_socket, 4) < 0)
  {
    ESP_LOGE(TAG, "Failed to listen");
    goto cleanup_socket;
  }

  ESP_LOGI(TAG, "SMB2 server listening on port 445");

  while (!s_stop_requested)
  {
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    int client_socket = accept(s_listen_socket, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_socket < 0)
    {
      if (s_stop_requested)
      {
        break;
      }
      ESP_LOGE(TAG, "Accept failed");
      continue;
    }

    ESP_LOGI(TAG, "Client connected from %s:%u", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    //-- Create handler task for client
    TaskHandle_t handler_task = NULL;
    if (xTaskCreate(
          smb_protocol_client_handler,
          "smb_client",
          6144,  //-- Increased for 8KB buffers on stack
          (void *)(intptr_t)client_socket,
          5,
          &handler_task) != pdPASS)
    {
      ESP_LOGE(TAG, "Failed to create client handler task");
      close(client_socket);
    }
  }

cleanup_socket:
  close(s_listen_socket);
  s_listen_socket = -1;
end:
  ESP_LOGI(TAG, "SMB2 listener task ended");
  vTaskDelete(NULL);
}

esp_err_t smb_protocol_run(void)
{
  s_stop_requested = false;

  TaskHandle_t listener_task = NULL;
  if (xTaskCreate(
        smb_protocol_listener_task,
        "smb_listener",
        4096,
        NULL,
        5,
        &listener_task) != pdPASS)
  {
    ESP_LOGE(TAG, "Failed to create listener task");
    return ESP_ERR_NO_MEM;
  }

  //-- Wait for stop signal
  while (!s_stop_requested)
  {
    vTaskDelay(pdMS_TO_TICKS(100));
  }

  ESP_LOGI(TAG, "SMB protocol run: stop requested");

  if (s_listen_socket >= 0)
  {
    close(s_listen_socket);
    s_listen_socket = -1;
  }

  return ESP_OK;
}

void smb_protocol_request_stop(void)
{
  s_stop_requested = true;

  if (s_listen_socket >= 0)
  {
    close(s_listen_socket);
    s_listen_socket = -1;
  }
}
