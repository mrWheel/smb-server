//-- smb_server - SMB2 command handlers (negotiate, session, tree, file operations)
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

//-- Real clients never chain more than 3-4 SMB2 commands via NextCommand.
//-- This bounds the compound-request loop against a malformed/hostile chain
//-- of tiny NextCommand jumps that would otherwise iterate up to payload_length times.
#define SMB_SERVER_MAX_COMPOUND_COMMANDS 16

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

//-- Each connection may have multiple trees open at once (e.g. two IPC$
//-- connects before the disk share connect); MS-SMB2 requires every open
//-- tree_id to be unique within a session, so a single global flag cannot
//-- represent this correctly.
#define SMB_SERVER_MAX_TREES 4

typedef struct
{
  uint32_t tree_id;
  bool in_use;
  bool is_ipc;
} smb_protocol_tree_t;

//-- Protocol state machine
typedef struct
{
  int socket;
  uint64_t message_id;
  bool session_setup_started;
  smb_protocol_tree_t trees[SMB_SERVER_MAX_TREES];
  uint32_t next_tree_id;
  smb2_header_t last_request_header;
} smb_protocol_context_t;

//-- Look up the tree slot for tree_id; NULL if not currently open.
static smb_protocol_tree_t *smb_protocol_find_tree(smb_protocol_context_t *ctx, uint32_t tree_id)
{
  for (int i = 0; i < SMB_SERVER_MAX_TREES; i++)
  {
    if (ctx->trees[i].in_use && ctx->trees[i].tree_id == tree_id)
    {
      return &ctx->trees[i];
    }
  }
  return NULL;
}

//-- True only if the CURRENT request's tree_id maps to an open IPC$ tree.
static bool smb_protocol_is_ipc_tree(smb_protocol_context_t *ctx, uint32_t tree_id)
{
  smb_protocol_tree_t *tree = smb_protocol_find_tree(ctx, tree_id);
  return tree != NULL && tree->is_ipc;
}

//-- Pending SMB2_CHANGE_NOTIFY watches. A small fixed table, same pattern as
//-- the tree table above: linear scan under a dedicated mutex. Each watch is
//-- registered by CHANGE_NOTIFY (interim STATUS_PENDING reply) and completed
//-- later by the owning connection's own recv-timeout tick once CREATE/CLOSE
//-- elsewhere fires a matching event.
#define SMB_SERVER_MAX_NOTIFY_WATCHES 8
#define SMB_SERVER_NOTIFY_NAME_MAX 64

typedef struct
{
  bool in_use;
  int socket;
  uint64_t file_id;
  char watched_path[SMB_SERVER_PATH_MAX];
  bool watch_tree;
  uint32_t completion_filter;
  uint64_t message_id;
  uint64_t session_id;
  uint64_t async_id;
  bool fired;                //-- false = still pending; true once result_status is valid
  uint32_t result_status;   //-- valid once fired: STATUS_SUCCESS or STATUS_CANCELLED
  uint32_t action;
  char name[SMB_SERVER_NOTIFY_NAME_MAX];
} smb_protocol_notify_watch_t;

static smb_protocol_notify_watch_t s_notify_watches[SMB_SERVER_MAX_NOTIFY_WATCHES];
static SemaphoreHandle_t s_notify_mutex;
static uint64_t s_next_async_id = 1;   //-- AsyncId must be nonzero (MS-SMB2)

static SemaphoreHandle_t smb_protocol_notify_get_mutex(void)
{
  if (s_notify_mutex == NULL)
  {
    s_notify_mutex = xSemaphoreCreateMutex();
  }

  return s_notify_mutex;
}

//-- Splits a resolved VFS path at its last '/' into a parent directory and a
//-- leaf name. parent_out never has a trailing slash (except for root "/").
static void smb_protocol_split_parent_and_name(
  const char *path, char *parent_out, size_t parent_out_size, const char **name_out)
{
  const char *slash = strrchr(path, '/');
  if (slash == NULL)
  {
    strlcpy(parent_out, "/", parent_out_size);
    *name_out = path;
    return;
  }

  size_t parent_length = (size_t)(slash - path);
  if (parent_length == 0)
  {
    parent_length = 1;  //-- keep the leading '/'
  }
  if (parent_length >= parent_out_size)
  {
    parent_length = parent_out_size - 1;
  }
  memcpy(parent_out, path, parent_length);
  parent_out[parent_length] = '\0';
  *name_out = slash + 1;
}

//-- Registers a new pending watch; returns ESP_ERR_NO_MEM if the table is full.
static esp_err_t smb_protocol_notify_register(
  int socket, uint64_t file_id, const char *watched_path, bool watch_tree,
  uint32_t completion_filter, uint64_t message_id, uint64_t session_id, uint64_t *async_id_out)
{
  SemaphoreHandle_t mutex = smb_protocol_notify_get_mutex();
  if (mutex == NULL || xSemaphoreTake(mutex, portMAX_DELAY) != pdTRUE)
  {
    return ESP_ERR_NO_MEM;
  }

  for (size_t index = 0; index < SMB_SERVER_MAX_NOTIFY_WATCHES; index++)
  {
    if (s_notify_watches[index].in_use)
    {
      continue;
    }

    smb_protocol_notify_watch_t *watch = &s_notify_watches[index];
    memset(watch, 0, sizeof(*watch));
    watch->in_use = true;
    watch->socket = socket;
    watch->file_id = file_id;
    strlcpy(watch->watched_path, watched_path, sizeof(watch->watched_path));
    watch->watch_tree = watch_tree;
    watch->completion_filter = completion_filter;
    watch->message_id = message_id;
    watch->session_id = session_id;
    watch->async_id = s_next_async_id++;
    watch->fired = false;
    watch->result_status = 0;
    *async_id_out = watch->async_id;
    xSemaphoreGive(mutex);
    return ESP_OK;
  }

  xSemaphoreGive(mutex);
  return ESP_ERR_NO_MEM;
}

//-- Marks every still-pending watch whose watched_path matches changed_dir_path
//-- (exact match, or an ancestor match when watch_tree is set) as fired.
static void smb_protocol_notify_fire(const char *changed_dir_path, uint32_t action, const char *name)
{
  SemaphoreHandle_t mutex = smb_protocol_notify_get_mutex();
  if (mutex == NULL || xSemaphoreTake(mutex, portMAX_DELAY) != pdTRUE)
  {
    return;
  }

  size_t changed_dir_length = strlen(changed_dir_path);

  for (size_t index = 0; index < SMB_SERVER_MAX_NOTIFY_WATCHES; index++)
  {
    smb_protocol_notify_watch_t *watch = &s_notify_watches[index];
    if (!watch->in_use || watch->fired)
    {
      continue;
    }

    bool matches = strcmp(watch->watched_path, changed_dir_path) == 0;
    if (!matches && watch->watch_tree)
    {
      size_t watched_length = strlen(watch->watched_path);
      matches = changed_dir_length > watched_length &&
        strncmp(changed_dir_path, watch->watched_path, watched_length) == 0 &&
        (watch->watched_path[watched_length - 1] == '/' || changed_dir_path[watched_length] == '/');
    }

    if (!matches)
    {
      continue;
    }

    watch->action = action;
    strlcpy(watch->name, name, sizeof(watch->name));
    watch->result_status = STATUS_SUCCESS;
    watch->fired = true;
  }

  xSemaphoreGive(mutex);
}

//-- Marks a pending watch cancelled (SMB2_CANCEL); the owning connection's
//-- poll tick will send the STATUS_CANCELLED final response and free the slot.
static void smb_protocol_notify_cancel(uint64_t async_id)
{
  SemaphoreHandle_t mutex = smb_protocol_notify_get_mutex();
  if (mutex == NULL || xSemaphoreTake(mutex, portMAX_DELAY) != pdTRUE)
  {
    return;
  }

  for (size_t index = 0; index < SMB_SERVER_MAX_NOTIFY_WATCHES; index++)
  {
    smb_protocol_notify_watch_t *watch = &s_notify_watches[index];
    if (watch->in_use && watch->async_id == async_id && !watch->fired)
    {
      watch->result_status = STATUS_CANCELLED;
      watch->fired = true;
      break;
    }
  }

  xSemaphoreGive(mutex);
}

//-- Frees any watch registered against this directory handle (CLOSE of the
//-- watched handle itself invalidates the watch; MS-SMB2 has no async
//-- completion for that case, so it is simply dropped rather than notified).
static void smb_protocol_notify_release_by_file_id(uint64_t file_id)
{
  SemaphoreHandle_t mutex = smb_protocol_notify_get_mutex();
  if (mutex == NULL || xSemaphoreTake(mutex, portMAX_DELAY) != pdTRUE)
  {
    return;
  }

  for (size_t index = 0; index < SMB_SERVER_MAX_NOTIFY_WATCHES; index++)
  {
    if (s_notify_watches[index].in_use && s_notify_watches[index].file_id == file_id)
    {
      memset(&s_notify_watches[index], 0, sizeof(s_notify_watches[index]));
    }
  }

  xSemaphoreGive(mutex);
}

//-- Frees every watch owned by a connection (disconnect/TREE_DISCONNECT/LOGOFF cleanup).
static void smb_protocol_notify_release_by_socket(int socket)
{
  SemaphoreHandle_t mutex = smb_protocol_notify_get_mutex();
  if (mutex == NULL || xSemaphoreTake(mutex, portMAX_DELAY) != pdTRUE)
  {
    return;
  }

  for (size_t index = 0; index < SMB_SERVER_MAX_NOTIFY_WATCHES; index++)
  {
    if (s_notify_watches[index].in_use && s_notify_watches[index].socket == socket)
    {
      memset(&s_notify_watches[index], 0, sizeof(s_notify_watches[index]));
    }
  }

  xSemaphoreGive(mutex);
}

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
  //-- MS-SMB2 2.2.2: a non-success response must carry the minimal 8-byte
  //-- Error Response body (StructureSize=9, ErrorContextCount, Reserved,
  //-- ByteCount=0). Omitting it (header-only, 64 bytes) is tolerated by
  //-- macOS but desyncs iOS's stricter SMB2 client ("Data loop, have N
  //-- bytes, need 72" as it waits for the missing 8-byte tail).
  if (status != STATUS_SUCCESS && body_length < 8)
  {
    body_length = 8;
  }

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
  if (status != STATUS_SUCCESS)
  {
    smb2_put_u16_le(response + SMB2_HEADER_SIZE, 9);  //-- structure_size
  }
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

  if (smb_protocol_is_ipc_tree(ctx, ctx->last_request_header.tree_id) && strcasecmp(smb_name, "srvsvc") == 0)
  {
    uint64_t smb_file_id = 0;
    if (smb_session_allocate_pipe(ctx->socket, &smb_file_id) != ESP_OK)
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
      else if (smb_session_allocate_directory(ctx->socket, path, directory, &smb_file_id) != ESP_OK)
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
      if (exists)
      {
        create_action = 3;
      }
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
    else if (smb_session_allocate_file(ctx->socket, path, fd, &smb_file_id) != ESP_OK)
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

  if (create_action == 2)
  {
    char parent[SMB_SERVER_PATH_MAX];
    const char *leaf = NULL;
    smb_protocol_split_parent_and_name(path, parent, sizeof(parent), &leaf);
    smb_protocol_notify_fire(parent, FILE_ACTION_ADDED, leaf);
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
    bool delete_pending = handle->delete_pending;
    bool is_directory = handle->is_directory;
    char path[SMB_SERVER_PATH_MAX];
    strlcpy(path, handle->path, sizeof(path));

    //-- Release the handle (closes the underlying fd/dir) before deleting;
    //-- esp_littlefs refuses to unlink a path that still has an open FD.
    smb_session_release(file_id);
    smb_protocol_notify_release_by_file_id(file_id);

    if (delete_pending)
    {
      int result = is_directory ? smb_vfs_rmdir(path) : smb_vfs_unlink(path);
      if (result != 0)
      {
        status = smb_protocol_status_from_errno(errno);
      }
      else
      {
        char parent[SMB_SERVER_PATH_MAX];
        const char *leaf = NULL;
        smb_protocol_split_parent_and_name(path, parent, sizeof(parent), &leaf);
        smb_protocol_notify_fire(parent, FILE_ACTION_REMOVED, leaf);
      }
      //-- Keep the pre-delete stat captured above; macOS rejects an
      //-- all-zero-attribute CLOSE response even for a deleted file.
    }
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
  //-- body_length=0: the file data is already read into the buffer above;
  //-- passing the real body length here would make
  //-- smb_protocol_build_header_response() memset() that region back to
  //-- zero right after we filled it.
  if (smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_SUCCESS, 0, response_length) != 0)
    return -ENOMEM;
  uint8_t *body = response + SMB2_HEADER_SIZE;
  smb2_put_u16_le(body, 17);
  body[2] = SMB2_HEADER_SIZE + 16;
  smb2_put_u32_le(body + 4, (uint32_t)read_length);
  *response_length = SMB2_HEADER_SIZE + 16 + (size_t)read_length;
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
    //-- body_length=0: the info block is already written above; passing the
    //-- real body length here would make smb_protocol_build_header_response()
    //-- memset() that region back to zero right after we filled it.
    if (smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_SUCCESS, 0, response_length) != 0) return -ENOMEM;
    smb2_put_u16_le(response + SMB2_HEADER_SIZE, 9);
    smb2_put_u16_le(response + SMB2_HEADER_SIZE + 2, SMB2_HEADER_SIZE + 8);
    smb2_put_u32_le(response + SMB2_HEADER_SIZE + 4, 24);
    *response_length = SMB2_HEADER_SIZE + 8 + 24;
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
  //-- body_length=0: the info block is already written above; passing the
  //-- real body length here would make smb_protocol_build_header_response()
  //-- memset() that region back to zero right after we filled it.
  if (smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_SUCCESS, 0, response_length) != 0) return -ENOMEM;
  smb2_put_u16_le(response + SMB2_HEADER_SIZE, 9);
  smb2_put_u16_le(response + SMB2_HEADER_SIZE + 2, SMB2_HEADER_SIZE + 8);
  smb2_put_u32_le(response + SMB2_HEADER_SIZE + 4, (uint32_t)info_length);
  *response_length = SMB2_HEADER_SIZE + 8 + info_length;
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
  if (smb_protocol_build_header_response(ctx, response, response_capacity, status,
      status == STATUS_SUCCESS ? 2 : 0, response_length) != 0)
  {
    return -ENOMEM;
  }
  if (status == STATUS_SUCCESS)
  {
    smb2_put_u16_le(response + SMB2_HEADER_SIZE, 2);
  }
  return 0;
}

//-- SMB2_CHANGE_NOTIFY (0x0f). Registers a pending watch on the given
//-- directory handle and replies immediately with the MS-SMB2 interim
//-- STATUS_PENDING async response; the real (final) response is sent later
//-- by smb_protocol_notify_poll() once a matching change fires or the
//-- request is cancelled.
static int smb_protocol_handle_change_notify(
  smb_protocol_context_t *ctx, const uint8_t *request, size_t request_length,
  uint8_t *response, size_t response_capacity, size_t *response_length)
{
  #define SMB2_WATCH_TREE 0x0001

  if (request_length < sizeof(smb2_change_notify_request_t)) return -EINVAL;
  const smb2_change_notify_request_t *req = (const smb2_change_notify_request_t *)request;

  smb_session_handle_t *handle = NULL;
  if (smb_session_lookup(smb_protocol_get_file_id(req->file_id), &handle) != ESP_OK || !handle->is_directory)
    return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_INVALID_PARAMETER, 0, response_length);

  char watched_path[SMB_SERVER_PATH_MAX];
  strlcpy(watched_path, handle->path, sizeof(watched_path));

  uint16_t flags = smb2_get_u16_le((const uint8_t *)&req->flags);
  uint32_t completion_filter = smb2_get_u32_le((const uint8_t *)&req->completion_filter);

  uint64_t async_id = 0;
  esp_err_t register_result = smb_protocol_notify_register(
    ctx->socket, smb_protocol_get_file_id(req->file_id), watched_path,
    (flags & SMB2_WATCH_TREE) != 0, completion_filter,
    ctx->last_request_header.message_id, ctx->last_request_header.session_id, &async_id);

  if (register_result != ESP_OK)
    return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_INSUFFICIENT_RESOURCES, 0, response_length);

  //-- Interim response: built by hand rather than via smb_protocol_build_header_response(),
  //-- which always treats bytes 32-39 as a sync reserved+tree_id pair. Here those same
  //-- wire bytes carry the async AsyncId instead (confirmed in smb_packet.c's header codec).
  if (response_capacity < SMB2_HEADER_SIZE + 8)
  {
    return -ENOMEM;
  }

  smb2_header_t header = {0};
  header.signature = SMB2_SIGNATURE;
  header.structure_size = SMB2_HEADER_SIZE;
  header.credit_requested = smb_protocol_grant_credits(ctx);
  header.command = ctx->last_request_header.command;
  header.flags = SMB2_FLAGS_SERVER_TO_REDIR | SMB2_FLAGS_ASYNC_COMMAND;
  header.status = STATUS_PENDING;
  header.message_id = ctx->last_request_header.message_id;
  header.reserved = (uint32_t)(async_id & 0xffffffffu);
  header.tree_id = (uint32_t)(async_id >> 32);
  header.session_id = ctx->last_request_header.session_id;
  smb2_build_header(response, response_capacity, &header);

  memset(response + SMB2_HEADER_SIZE, 0, 8);
  smb2_put_u16_le(response + SMB2_HEADER_SIZE, 9);  //-- structure_size (SMB2 Error Response)
  *response_length = SMB2_HEADER_SIZE + 8;
  return 0;

  #undef SMB2_WATCH_TREE
}

//-- Convert Unix time to Windows FILETIME (100-nanosecond intervals since 1601-01-01)
static uint64_t smb_protocol_unix_to_filetime(time_t unix_time)
{
  //-- Unix epoch: 1970-01-01, Windows epoch: 1601-01-01
  //-- Difference: 116444736000000000 (100-ns intervals)
  const uint64_t EPOCH_DIFF = 116444736000000000ULL;
  return (uint64_t)unix_time * 10000000ULL + EPOCH_DIFF;
}

//-- Case-insensitive DOS-style wildcard match ('*' and '?'), used to filter
//-- QUERY_DIRECTORY entries against the client's search pattern (MS-SMB2 2.2.33).
//-- Without this, SL_RETURN_SINGLE_ENTRY lookups for a specific filename
//-- always return whatever readdir() yields first, so a client polling for
//-- a particular file it hasn't seen yet spins forever.
static bool smb_protocol_wildcard_match(const char *pattern, size_t pattern_len, const char *name)
{
  size_t name_len = strlen(name);
  size_t pi = 0, ni = 0;
  size_t star_pi = (size_t)-1, star_ni = 0;

  while (ni < name_len)
  {
    char pc = (pi < pattern_len) ? pattern[pi] : 0;
    char nc = name[ni];
    if (pc >= 'A' && pc <= 'Z') pc += ('a' - 'A');
    if (nc >= 'A' && nc <= 'Z') nc += ('a' - 'A');

    if (pi < pattern_len && (pattern[pi] == '?' || pc == nc))
    {
      pi++;
      ni++;
    }
    else if (pi < pattern_len && pattern[pi] == '*')
    {
      star_pi = pi++;
      star_ni = ni;
    }
    else if (star_pi != (size_t)-1)
    {
      pi = star_pi + 1;
      ni = ++star_ni;
    }
    else
    {
      return false;
    }
  }
  while (pi < pattern_len && pattern[pi] == '*')
    pi++;
  return pi == pattern_len;
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

  //-- Decode the client's search pattern (UTF-16LE, MS-SMB2 2.2.33) so entries
  //-- not matching it can be skipped instead of always returning the first
  //-- readdir() result.
  char search_pattern[128] = {0};
  size_t search_pattern_len = 0;
  const uint8_t *pattern_utf16 = NULL;
  if (req->file_name_length > 0 &&
      smb_protocol_variable_data(request, request_length, req->file_name_offset, req->file_name_length, &pattern_utf16) == 0)
  {
    search_pattern_len = req->file_name_length / 2;
    if (search_pattern_len > sizeof(search_pattern) - 1)
      search_pattern_len = sizeof(search_pattern) - 1;
    for (size_t i = 0; i < search_pattern_len; i++)
      search_pattern[i] = (char)pattern_utf16[i * 2];
    search_pattern[search_pattern_len] = 0;
  }

  //-- No pattern, or the "match everything" wildcard: skip filtering entirely
  bool match_all = (search_pattern_len == 0) ||
    (search_pattern_len == 1 && search_pattern[0] == '*');

  ESP_LOGI(TAG, "QUERY_DIRECTORY: search_pattern='%s'", search_pattern);

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

    if (!match_all && !smb_protocol_wildcard_match(search_pattern, search_pattern_len, entry->d_name))
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

    uint32_t attrs = S_ISDIR(st.st_mode) ? 0x10 : 0x80;
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

    //-- Zero the 8-byte alignment gap after the filename so no leftover
    //-- data from a previous response (response_buffer is reused, not
    //-- cleared, across requests) is sent as unspecified padding.
    if (next_entry_aligned > entry_size)
      memset(entry_ptr + entry_size, 0, next_entry_aligned - entry_size);

    prev_entry_offset = buffer_used;
    prev_entry_aligned_size = next_entry_aligned;

    buffer_used += next_entry_aligned;

    if (single_entry_only)
      break;
  }

  ESP_LOGI(TAG, "QUERY_DIRECTORY: %zu entries returned, %zu bytes", entry_count, buffer_used);

  if (buffer_used == 0)
    return smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_NO_MORE_FILES, 0, response_length);

  //-- body_length=0: the directory entries are already written into the
  //-- buffer above; passing the real body length here would make
  //-- smb_protocol_build_header_response() memset() that region back to
  //-- zero right after we filled it.
  if (smb_protocol_build_header_response(ctx, response, response_capacity, STATUS_SUCCESS, 0, response_length) != 0)
    return -ENOMEM;

  smb2_put_u16_le(response + SMB2_HEADER_SIZE, 9);
  smb2_put_u16_le(response + SMB2_HEADER_SIZE + 2, SMB2_HEADER_SIZE + 8);
  smb2_put_u32_le(response + SMB2_HEADER_SIZE + 4, (uint32_t)buffer_used);
  *response_length = SMB2_HEADER_SIZE + 8 + buffer_used;

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
      //-- Log every raw offered dialect so we can see values our accept-list
      //-- silently drops (e.g. 0x0311), instead of guessing blind again.
      ESP_LOGI(TAG, "  offered dialect[%u] = 0x%04x", index, dialect);
        if (dialect == SMB2_DIALECT_202 || dialect == SMB2_DIALECT_210 ||
          dialect == SMB2_DIALECT_300 || dialect == SMB2_DIALECT_302 ||
          dialect == SMB2_DIALECT_2FF)
      {
        if (dialect > selected_dialect)
        {
          selected_dialect = dialect;
        }
      }
    }
  }

  ESP_LOGI(TAG, "Client offered %u dialects (request body: %zu bytes), selected 0x%04x",
    dialect_count, request_length, selected_dialect);

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

  //-- Reply with the SMB2 wildcard dialect (0x02FF), not a committed dialect.
  //-- This is the standard multi-protocol-negotiate handshake: it tells the
  //-- client "I support SMB2, send a real NEGOTIATE with your dialect list"
  //-- so it can pick a modern dialect. Committing directly to 0x0202 here
  //-- pins every connection to the oldest SMB2 dialect, which Apple clients
  //-- accept for anonymous share browsing (IPC$) but refuse for real file
  //-- data access -- they silently abandon the connection right after a
  //-- successful TREE_CONNECT to an actual disk share.
  uint8_t negotiate_request[sizeof(smb2_negotiate_request_t) + sizeof(uint16_t)] = {0};
  smb2_put_u16_le(negotiate_request, 36);
  smb2_put_u16_le(negotiate_request + 2, 1);
  smb2_put_u16_le(negotiate_request + sizeof(smb2_negotiate_request_t), SMB2_DIALECT_2FF);

  memset(&ctx->last_request_header, 0, sizeof(ctx->last_request_header));
  ctx->last_request_header.signature = SMB2_SIGNATURE;
  ctx->last_request_header.command = SMB2_NEGOTIATE;
  ctx->last_request_header.message_id = smb2_get_u16_le(request + 31);

  ESP_LOGI(TAG, "SMB1 negotiate offered SMB2; replying with wildcard dialect 0x02ff");
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

  //-- Some clients (macOS mount_smbfs, "Filer") send a bare, unwrapped
  //-- NTLMSSP negotiate token; others (iOS "Files") send it wrapped in a
  //-- SPNEGO/GSS-API NegTokenInit envelope and reject an unwrapped reply.
  //-- Mirror whichever form the client itself used.
  bool client_sent_bare_ntlmssp = false;
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
      client_sent_bare_ntlmssp = security_buffer_length >= 8 &&
        memcmp(request + security_buffer_start, "NTLMSSP\0", 8) == 0;
    }
  }

  //-- Accept all session setup requests (guest access)
  //-- Minimal validation; client may send partial requests
  //-- The NTLM challenge message must be wrapped in a SPNEGO/GSS-API
  //-- NegTokenResp ASN.1 envelope for clients (iOS "Files") that sent a
  //-- SPNEGO-wrapped negotiate token; clients that sent a bare NTLMSSP
  //-- token (macOS mount_smbfs, "Filer") get the same 94-byte NTLM
  //-- Challenge message back unwrapped instead (see ntlm_challenge_raw
  //-- below, identical bytes to the responseToken embedded here).
  static const uint8_t spnego_challenge[] =
    {
    0xa1, 0x77,                                                  //-- [1] NegTokenResp
      0x30, 0x75,                                                //--   SEQUENCE
        0xa0, 0x03, 0x0a, 0x01, 0x01,                            //--     [0] negState: accept-incomplete(1)
        0xa1, 0x0c, 0x06, 0x0a,                                  //--     [1] supportedMech
          0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,  //--       OID 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
        0xa2, 0x60, 0x04, 0x5e,                                  //--     [2] responseToken OCTET STRING (94 bytes)
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
  //-- Same NTLM Type-2 Challenge message as the responseToken above, sent
  //-- unwrapped for clients that themselves sent a bare NTLMSSP token.
  static const uint8_t ntlm_challenge_raw[] =
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
    (client_sent_bare_ntlmssp ? ntlm_challenge_raw : spnego_challenge) :
    guest_spnego_complete;
  const size_t security_token_length = first_session_setup ?
    (client_sent_bare_ntlmssp ? sizeof(ntlm_challenge_raw) : sizeof(spnego_challenge)) : 0;
  const size_t security_token_offset = SMB2_HEADER_SIZE + 8;  //-- fixed body is 8 bytes; 9 is the declared StructureSize value, not a byte offset
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
  bool is_ipc = strcasestr(tree_path, "IPC$") != NULL;
  ESP_LOGI(TAG, "Tree Connect path='%s' ipc=%s", tree_path, is_ipc ? "yes" : "no");

  //-- Validate share path
  uint32_t status = STATUS_SUCCESS;
  if (!is_ipc)
  {
    //-- For disk shares, path MUST contain the share name (ESP32)
    if (strcasestr(tree_path, g_smb_server_state.share_name) == NULL)
    {
      status = STATUS_OBJECT_NAME_NOT_FOUND;
      ESP_LOGI(TAG, "Tree Connect: share '%s' not found", tree_path);
    }
  }

  //-- Allocate a free tree slot with a unique, never-reused tree_id; each
  //-- concurrently-open tree within a session must have its own id so the
  //-- client can track them independently (MS-SMB2 2.2.9).
  uint32_t tree_id = 0;
  if (status == STATUS_SUCCESS)
  {
    smb_protocol_tree_t *slot = NULL;
    for (int i = 0; i < SMB_SERVER_MAX_TREES; i++)
    {
      if (!ctx->trees[i].in_use)
      {
        slot = &ctx->trees[i];
        break;
      }
    }

    if (slot == NULL)
    {
      status = STATUS_INSUFFICIENT_RESOURCES;
      ESP_LOGW(TAG, "Tree Connect: no free tree slots (max %u)", SMB_SERVER_MAX_TREES);
    }
    else
    {
      if (++ctx->next_tree_id == 0) ctx->next_tree_id = 1;  //-- 0 is reserved/invalid
      tree_id = ctx->next_tree_id;
      slot->tree_id = tree_id;
      slot->in_use = true;
      slot->is_ipc = is_ipc;
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
  resp_header.tree_id = tree_id;
  resp_header.session_id = ctx->last_request_header.session_id;

  smb2_build_header(response, response_capacity, &resp_header);

  if (status == STATUS_SUCCESS)
  {
    //-- Build tree connect response body (starts after 64-byte header)
    uint8_t *resp_body = response + SMB2_HEADER_SIZE;
    smb2_put_u16_le(resp_body + 0, 16);  //-- structure_size
    resp_body[2] = is_ipc ? 2 : 1;       //-- share_type (pipe or disk share)
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
    case SMB2_CHANGE_NOTIFY:   return offsetof(smb2_change_notify_request_t, file_id);
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
  size_t compound_command_count = 0;
  int result = 0;

  while (1)
  {
    if (compound_command_count >= SMB_SERVER_MAX_COMPOUND_COMMANDS)
    {
      ESP_LOGW(TAG, "Compound chain truncated: exceeded max of %d sub-commands", SMB_SERVER_MAX_COMPOUND_COMMANDS);
      if (write_offset > 0)
      {
        smb2_put_u32_le(prev_response_header + offsetof(smb2_header_t, next_command), 0);
      }
      result = 0;
      break;
    }

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

    compound_command_count++;

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

      case SMB2_CHANGE_NOTIFY:
        result = smb_protocol_handle_change_notify(ctx, cmd_payload, cmd_payload_length, sub_response, sub_response_capacity, &sub_response_length);
        break;

      case SMB2_CANCEL:
        //-- MS-SMB2 2.2.30: CANCEL never gets a response, sync or async. An
        //-- async cancel (the only kind used by our pending CHANGE_NOTIFY
        //-- watches) carries the target's AsyncId in this request's own
        //-- header reserved/tree_id fields (same wire bytes as always).
        if (ctx->last_request_header.flags & SMB2_FLAGS_ASYNC_COMMAND)
        {
          uint64_t async_id = (uint64_t)ctx->last_request_header.reserved |
            ((uint64_t)ctx->last_request_header.tree_id << 32);
          smb_protocol_notify_cancel(async_id);
        }
        ESP_LOGI(TAG, "Command 0x%02x: CANCEL (no response)", ctx->last_request_header.command);
        sub_response_length = 0;
        break;

      case SMB2_IOCTL:
        result = smb_protocol_handle_ioctl(ctx, cmd_payload, cmd_payload_length, sub_response, sub_response_capacity, &sub_response_length);
        break;

      case SMB2_ECHO:
        result = smb_protocol_handle_echo(ctx, sub_response, sub_response_capacity, &sub_response_length);
        break;

      case SMB2_TREE_DISCONNECT:
      {
        smb_protocol_tree_t *tree = smb_protocol_find_tree(ctx, ctx->last_request_header.tree_id);
        if (tree != NULL)
        {
          tree->in_use = false;
        }
        ESP_LOGI(TAG, "Tree Disconnect: tree_id=%u closed", ctx->last_request_header.tree_id);
        [[fallthrough]];  //-- LOGOFF and TREE_DISCONNECT build the same header-only success response below.
      }
      case SMB2_LOGOFF:
        ESP_LOGI(TAG, "Command 0x%02x: OK (no-op)", ctx->last_request_header.command);
        //-- LOGOFF ends the session; a later SESSION_SETUP on this same TCP
        //-- connection is a brand-new leg-1 negotiate, not a continuation.
        ctx->session_setup_started = false;
        //-- Slots don't track tree_id, so TREE_DISCONNECT (which falls through
        //-- to here) frees ALL of this connection's open handles and pending
        //-- watches, not just ones on the disconnected tree (accepted
        //-- deviation; only matters with two disk trees open at once). Scoped
        //-- to this connection's socket so other clients' handles are untouched.
        smb_session_release_by_socket(ctx->socket);
        smb_protocol_notify_release_by_socket(ctx->socket);
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

//-- Sends the final async response for one fired CHANGE_NOTIFY watch owned by
//-- this connection, then frees its slot. Called repeatedly (once per fired
//-- watch) from the client handler's recv-timeout tick.
static void smb_protocol_notify_poll(smb_protocol_context_t *ctx, uint8_t *response_buffer, size_t buffer_capacity)
{
  while (1)
  {
    SemaphoreHandle_t mutex = smb_protocol_notify_get_mutex();
    if (mutex == NULL || xSemaphoreTake(mutex, portMAX_DELAY) != pdTRUE)
    {
      return;
    }

    uint64_t async_id = 0, message_id = 0, session_id = 0;
    uint32_t result_status = 0, action = 0;
    char name[SMB_SERVER_NOTIFY_NAME_MAX] = {0};
    bool found = false;

    for (size_t index = 0; index < SMB_SERVER_MAX_NOTIFY_WATCHES; index++)
    {
      smb_protocol_notify_watch_t *watch = &s_notify_watches[index];
      if (watch->in_use && watch->socket == ctx->socket && watch->fired)
      {
        async_id = watch->async_id;
        message_id = watch->message_id;
        session_id = watch->session_id;
        result_status = watch->result_status;
        action = watch->action;
        strlcpy(name, watch->name, sizeof(name));
        memset(watch, 0, sizeof(*watch));
        found = true;
        break;
      }
    }

    xSemaphoreGive(mutex);

    if (!found)
    {
      return;
    }

    size_t name_utf16_len = (result_status == STATUS_SUCCESS) ? strlen(name) * 2 : 0;
    size_t body_length = (result_status == STATUS_SUCCESS) ? (8 + 12 + name_utf16_len) : 8;

    if (buffer_capacity < SMB2_HEADER_SIZE + body_length)
    {
      ESP_LOGW(TAG, "Notify response too large for buffer (%zu bytes); dropping", body_length);
      continue;
    }

    smb2_header_t header = {0};
    header.signature = SMB2_SIGNATURE;
    header.structure_size = SMB2_HEADER_SIZE;
    header.credit_requested = 0;  //-- final async responses grant no credits (MS-SMB2)
    header.command = SMB2_CHANGE_NOTIFY;
    header.flags = SMB2_FLAGS_SERVER_TO_REDIR | SMB2_FLAGS_ASYNC_COMMAND;
    header.status = result_status;
    header.message_id = message_id;
    header.reserved = (uint32_t)(async_id & 0xffffffffu);
    header.tree_id = (uint32_t)(async_id >> 32);
    header.session_id = session_id;
    smb2_build_header(response_buffer, buffer_capacity, &header);

    uint8_t *body = response_buffer + SMB2_HEADER_SIZE;
    memset(body, 0, body_length);
    smb2_put_u16_le(body, 9);  //-- structure_size (both the success and error shapes start with this)
    if (result_status == STATUS_SUCCESS)
    {
      smb2_put_u16_le(body + 2, SMB2_HEADER_SIZE + 8);              //-- output_buffer_offset
      smb2_put_u32_le(body + 4, (uint32_t)(12 + name_utf16_len));   //-- output_buffer_length
      uint8_t *notify_info = body + 8;
      smb2_put_u32_le(notify_info + 0, 0);  //-- next_entry_offset (single entry)
      smb2_put_u32_le(notify_info + 4, action);
      smb2_put_u32_le(notify_info + 8, (uint32_t)name_utf16_len);
      uint8_t *fname = notify_info + 12;
      for (size_t i = 0; i < strlen(name); i++)
      {
        fname[i * 2] = name[i];
        fname[i * 2 + 1] = 0;
      }
    }

    size_t response_length = SMB2_HEADER_SIZE + body_length;
    uint8_t netbios_frame[4];
    netbios_frame[0] = 0x00;
    netbios_frame[1] = (uint8_t)((response_length >> 16) & 0xff);
    netbios_frame[2] = (uint8_t)((response_length >> 8) & 0xff);
    netbios_frame[3] = (uint8_t)(response_length & 0xff);

    if (send(ctx->socket, netbios_frame, 4, 0) == 4)
    {
      send(ctx->socket, response_buffer, response_length, 0);
    }
    ESP_LOGI(TAG, "Sent CHANGE_NOTIFY final response: status=0x%08x action=%u name='%s'", result_status, action, name);
  }
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

  //-- Poll tick for pending CHANGE_NOTIFY watches: without this, a client
  //-- with an outstanding watch and nothing else to say would leave recv()
  //-- blocked forever, and a fired watch's final response would never be
  //-- sent until the client happened to issue another request.
  struct timeval notify_poll_timeout = { .tv_sec = 1, .tv_usec = 0 };
  if (setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &notify_poll_timeout, sizeof(notify_poll_timeout)) < 0)
  {
    ESP_LOGW(TAG, "Failed to set SO_RCVTIMEO on client socket %d: errno=%d", client_socket, errno);
  }

  //-- Bytes already sitting in request_buffer[0..buffered_len) that belong
  //-- to a NetBIOS frame which hasn't fully arrived yet. Must survive across
  //-- recv() calls; a frame split over two TCP segments would otherwise be
  //-- discarded (see the "Incomplete trailing NetBIOS frame" case below).
  size_t buffered_len = 0;

  while (1)
  {
    if (buffered_len == BUFFER_SIZE)
    {
      ESP_LOGE(TAG, "NetBIOS frame exceeds buffer size (%d bytes); disconnecting", BUFFER_SIZE);
      break;
    }

    ssize_t bytes_read = recv(client_socket, request_buffer + buffered_len, BUFFER_SIZE - buffered_len, 0);
    if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
      smb_protocol_notify_poll(&ctx, response_buffer, BUFFER_SIZE);
      continue;
    }
    if (bytes_read <= 0)
    {
      ESP_LOGI(TAG, "Client disconnected (bytes_read=%zd)", bytes_read);
      break;
    }

    ESP_LOGD(TAG, "Received %zd bytes from client", bytes_read);
    smb_protocol_dump_packet("Request", request_buffer + buffered_len, (size_t)bytes_read);

    buffered_len += (size_t)bytes_read;

    //-- A single recv() may coalesce multiple NetBIOS-framed SMB2 messages
    //-- (e.g. Finder pipelining CREATE+CLOSE immediately followed by
    //-- QUERY_DIRECTORY in the same TCP segment). Process every complete
    //-- frame present in the buffer; otherwise trailing requests are
    //-- silently dropped and the client waits forever for a response that
    //-- never arrives.
    size_t frame_offset = 0;
    bool disconnect = false;

    while (frame_offset + 4 <= buffered_len)
    {
      const uint8_t *frame = request_buffer + frame_offset;
      uint32_t netbios_length = ((uint32_t)frame[1] << 16) | ((uint32_t)frame[2] << 8) | frame[3];
      size_t frame_total = 4 + netbios_length;

      if (frame_offset + frame_total > buffered_len)
      {
        ESP_LOGD(TAG, "Incomplete trailing NetBIOS frame (%zu bytes available, %zu needed); waiting for more",
          buffered_len - frame_offset, frame_total);
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

    //-- Keep any leftover partial frame at the front of the buffer so the
    //-- next recv() can append to it instead of overwriting it.
    size_t leftover = buffered_len - frame_offset;
    if (leftover > 0 && frame_offset > 0)
    {
      memmove(request_buffer, request_buffer + frame_offset, leftover);
    }
    buffered_len = leftover;
  }

  smb_session_release_by_socket(client_socket);
  smb_protocol_notify_release_by_socket(client_socket);
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
