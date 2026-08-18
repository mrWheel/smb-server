#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#pragma pack(1)  //-- Disable struct padding; all SMB2 structures must be byte-aligned

//-- SMB2 Constants
#define SMB2_SIGNATURE 0x424d53fe  //-- 0xfe, 0x53, 0x4d, 0x42
#define SMB1_SIGNATURE 0x424d53ff  //-- 0xff, 0x53, 0x4d, 0x42
#define SMB2_HEADER_SIZE 64
#define SMB2_MAX_PACKET_SIZE 65536

//-- SMB2 Dialects
#define SMB2_DIALECT_202 0x0202
#define SMB2_DIALECT_210 0x0210
#define SMB2_DIALECT_300 0x0300
#define SMB2_DIALECT_302 0x0302
#define SMB2_DIALECT_311 0x0311

//-- SMB2 Command Codes
#define SMB2_NEGOTIATE 0x00
#define SMB2_SESSION_SETUP 0x01
#define SMB2_LOGOFF 0x02
#define SMB2_TREE_CONNECT 0x03
#define SMB2_TREE_DISCONNECT 0x04
#define SMB2_CREATE 0x05
#define SMB2_CLOSE 0x06
#define SMB2_FLUSH 0x07
#define SMB2_READ 0x08
#define SMB2_WRITE 0x09
#define SMB2_LOCK 0x0a
#define SMB2_IOCTL 0x0b
#define SMB2_CANCEL 0x0c
#define SMB2_ECHO 0x0d
#define SMB2_QUERY_DIRECTORY 0x0e
#define SMB2_CHANGE_NOTIFY 0x0f
#define SMB2_QUERY_INFO 0x10
#define SMB2_SET_INFO 0x11

//-- SMB2 Flags
#define SMB2_FLAGS_SERVER_TO_REDIR 0x00000001
#define SMB2_FLAGS_ASYNC_COMMAND 0x00000002
#define SMB2_FLAGS_RELATED_OPERATIONS 0x00000004
#define SMB2_FLAGS_SIGNED 0x00000008
#define SMB2_FLAGS_DFS_OPERATIONS 0x10000000
#define SMB2_FLAGS_REPLAY_OPERATION 0x20000000

//-- SMB2 Status Codes (NTSTATUS)
#define STATUS_SUCCESS 0x00000000
#define STATUS_INVALID_PARAMETER 0xc000000d
#define STATUS_MORE_PROCESSING_REQUIRED 0xc0000016
#define STATUS_NOT_IMPLEMENTED 0xc0000002
#define STATUS_OBJECT_NAME_NOT_FOUND 0xc0000034
#define STATUS_OBJECT_NAME_COLLISION 0xc0000035
#define STATUS_OBJECT_PATH_NOT_FOUND 0xc000003a
#define STATUS_ACCESS_DENIED 0xc0000022
#define STATUS_END_OF_FILE 0xc0000011
#define STATUS_DISK_FULL 0xc000007f
#define STATUS_INSUFFICIENT_RESOURCES 0xc000009a
#define STATUS_DIRECTORY_NOT_EMPTY 0xc0000144
#define STATUS_FILE_IS_A_DIRECTORY 0xc00000ba
#define STATUS_NOT_A_DIRECTORY 0xc0000103
#define STATUS_NOT_SUPPORTED 0xc00000bb

//-- SMB2 Session Setup response flags
#define SMB2_SESSION_FLAG_IS_GUEST 0x0001

//-- SMB2 File Info Classes
#define FileBasicInformation 4
#define FileStandardInformation 5
#define FileNetworkOpenInformation 34
#define FileAllInformation 18
#define FileDispositionInformation 13
#define FileEndOfFileInformation 20

//-- SMB2 Create Disposition (Disposition field)
#define FILE_SUPERSEDE 0x00000000
#define FILE_OPEN 0x00000001
#define FILE_CREATE 0x00000002
#define FILE_OPEN_IF 0x00000003
#define FILE_OVERWRITE 0x00000004
#define FILE_OVERWRITE_IF 0x00000005

//-- SMB2 Create Options
#define FILE_DIRECTORY_FILE 0x00000001
#define FILE_WRITE_THROUGH 0x00000002
#define FILE_SEQUENTIAL_ONLY 0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING 0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT 0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_DELETE_ON_CLOSE 0x00001000

//-- SMB2 Query Info Types
#define SMB2_0_INFO_FILE 0x01
#define SMB2_0_INFO_FILESYSTEM 0x02
#define SMB2_0_INFO_SECURITY 0x03
#define SMB2_0_INFO_QUOTA 0x04

//-- SMB2 Header
typedef struct
{
  uint32_t signature;          //-- 0xfe534d42
  uint16_t structure_size;     //-- 64
  uint16_t credit_charge;
  uint32_t status;             //-- status code or next_command offset
  uint16_t command;
  uint16_t credit_requested;
  uint32_t flags;
  uint32_t next_command;
  uint64_t message_id;
  uint32_t reserved;           //-- process_id (client) or tree_id (server)
  uint32_t tree_id;
  uint64_t session_id;
  uint8_t signature_bytes[16];
} smb2_header_t;

//-- SMB2 Negotiate Request
typedef struct
{
  uint16_t structure_size;     //-- 36
  uint16_t dialect_count;
  uint16_t security_mode;
  uint16_t reserved;
  uint32_t capabilities;
  uint8_t client_guid[16];
  uint64_t client_start_time;
  //-- dialects follow as uint16_t array
} smb2_negotiate_request_t;

//-- SMB2 Negotiate Response
typedef struct
{
  uint16_t structure_size;     //-- 65
  uint16_t security_mode;
  uint16_t dialect_revision;
  uint16_t reserved;
  uint8_t server_guid[16];
  uint32_t capabilities;
  uint32_t max_transact_size;
  uint32_t max_read_size;
  uint32_t max_write_size;
  uint64_t system_time;
  uint64_t server_start_time;
  uint16_t security_buffer_offset;
  uint16_t security_buffer_length;
  uint32_t reserved2;
  //-- security buffer follows
} smb2_negotiate_response_t;

//-- SMB2 Session Setup Request
typedef struct
{
  uint16_t structure_size;     //-- 25
  uint8_t flags;
  uint8_t security_mode;
  uint32_t capabilities;
  uint32_t channel;
  uint16_t security_buffer_offset;
  uint16_t security_buffer_length;
  uint64_t previous_session_id;
  //-- security buffer follows
} smb2_session_setup_request_t;

//-- SMB2 Session Setup Response
typedef struct
{
  uint16_t structure_size;     //-- 9
  uint16_t flags;
  uint16_t security_buffer_offset;
  uint16_t security_buffer_length;
  //-- security buffer follows
} smb2_session_setup_response_t;

//-- SMB2 Tree Connect Request
typedef struct
{
  uint16_t structure_size;     //-- 9
  uint16_t reserved;
  uint16_t path_offset;
  uint16_t path_length;
  //-- path follows (UTF-16LE)
} smb2_tree_connect_request_t;

//-- SMB2 Tree Connect Response
typedef struct
{
  uint16_t structure_size;     //-- 16
  uint8_t share_type;
  uint8_t reserved;
  uint32_t share_flags;
  uint32_t capabilities;
  uint32_t maximal_access;
} smb2_tree_connect_response_t;

//-- SMB2 Create Request
typedef struct
{
  uint16_t structure_size;     //-- 57
  uint8_t security_flags;
  uint8_t request_type;
  uint32_t impersonation_level;
  uint64_t smb_create_flags;
  uint64_t reserved;
  uint32_t desired_access;
  uint32_t file_attributes;
  uint32_t share_access;
  uint32_t create_disposition;
  uint32_t create_options;
  uint16_t name_offset;
  uint16_t name_length;
  uint32_t create_contexts_offset;
  uint32_t create_contexts_length;
  //-- name and context follow
} smb2_create_request_t;

//-- SMB2 Create Response
typedef struct
{
  uint16_t structure_size;     //-- 89
  uint8_t oplock_level;
  uint8_t reserved;
  uint32_t create_action;
  uint64_t creation_time;
  uint64_t last_access_time;
  uint64_t last_write_time;
  uint64_t change_time;
  uint64_t allocation_size;
  uint64_t end_of_file;
  uint32_t file_attributes;
  uint32_t reserved2;
  uint8_t file_id[16];         //-- persistent & volatile
  uint32_t create_contexts_offset;
  uint32_t create_contexts_length;
} smb2_create_response_t;

//-- SMB2 Close Request
typedef struct
{
  uint16_t structure_size;     //-- 24
  uint16_t flags;
  uint32_t reserved;
  uint8_t file_id[16];
} smb2_close_request_t;

//-- SMB2 Close Response
typedef struct
{
  uint16_t structure_size;     //-- 60
  uint16_t flags;
  uint32_t reserved;
  uint64_t creation_time;
  uint64_t last_access_time;
  uint64_t last_write_time;
  uint64_t change_time;
  uint64_t allocation_size;
  uint64_t end_of_file;
  uint32_t file_attributes;
} smb2_close_response_t;

//-- SMB2 Read Request
typedef struct
{
  uint16_t structure_size;     //-- 49
  uint8_t padding;
  uint8_t flags;
  uint32_t length;
  uint64_t offset;
  uint8_t file_id[16];
  uint32_t minimum_count;
  uint32_t channel;
  uint32_t remaining_bytes;
  uint16_t read_channel_info_offset;
  uint16_t read_channel_info_length;
} smb2_read_request_t;

//-- SMB2 Read Response
typedef struct
{
  uint16_t structure_size;     //-- 17
  uint8_t padding;
  uint8_t reserved;
  uint32_t data_length;
  uint64_t data_offset;
  uint32_t remaining;
  uint32_t reserved2;
  //-- data follows
} smb2_read_response_t;

//-- SMB2 Write Request
typedef struct
{
  uint16_t structure_size;     //-- 49
  uint16_t data_offset;
  uint32_t data_length;
  uint64_t offset;
  uint8_t file_id[16];
  uint32_t channel;
  uint32_t remaining_bytes;
  uint16_t write_channel_info_offset;
  uint16_t write_channel_info_length;
  uint32_t flags;
  //-- data follows
} smb2_write_request_t;

//-- SMB2 Write Response
typedef struct
{
  uint16_t structure_size;     //-- 17
  uint16_t reserved;
  uint32_t count;
  uint32_t remaining;
  uint16_t write_channel_info_offset;
  uint16_t write_channel_info_length;
} smb2_write_response_t;

//-- SMB2 Query Info Request
typedef struct
{
  uint16_t structure_size;     //-- 41
  uint8_t info_type;
  uint8_t file_info_class;
  uint32_t output_buffer_length;
  uint16_t input_buffer_offset;
  uint16_t reserved;
  uint32_t input_buffer_length;
  uint32_t additional_information;
  uint32_t flags;
  uint8_t file_id[16];
  //-- input buffer follows
} smb2_query_info_request_t;

//-- SMB2 Query Info Response
typedef struct
{
  uint16_t structure_size;     //-- 9
  uint16_t output_buffer_offset;
  uint32_t output_buffer_length;
  //-- output buffer follows
} smb2_query_info_response_t;

//-- SMB2 Set Info Request
typedef struct
{
  uint16_t structure_size;     //-- 33
  uint8_t info_type;
  uint8_t file_info_class;
  uint32_t buffer_length;
  uint16_t buffer_offset;
  uint16_t reserved;
  uint32_t additional_information;
  uint8_t file_id[16];
  //-- buffer follows
} smb2_set_info_request_t;

//-- SMB2 Set Info Response
typedef struct
{
  uint16_t structure_size;     //-- 2
} smb2_set_info_response_t;

//-- SMB2 Query Directory Request
typedef struct
{
  uint16_t structure_size;     //-- 33
  uint8_t file_information_class;
  uint8_t flags;
  uint32_t file_index;
  uint8_t file_id[16];
  uint16_t file_name_offset;
  uint16_t file_name_length;
  uint32_t output_buffer_length;
  //-- file_name follows
} smb2_query_directory_request_t;

//-- SMB2 Query Directory Response
typedef struct
{
  uint16_t structure_size;     //-- 9
  uint16_t output_buffer_offset;
  uint32_t output_buffer_length;
  //-- output buffer follows
} smb2_query_directory_response_t;

//-- Packet Buffer
typedef struct
{
  uint8_t data[SMB2_MAX_PACKET_SIZE];
  size_t length;
  size_t offset;
} smb2_buffer_t;

//-- Helper Functions
uint16_t smb2_get_u16_le(const uint8_t *data);
uint32_t smb2_get_u32_le(const uint8_t *data);
uint64_t smb2_get_u64_le(const uint8_t *data);

void smb2_put_u16_le(uint8_t *data, uint16_t value);
void smb2_put_u32_le(uint8_t *data, uint32_t value);
void smb2_put_u64_le(uint8_t *data, uint64_t value);

int smb2_parse_header(const uint8_t *data, size_t length, smb2_header_t *header);
int smb2_build_header(uint8_t *data, size_t length, const smb2_header_t *header);

#pragma pack()  //-- Re-enable default packing
