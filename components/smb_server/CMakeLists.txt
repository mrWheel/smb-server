idf_component_register(
  SRCS
    "src/smb_server.c"
    "src/smb_protocol.c"
    "src/smb_packet.c"
    "src/smb_path.c"
    "src/smb_vfs.c"
    "src/smb_session.c"
  INCLUDE_DIRS
    "include"
  PRIV_INCLUDE_DIRS
    "src"
)

target_compile_options(${COMPONENT_LIB} PRIVATE
  -Wall
  -Wextra
  -Werror=return-type
)
