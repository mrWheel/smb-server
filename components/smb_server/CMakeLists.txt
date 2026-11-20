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
  #-- esp_err.h is used in the public header smb_server.h
  REQUIRES
    esp_common
  #-- FreeRTOS tasks/semaphores, lwIP POSIX sockets, heap caps, logging and
  #-- the VFS layer are only needed by the private implementation sources.
  #-- (esp_log.h is provided by the "log" component in ESP-IDF 6.x.)
  PRIV_REQUIRES
    freertos
    log
    heap
    lwip
    vfs
)

target_compile_options(${COMPONENT_LIB} PRIVATE
  -Wall
  -Wextra
  -Werror=return-type
)
