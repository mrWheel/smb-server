idf_component_register(
  #-- main.c only pulls in the example's main.c, so the example under
  #-- components/smb_server/examples/basic stays the single source of truth.
  SRCS "main.c"
  INCLUDE_DIRS "."
  REQUIRES
    smb_server
)

#-- Bake the example's littlefs_assets/ folder into the "littlefs" partition
#-- (partitions.csv) at build time and flash it along with the app.
littlefs_create_partition_image(littlefs ../components/smb_server/examples/basic/littlefs_assets FLASH_IN_PROJECT)
