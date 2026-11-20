idf_component_register(
  SRCS "main.c"
  INCLUDE_DIRS "."
  REQUIRES
    smb_server
)

#-- Bake the example's own littlefs_assets/ folder into the "littlefs"
#-- partition (partitions.csv) at build time and flash it along with the app.
littlefs_create_partition_image(littlefs ../littlefs_assets FLASH_IN_PROJECT)
