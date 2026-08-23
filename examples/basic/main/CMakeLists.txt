idf_component_register(
  SRCS "main.c"
  INCLUDE_DIRS "."
  REQUIRES
    smb_server
)

#-- Bake the repo-root flash_data/ folder into the "littlefs" partition
#-- (partitions.csv) at build time and flash it along with the app.
littlefs_create_partition_image(littlefs ../../../flash_data FLASH_IN_PROJECT)
