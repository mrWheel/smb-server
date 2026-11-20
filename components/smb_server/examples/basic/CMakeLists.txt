cmake_minimum_required(VERSION 3.16)

#-- Managed dependencies (including smb_server itself) are declared in
#-- idf_component.yml. The override_path there makes this example build
#-- against the local component sources in a Git checkout and against the
#-- published component when downloaded from the ESP Component Registry.
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(smb_server_basic)
