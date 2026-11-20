cmake_minimum_required(VERSION 3.16)

#-- Root test application (same layout as the ringFileStore repository):
#-- building at the repository root builds and flashes the basic SMB share
#-- example. The component itself lives in components/smb_server and the
#-- publishable copy of the example stays inside the component.
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(smb_server_basic)
