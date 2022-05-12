set(REPROC++ ON)
add_subdirectory(reproc/)

add_subdirectory(batchsystem/)

set(CLIPP_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/clipp/include/ CACHE INTERNAL "")
