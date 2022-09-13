cmake_minimum_required(VERSION 3.5)

# detect if Catch is being bundled,
# disable testsuite in that case
if(NOT DEFINED PROJECT_NAME)
  set(NOT_SUBPROJECT ON)
else()
  set(NOT_SUBPROJECT OFF)
endif()

project(xcat LANGUAGES CXX VERSION 1.0.0)

FIND_PACKAGE(PkgConfig REQUIRED) # workaround else PKG_SEARCH_MODULE isn't found

if(NOT_SUBPROJECT)
    # use custom flags if compiled as main project only, else use parent projects
    set( CMAKE_CXX_FLAGS "-Werror -Wall -Wextra -pedantic -Wshadow -Wswitch-enum -Wpointer-arith -Wwrite-strings -Wunreachable-code -Wformat=2 -Wundef -Wredundant-decls -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-include-dirs -Wnoexcept -Wredundant-decls -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=1 -Wundef -Wno-deprecated-copy -Wfloat-equal -Wswitch-default -Wsign-conversion -Wconversion  -Wold-style-cast -Wstrict-overflow=2")
  endif(NOT_SUBPROJECT)

add_subdirectory(src/)

if(NOT_SUBPROJECT)
    add_subdirectory(test/)
endif(NOT_SUBPROJECT)
