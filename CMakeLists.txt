cmake_minimum_required(VERSION 3.6)

# set the project name
project(TREX)

# general project preparation
include(cmake/findPackages.cmake)
include(cmake/compilerSettings.cmake)

# project itself
add_subdirectory(src/)
add_subdirectory(test/)