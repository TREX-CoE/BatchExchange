add_subdirectory(Catch2)
# These tests can use the Catch2-provided main
add_executable(tests unit.cpp internal.cpp full.cpp)

set_target_properties( Catch2 PROPERTIES COMPILE_FLAGS "-w" )
set_target_properties( tests PROPERTIES COMPILE_FLAGS "-Wno-ctor-dtor-privacy" )
target_link_libraries(tests PRIVATE
    Catch2::Catch2WithMain
    batchsystem
)
target_include_directories( tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# pass testdata dir to testing code
set (TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/testdata)
target_compile_definitions( tests PRIVATE TEST_DIR="${TEST_DIR}")



