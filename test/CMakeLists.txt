add_subdirectory(Catch2)
# These tests can use the Catch2-provided main
add_executable(tests test.cpp)

set_target_properties( Catch2 PROPERTIES COMPILE_FLAGS "-w" )
set_target_properties( tests PROPERTIES COMPILE_FLAGS "-Wno-ctor-dtor-privacy" )
target_link_libraries(tests PRIVATE
    Catch2::Catch2WithMain
    TREX_LIB
    batchsystem
    reproc++
)
target_include_directories( tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/batchExchange/"
)


