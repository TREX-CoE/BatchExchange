find_package( Boost 1.58.0 COMPONENTS system filesystem regex iostreams unit_test_framework REQUIRED ) 
find_package( OpenSSL REQUIRED )

# add the executable
add_executable( cli
                main.cpp
)

target_link_libraries( cli
shared
)

include_directories(${MAIN_INCLUDE_DIR})

include_directories(${CURL_INCLUDE_DIR})
include_directories(${Boost_INCLUDE_DIR})
include_directories(${CLIPP_INCLUDE_DIR})

target_link_libraries(cli Threads::Threads)
target_link_libraries(cli ${CURL_LIBRARIES})
target_link_libraries(cli ${Boost_LIBRARIES})
target_link_libraries(cli batchsystem)

