find_package( Boost 1.70.0 COMPONENTS system filesystem regex iostreams unit_test_framework REQUIRED ) 
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package( OpenSSL REQUIRED )

# add the executable
add_executable( proxy
                main.cpp
)

target_link_libraries( proxy
shared
)

include_directories(${Boost_INCLUDE_DIR})
include_directories(${CLIPP_INCLUDE_DIR})
include_directories(${SHARED_INCLUDE_DIR})

target_link_libraries(proxy Threads::Threads)
target_link_libraries(proxy ${Boost_LIBRARIES})
target_link_libraries(proxy reproc++)
target_link_libraries(proxy batchsystem)
target_link_libraries(proxy OpenSSL::SSL)
target_link_libraries(proxy OpenSSL::Crypto)




