
set(Boost_USE_STATIC_LIBS   ON)
set(OPENSSL_USE_STATIC_LIBS ON)

find_package( Boost 1.70.0 COMPONENTS system filesystem REQUIRED )
find_package( OpenSSL REQUIRED )

set( proxy_SRC
    batchsystem_process.cpp
    main.cpp
    asyncapi_json.cpp
    openapi_json.cpp
    credentials.cpp
    globals.cpp
    uri.cpp
    cmd_run.cpp
    cmd_user.cpp
    handler.cpp
    server_wrap.cpp
)
set( proxy_HDR
    batchsystem_process.h
    asyncapi_json.h
    openapi_json.h
    credentials.h
    globals.h
    salt_hash.h
    set_echo.h
    response.h
    uri.h
    cmd_run.h
    cmd_user.h
    handler.h
    server_wrap.h
)

set( CMAKE_CXX_FLAGS "-Werror -Wall -Wextra -pedantic -Wshadow -Wswitch-enum -Wpointer-arith -Wwrite-strings -Wunreachable-code -Wformat=2 -Wundef -Wredundant-decls -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-include-dirs -Wnoexcept -Woverloaded-virtual -Wredundant-decls -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=1 -Wundef -Wno-deprecated-copy -Wfloat-equal -Wswitch-default -Wconversion  -Wold-style-cast -Wstrict-overflow=2")
# -Wsign-conversion 

# add the executable
add_executable( proxy
                ${proxy_SRC}
                ${proxy_HDR}
)


include_directories(${Boost_INCLUDE_DIR})
include_directories(${CLIPP_INCLUDE_DIR})
include_directories(${INVOKE_LITE_INCLUDE_DIR})
include_directories(${MAIN_INCLUDE_DIR})

target_link_libraries( proxy shared)
target_link_libraries(proxy Threads::Threads)
target_link_libraries(proxy ${Boost_LIBRARIES})
target_link_libraries(proxy batchsystem)
target_link_libraries(proxy OpenSSL::SSL)
target_link_libraries(proxy OpenSSL::Crypto)

file(READ "openapi.json" OPENAPI)
configure_file(openapi_json.cpp.in "${CMAKE_CURRENT_SOURCE_DIR}/openapi_json.cpp" @ONLY)

file(READ "asyncapi.json" ASYNCAPI)
configure_file(asyncapi_json.cpp.in "${CMAKE_CURRENT_SOURCE_DIR}/asyncapi_json.cpp" @ONLY)

set(PEPPER 2VtWe3CVzV)
set(PEPPER_XOR 0x55)
target_compile_definitions( proxy PRIVATE PEPPER="${PEPPER}")
target_compile_definitions( proxy PRIVATE PEPPER_XOR=${PEPPER_XOR})



