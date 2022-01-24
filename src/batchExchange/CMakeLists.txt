set(TREX_LIB_SRC
    base64.cpp
    httpSession.cpp
    restClient.cpp
    slurm.cpp
    utils.cpp
    xcat.cpp
)

set(TREX_LIB_HDR
    base64.h
    curlHelper.h
    httpSession.h
    restClient.h
    sessionTokenTypes.h
    slurm.h
    utils.h
    xcat.h
)

# add the executable
add_executable( TREX
                main.cpp
                ${TREX_LIB_SRC}
                ${TREX_LIB_HDR}
)

include_directories(${CURL_INCLUDE_DIR})
include_directories(${Boost_INCLUDE_DIR})

target_link_libraries(TREX Threads::Threads)
target_link_libraries(TREX ${CURL_LIBRARIES})
target_link_libraries(TREX ${Boost_LIBRARIES})
