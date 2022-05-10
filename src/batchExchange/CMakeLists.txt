set(TREX_LIB_SRC
    base64.cpp
	CBatch.cpp
	CBatchSlurm.cpp
    CXCat.cpp
    httpSession.cpp
    restClient.cpp
    utils.cpp
)

set(TREX_LIB_HDR
    base64.h
	CBatch.h
	CBatchSlurm.h
    CXCat.h
	clipp.h
    curlHelper.h
    httpSession.h
    restClient.h
    sessionTokenTypes.h
    utils.h
)

add_library( TREX_LIB STATIC
    ${TREX_LIB_SRC}
    ${TREX_LIB_HDR}
)

# add the executable
add_executable( TREX
                main.cpp
)

target_link_libraries( TREX
TREX_LIB
)

include_directories(${CURL_INCLUDE_DIR})
include_directories(${Boost_INCLUDE_DIR})

target_link_libraries(TREX Threads::Threads)
target_link_libraries(TREX ${CURL_LIBRARIES})
target_link_libraries(TREX ${Boost_LIBRARIES})
target_link_libraries(TREX reproc++)
target_link_libraries(TREX batchsystem)
