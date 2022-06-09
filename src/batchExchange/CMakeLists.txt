set(TREX_LIB_SRC
    CBatch.cpp
	CBatchSlurm.cpp
    CXCat.cpp
    utils.cpp
)

set(TREX_LIB_HDR
	CBatch.h
	CBatchSlurm.h
    CXCat.h
	clipp.h
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

target_link_libraries(TREX TREX_LIB)
target_link_libraries(TREX restclient-cpp)

include_directories(${CURL_INCLUDE_DIR})
include_directories(${Boost_INCLUDE_DIR})

target_link_libraries(TREX Threads::Threads)
target_link_libraries(TREX ${CURL_LIBRARIES})
target_link_libraries(TREX ${Boost_LIBRARIES})
