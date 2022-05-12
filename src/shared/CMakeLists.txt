set(SHARED_SRC
    base64.cpp
    CXCat.cpp
    httpSession.cpp
    restClient.cpp
    utils.cpp
)

set(SHARED_HDR
    base64.h
    CXCat.h
    curlHelper.h
    httpSession.h
    restClient.h
    sessionTokenTypes.h
    utils.h
)

add_library( shared STATIC
    ${SHARED_SRC}
    ${SHARED_HDR}
)

set(SHARED_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}" CACHE INTERNAL "")
