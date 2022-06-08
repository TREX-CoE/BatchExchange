set(SHARED_SRC
    CXCat.cpp
    httpSession.cpp
    restClient.cpp
    utils.cpp
    sha512.cpp
    http.cpp
)

set(SHARED_HDR
    CXCat.h
    curlHelper.h
    httpSession.h
    restClient.h
    sessionTokenTypes.h
    utils.h
    obfuscator.h
    base64.h
    sha512.h
    salt_hash.h
    stream_cast.h
    string_view.h
    splitString.h
    joinString.h
    http.h
    randomHex.h
)

include_directories(${MAIN_INCLUDE_DIR})

add_library( shared STATIC
    ${SHARED_SRC}
    ${SHARED_HDR}
)
