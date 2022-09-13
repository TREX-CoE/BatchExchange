set(SHARED_SRC
    utils.cpp
    sha512.cpp
    http.cpp
)

set(SHARED_HDR
    utils.h
    obfuscator.h
    base64.h
    sha512.h
    salt_hash.h
    stream_cast.h
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
