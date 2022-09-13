set( xcat_SRC
        xcat/xcat.cpp
)

set( xcat_HDR
        xcat/xcat.h
)

# Fixme: STATIC because for dynamic, we would need to handle visibility
# and I don't want to do the annotations right now
add_library(xcat STATIC
  ${xcat_SRC}
  ${xcat_HDR}
)

target_compile_features(xcat PUBLIC cxx_std_14)

target_include_directories( xcat
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)
