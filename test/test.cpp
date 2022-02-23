#include <catch2/catch_test_macros.hpp>

#include "utils.h"


TEST_CASE( "Test starts_with", "[utils]" ) {
        REQUIRE(utils::starts_with("abc", "a")); 
        REQUIRE(!utils::starts_with("abc", "b")); 
}
