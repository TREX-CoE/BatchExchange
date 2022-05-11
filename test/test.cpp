#include <catch2/catch_test_macros.hpp>

#include "utils.h"

#include "batchsystem/batchsystem.h"
#include <reproc++/run.hpp>

namespace {

int runCommand(std::string& out, const cw::batch::CmdOptions& opts) {
        reproc::options options;
        options.deadline = reproc::milliseconds(5000);
        std::vector<std::string> args{opts.cmd};
        for (const auto& a: opts.args) args.push_back(a);
        auto ret = reproc::run(args);
        return ret.first;
}

}

TEST_CASE( "Test starts_with", "[utils]" ) {
        REQUIRE(utils::starts_with("abc", "a")); 
        REQUIRE(!utils::starts_with("abc", "b")); 
}


TEST_CASE( "Batchsystem integration", "[batchsystem]" ) {
}
