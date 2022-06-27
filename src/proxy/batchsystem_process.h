
#ifndef BOOST_PROXY_BATCHSYSTEM_PROCESS
#define BOOST_PROXY_BATCHSYSTEM_PROCESS

#include "batchsystem/batchsystem.h"
#include <boost/asio/io_context.hpp>

namespace cw {
namespace proxy {
namespace batch {

enum cmd_status {
    cmd_status_running = -1,
    cmd_status_spawn_failed = -2,
};

void runCommand(boost::asio::io_context& ioc_, cw::batch::Result& result, const cw::batch::Cmd& cmd, unsigned int timeout = 0);

}
}
}


#endif /* BOOST_PROXY_BATCHSYSTEM_PROCESS */