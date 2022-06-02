
#ifndef BOOST_PROXY_BATCHSYSTEM_PROCESS
#define BOOST_PROXY_BATCHSYSTEM_PROCESS

#include "batchsystem/batchsystem.h"
#include <boost/asio/io_context.hpp>

namespace cw {
namespace proxy {
namespace batch {

void runCommand(boost::asio::io_context& ioc_, cw::batch::Result& result, const cw::batch::Cmd& cmd);

}
}
}


#endif /* BOOST_PROXY_BATCHSYSTEM_PROCESS */