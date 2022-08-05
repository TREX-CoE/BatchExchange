
#ifndef BOOST_PROXY_XCAT_HTTP
#define BOOST_PROXY_XCAT_HTTP

#include "xcat/xcat.h"
#include <boost/asio/io_context.hpp>

namespace cw {
namespace proxy {
namespace xcat {

enum cmd_status {
    cmd_status_running = -1,
    cmd_status_spawn_failed = -2,
};

void runHttp(boost::asio::io_context& ioc_, ::xcat::ApiCallResponse& res, const ::xcat::ApiCallRequest& req, unsigned int timeout_ms);

}
}
}


#endif /* BOOST_PROXY_XCAT_HTTP */