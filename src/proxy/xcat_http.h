
#ifndef BOOST_PROXY_XCAT_HTTP
#define BOOST_PROXY_XCAT_HTTP

#include "xcat/xcat.h"
#include <boost/asio/io_context.hpp>

namespace cw {
namespace proxy {
namespace xcat {

void runHttp(boost::asio::io_context& ioc_, ::xcat::ApiCallResponse& res, const ::xcat::ApiCallRequest& req, unsigned int timeout_ms, std::string host, std::string port);

}
}
}


#endif /* BOOST_PROXY_XCAT_HTTP */
