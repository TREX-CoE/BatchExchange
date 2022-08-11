
#ifndef BOOST_PROXY_XCAT_HTTP
#define BOOST_PROXY_XCAT_HTTP

#include "xcat/xcat.h"
#include <boost/asio/io_context.hpp>
#include <functional>

namespace cw {
namespace proxy {
namespace xcat {

void runHttp(boost::asio::io_context& ioc_, ::xcat::ApiCallRequest req, std::function<void(::xcat::ApiCallResponse)> resp, unsigned int timeout_ms, std::string host, std::string port);


}
}
}


#endif /* BOOST_PROXY_XCAT_HTTP */
