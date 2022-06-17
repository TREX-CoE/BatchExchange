#ifndef BOOST_SERVER_WRAP
#define BOOST_SERVER_WRAP

#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>

namespace cw {
namespace proxy {

void run(boost::asio::io_context& ioc, boost::asio::ssl::context& ctx, boost::asio::ip::tcp::endpoint endpoint, bool force_ssl, bool websocket_support);

}
}

#endif /* BOOST_SERVER_WRAP */