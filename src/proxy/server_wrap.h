#ifndef BOOST_SERVER_WRAP
#define BOOST_SERVER_WRAP

#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>

namespace cw {
namespace proxy {

struct XcatOptions {
    std::string token;
    std::string host;
    std::string port;
    std::string user;
    std::string password;
    unsigned long int expires;
    bool ssl = true;
    bool ssl_verify = false;
};

void run(boost::asio::io_context& ioc, boost::asio::ssl::context& ctx, boost::asio::ip::tcp::endpoint endpoint, bool force_ssl, bool websocket_support);

}
}

#endif /* BOOST_SERVER_WRAP */