#ifndef BOOST_PROXY_HANDLER
#define BOOST_PROXY_HANDLER

#include <boost/asio.hpp>
#include <boost/optional.hpp>
#include <boost/beast/http.hpp>

#include <set>
#include <string>
#include <functional>

#include "batchsystem/factory.h"

namespace cw {
namespace proxy {
namespace handler {

void ws(std::function<void(std::string)> send_, boost::asio::io_context& ioc, std::string input, std::set<std::string>& scopes, std::string& user, boost::optional<cw::batch::System>& selectedSystem, std::string& xcat_token, std::string& xcat_host, std::string& xcat_port, std::string& xcat_user, std::string& xcat_password);
void rest(std::function<void(boost::beast::http::response<boost::beast::http::string_body>)> send_, boost::asio::io_context& ioc, boost::beast::http::request<boost::beast::http::string_body> req);

}
}
}


#endif /* BOOST_PROXY_HANDLER */
