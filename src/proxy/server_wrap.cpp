#include "proxy/server_wrap.h"
#include "proxy/handler.h"
#include "proxy/server.h"

#include <set>
#include "batchsystem/factory.h"

namespace {

namespace beast = boost::beast;                 // from <boost/beast.hpp>
namespace http = beast::http;                   // from <boost/beast/http.hpp>

struct Handler {
    constexpr static std::chrono::duration<long int> timeout() { return std::chrono::seconds(30); }
    constexpr static unsigned int body_limit() { return 10000; }
    constexpr static unsigned int limit() { return 8; }

    struct websocket_session {
        std::set<std::string> scopes;
        std::string user;
        boost::optional<cw::batch::System> selectedSystem;
        std::function<void(std::string)> send_;

        std::string xcat_token;
        std::string xcat_host;
        std::string xcat_port;
        template <class Session>
        static void init(Session& self) { (void)self; } // NOTE: storing std::function for send would cause leak for some reason
    };

    template <class Session>
    static void handle_socket(Session& self, std::string input) {
        cw::proxy::handler::ws([session=self.shared_from_this()](std::string s){session->send(s);}, self.ioc(), input, self.scopes, self.user, self.selectedSystem);
    }

    template<class Session>
    static void
    handle_request(Session& self, http::request<http::string_body>&& req) {
        cw::proxy::handler::rest([session=self.shared_from_this()](http::response<http::string_body> r){ session->send(std::move(r)); }, self.ioc(), std::move(req));
    }
};

}

namespace cw {
namespace proxy {

void run(boost::asio::io_context& ioc, boost::asio::ssl::context& ctx, boost::asio::ip::tcp::endpoint endpoint, bool force_ssl, bool websocket_support) {
    std::make_shared<cw::proxy::listener<Handler>>(
        ioc,
        ctx,
        endpoint,
        force_ssl,
        websocket_support)->run();
}

}
}
