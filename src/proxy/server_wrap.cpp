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
        boost::optional<cw::batch::System> selectedSystem;
        std::function<void(std::string)> send_;

        template <class Session>
        static void init(std::shared_ptr<Session> session) {
            session->send_ = [session](std::string s){
                session->send(s);
            };
        } 
    };

    template <class Session>
    static void handle_socket(std::shared_ptr<Session> session, std::string input) {
        cw::proxy::handler::ws(session->send_, session->ioc(), input, session->scopes, session->selectedSystem);
    }

    template<class Session>
    static void
    handle_request(std::shared_ptr<Session> session, http::request<http::string_body>&& req) {
        cw::proxy::handler::rest([session](http::response<http::string_body> r){ session->send(std::move(r)); }, session->ioc(), std::move(req));
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
