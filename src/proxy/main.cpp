/**
 * @file main.cpp
 * @brief CLI
 *
 * ./src/server/proxy --cred ../data/creds run --cert ../data/server.crt --priv ../data/server.key --dh ../data/dh2048.pem --port 2000 --host 0.0.0.0
 * 
 ***********************************************/

#include <signal.h>
#include <unistd.h>

#include <chrono>
#include <ctime>
#include <exception>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <thread>
#include <algorithm>
#include <memory>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/make_unique.hpp>
#include <boost/optional.hpp>
#include <boost/process.hpp>

#include <cassert>
#include <stdlib.h>

#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "proxy/openapi_json.h"
#include "proxy/credentials.h"
#include "shared/obfuscator.h"
#include "shared/stream_cast.h"
#include "shared/sha512.h"
#include "proxy/salt_hash.h"
#include "shared/string_view.h"


#include "clipp.h"

#include "batchsystem/batchsystem.h"
#include "batchsystem/factory.h"
#include "batchsystem/pbsBatch.h"
#include "batchsystem/json.h"


namespace beast = boost::beast;                 // from <boost/beast.hpp>
namespace http = beast::http;                   // from <boost/beast/http.hpp>
namespace websocket = beast::websocket;         // from <boost/beast/websocket.hpp>
namespace net = boost::asio;                    // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;               // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>
namespace bp = boost::process;

namespace batch = cw::batch;

bool canceled(false);

/**
 * @brief Handle caught signal
 *
 * This function is called when SIGINT is caught.
 *
 * @param signal Number of signal
 */
void sigHandler(int signal) {
    std::cout << "Caught signal " << signal << std::endl;

    // only exit on second SIGINT
    if (canceled) {
        exit(EXIT_FAILURE);
    }
    canceled = true;
}

namespace {

cw::credentials::dict creds;

const cw::credentials::dict& get_creds() {
    return creds;
}


struct CmdProcess {
    int exit;
    std::future<std::string> out; // before cp else "std::future_error: No associated state" because initialized afterwards
    bp::child cp;
    template <typename F>
    CmdProcess(net::io_context& ioc, const cw::batch::CmdOptions& opts, F func): exit(-1), cp(bp::search_path(opts.cmd), bp::args(opts.args), bp::std_out > out, ioc, bp::on_exit=[&](int ret, const std::error_code& ec){
        exit = ec ? -2 : ret;
        func(*this, ret, ec);
    }) {}
};

}

ssl::context create_ssl_context(const std::string& cert, const std::string& priv, const std::string& dh) {
    // The SSL context is required, and holds certificates
    ssl::context ctx{boost::asio::ssl::context::sslv23};
    ctx.set_options(
        boost::asio::ssl::context::default_workarounds
        | boost::asio::ssl::context::no_sslv2
        | boost::asio::ssl::context::single_dh_use);
    ctx.use_certificate_chain_file(cert);
    ctx.use_private_key_file(priv, boost::asio::ssl::context::pem);
    ctx.use_tmp_dh_file(dh);
    return ctx;
}

rapidjson::Document generate_json_error(const std::string& type, const std::string& message, http::status status) {
    rapidjson::Document document;
    rapidjson::Document::AllocatorType& allocator = document.GetAllocator();
    document.SetObject();
    {
        rapidjson::Value error;
        error.SetObject();
        error.AddMember("type", type, allocator);
        error.AddMember("message", message, allocator);
        error.AddMember("code", static_cast<int>(status), allocator);
        document.AddMember("error", error, allocator);
    }
    return document;
}

//------------------------------------------------------------------------------

// Report a failure
void
fail(beast::error_code ec, char const* what)
{
    // ssl::error::stream_truncated, also known as an SSL "short read",
    // indicates the peer closed the connection without performing the
    // required closing handshake (for example, Google does this to
    // improve performance). Generally this can be a security issue,
    // but if your communication protocol is self-terminated (as
    // it is with both HTTP and WebSocket) then you may simply
    // ignore the lack of close_notify.
    //
    // https://github.com/boostorg/beast/issues/38
    //
    // https://security.stackexchange.com/questions/91435/how-to-handle-a-malicious-ssl-tls-shutdown
    //
    // When a short read would cut off the end of an HTTP message,
    // Beast returns the error beast::http::error::partial_message.
    // Therefore, if we see a short read here, it has occurred
    // after the message has been completed, so it is safe to ignore it.

    if(ec == net::ssl::error::stream_truncated)
        return;

    std::cerr << what << ": " << ec.message() << "\n";
}

//------------------------------------------------------------------------------

// Echoes back all received WebSocket messages.
// This uses the Curiously Recurring Template Pattern so that
// the same code works with both SSL streams and regular sockets.
template<class Derived>
class websocket_session
{
    // Access the derived class, this is part of
    // the Curiously Recurring Template Pattern idiom.
    Derived&
    derived()
    {
        return static_cast<Derived&>(*this);
    }

    beast::flat_buffer buffer_;

    // Start the asynchronous operation
    template<class Body, class Allocator>
    void
    do_accept(http::request<Body, http::basic_fields<Allocator>> req)
    {
        // Set suggested timeout settings for the websocket
        derived().ws().set_option(
            websocket::stream_base::timeout::suggested(
                beast::role_type::server));

        // Set a decorator to change the Server of the handshake
        derived().ws().set_option(
            websocket::stream_base::decorator(
            [](websocket::response_type& res)
            {
                res.set(http::field::server,
                    std::string(BOOST_BEAST_VERSION_STRING) +
                        " advanced-server-flex");
            }));

        // Accept the websocket handshake
        derived().ws().async_accept(
            req,
            beast::bind_front_handler(
                &websocket_session::on_accept,
                derived().shared_from_this()));
    }

    void
    on_accept(beast::error_code ec)
    {
        if(ec)
            return fail(ec, "accept");

        // Read a message
        do_read();
    }

    void
    do_read()
    {
        // Read a message into our buffer
        derived().ws().async_read(
            buffer_,
            beast::bind_front_handler(
                &websocket_session::on_read,
                derived().shared_from_this()));
    }

    void
    on_read(
        beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        // This indicates that the websocket_session was closed
        if(ec == websocket::error::closed)
            return;

        if(ec)
            fail(ec, "read");

        // Echo the message
        derived().ws().text(derived().ws().got_text());
        derived().ws().async_write(
            buffer_.data(),
            beast::bind_front_handler(
                &websocket_session::on_write,
                derived().shared_from_this()));
    }

    void
    on_write(
        beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if(ec)
            return fail(ec, "write");

        // Clear the buffer
        buffer_.consume(buffer_.size());

        // Do another read
        do_read();
    }

public:
    // Start the asynchronous operation
    template<class Body, class Allocator>
    void
    run(http::request<Body, http::basic_fields<Allocator>> req)
    {
        // Accept the WebSocket upgrade request
        do_accept(std::move(req));
    }
};

//------------------------------------------------------------------------------

// Handles a plain WebSocket connection
class plain_websocket_session
    : public websocket_session<plain_websocket_session>
    , public std::enable_shared_from_this<plain_websocket_session>
{
    websocket::stream<beast::tcp_stream> ws_;

public:
    // Create the session
    explicit
    plain_websocket_session(
        beast::tcp_stream&& stream)
        : ws_(std::move(stream))
    {
    }

    // Called by the base class
    websocket::stream<beast::tcp_stream>&
    ws()
    {
        return ws_;
    }
};

//------------------------------------------------------------------------------

// Handles an SSL WebSocket connection
class ssl_websocket_session
    : public websocket_session<ssl_websocket_session>
    , public std::enable_shared_from_this<ssl_websocket_session>
{
    websocket::stream<
        beast::ssl_stream<beast::tcp_stream>> ws_;

public:
    // Create the ssl_websocket_session
    explicit
    ssl_websocket_session(
        beast::ssl_stream<beast::tcp_stream>&& stream)
        : ws_(std::move(stream))
    {
    }

    // Called by the base class
    websocket::stream<
        beast::ssl_stream<beast::tcp_stream>>&
    ws()
    {
        return ws_;
    }
};

//------------------------------------------------------------------------------

template<class Body, class Allocator>
void
make_websocket_session(
    beast::tcp_stream stream,
    http::request<Body, http::basic_fields<Allocator>> req)
{
    std::make_shared<plain_websocket_session>(
        std::move(stream))->run(std::move(req));
}

template<class Body, class Allocator>
void
make_websocket_session(
    beast::ssl_stream<beast::tcp_stream> stream,
    http::request<Body, http::basic_fields<Allocator>> req)
{
    std::make_shared<ssl_websocket_session>(
        std::move(stream))->run(std::move(req));
}

//------------------------------------------------------------------------------

class PollTimer {
public:
    explicit PollTimer(net::io_context& io_context): _timer( io_context ) {}
    
    void start(std::function<bool(const boost::system::error_code& ec)> func)
    {
        _func = func;
        this->wait();
    }

private:
    boost::asio::deadline_timer _timer;
    std::function<bool(const boost::system::error_code& ec)> _func;
    void wait()
    {
        _timer.expires_from_now(boost::posix_time::millisec(400));
        _timer.async_wait([&](const boost::system::error_code& ec) {
            if (!this->_func(ec)) return;
            this->wait();
        });
    }
};


// Handles an HTTP server connection.
// This uses the Curiously Recurring Template Pattern so that
// the same code works with both SSL streams and regular sockets.
template<class Derived>
class http_session
{
    // Access the derived class, this is part of
    // the Curiously Recurring Template Pattern idiom.
    Derived&
    derived()
    {
        return static_cast<Derived&>(*this);
    }

    // This queue is used for HTTP pipelining.
    class queue
    {
        enum
        {
            // Maximum number of responses we will queue
            limit = 8
        };

        // The type-erased, saved work item
        struct work
        {
            virtual ~work() = default;
            virtual void operator()() = 0;
        };

        http_session& self_;
        std::vector<std::unique_ptr<work>> items_;

    public:
        explicit
        queue(http_session& self)
            : self_(self)
        {
            static_assert(limit > 0, "queue limit must be positive");
            items_.reserve(limit);
        }

        // Returns `true` if we have reached the queue limit
        bool
        is_full() const
        {
            return items_.size() >= limit;
        }

        // Called when a message finishes sending
        // Returns `true` if the caller should initiate a read
        bool
        on_write()
        {
            BOOST_ASSERT(! items_.empty());
            auto const was_full = is_full();
            items_.erase(items_.begin());
            if(! items_.empty())
                (*items_.front())();
            return was_full;
        }

        // Called by the HTTP handler to send a response.
        template<bool isRequest, class Body, class Fields>
        void
        operator()(http::message<isRequest, Body, Fields>&& msg)
        {
            // This holds a work item
            struct work_impl : work
            {
                http_session& self_;
                http::message<isRequest, Body, Fields> msg_;

                work_impl(
                    http_session& self,
                    http::message<isRequest, Body, Fields>&& msg)
                    : self_(self)
                    , msg_(std::move(msg))
                {
                }

                void
                operator()()
                {
                    http::async_write(
                        self_.derived().stream(),
                        msg_,
                        beast::bind_front_handler(
                            &http_session::on_write,
                            self_.derived().shared_from_this(),
                            msg_.need_eof()));
                }
            };

            // Allocate and store the work
            items_.push_back(
                boost::make_unique<work_impl>(self_, std::move(msg)));

            // If there was no previous work, start this one
            if(items_.size() == 1)
                (*items_.front())();
        }
    };

    queue queue_;

    // The parser is stored in an optional container so we can
    // construct it from scratch it at the beginning of each new message.
    boost::optional<http::request_parser<http::string_body>> parser_;

protected:
    beast::flat_buffer buffer_;

public:
    // Construct the session
    http_session(
        beast::flat_buffer buffer)
        : queue_(*this)
        , buffer_(std::move(buffer))
    {
    }

    // This function produces an HTTP response for the given
    // request. The type of the response object depends on the
    // contents of the request, so the interface requires the
    // caller to pass a generic lambda for receiving the response.
    template<
        class Body, class Allocator,
        class Send>
    void
    handle_request(
        http::request<Body, http::basic_fields<Allocator>>&& req,
        Send&& send
        )
    {
        auto const json_response =
        [&](const rapidjson::Document& document, http::status status = http::status::ok)
        {
            http::response<http::string_body> res{status, 11}; // req.version(); fails
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "application/json");
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            document.Accept(writer);
            res.body() = buffer.GetString();
            res.prepare_payload();
            return res;
        };

        auto const json_error_response =
        [&](const std::string& type, const std::string& message, http::status status)
        {
            return json_response(generate_json_error(type, message, status), status);
        };

        auto const bad_request =
        [&]()
        {
            return json_error_response("Bad request", "Unsupported API call", http::status::bad_request);
        };

        auto const check_auth =
        [&](const std::set<std::string>& scopes = {})
        {
            const auto it = cw::credentials::check_header(get_creds(), req["Authorization"]);
            if (it == get_creds().end()) {
                send(json_error_response("Invalid credentials", "Could not authenticate user", http::status::unauthorized));
                return false;
            }
            if (!scopes.empty()) {
                for (const auto& s : scopes) {
                    if (it->second.scopes.find(s) == it->second.scopes.end()) {
                        send(json_error_response("Invalid scope", std::string("User does not have requested scope: ")+s, http::status::unauthorized));
                        return false;
                    }
                }
            }
            return true;
        };
            
        if (req.method() == http::verb::get && req.target() == "/openapi.json") {
            http::string_body::value_type body{cw::openapi::openapi_json};
            const auto size = body.size();
            // Respond to GET request
            http::response<http::string_body> res{
                std::piecewise_construct,
                std::make_tuple(std::move(body)),
                std::make_tuple(http::status::ok, req.version())};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "application/json");
            res.content_length(size);
            res.keep_alive(req.keep_alive());
            return send(std::move(res));
        } else if (req.method() == http::verb::get && req.target() == "/users") {
            if (!check_auth({"a"})) return;

            cw::batch::CmdOptions opts{"bash", {"-c", "sleep 2; echo Hallo"}};
            derived().process_cache_[opts].emplace(derived().ioc_, opts, [&send, &json_response, &json_error_response](CmdProcess& proc, int ret, const std::error_code& ec){
                if (ec) {
                    return send(json_error_response("Running command failed", "Could not run command", http::status::internal_server_error));
                }
                if (ret != 0) {
                    return send(json_error_response("Running command failed", "Command exited with error code", http::status::internal_server_error));
                }

                rapidjson::Document document;
                rapidjson::Document::AllocatorType& allocator = document.GetAllocator();
                document.SetObject();
                document.AddMember("data", proc.out.get(), allocator);
                return send(json_response(document));
            });
            return;
        } else if (req.method() == http::verb::get && req.target() == "/nodes") {
            if (!check_auth({"nodes_info"})) return;

            auto pbs = std::make_shared<cw::batch::pbs::PbsBatch>([&](std::string& out, const cw::batch::CmdOptions& opts) {
                std::cout << "1" << std::endl;
                if (derived().process_cache_[opts].has_value()) {
                    std::cout << "2" << std::endl;

                    if (derived().process_cache_[opts]->exit >= 0) out = derived().process_cache_[opts]->out.get();
                    std::cout << "4" << std::endl;
                    return derived().process_cache_[opts]->exit;
                } else {
                    std::cout << "3" << std::endl;
                    // start command
                    derived().process_cache_[opts].emplace(derived().ioc_, opts, [opts, &send, &json_error_response](CmdProcess& proc, int ret, const std::error_code& ec){
                        (void)proc;
                        std::cout << "5" << std::endl;
                        if (ec) return send(json_error_response("Running command failed", "Could not run command", http::status::internal_server_error));
                        if (ret != 0) return send(json_error_response("Running command failed", "Command exited with error code", http::status::internal_server_error));
                        std::cout << "6" << std::endl;
                        //return send(json_error_response("a", "b", http::status::internal_server_error));
                    });
                }
                return -1;
            });

            auto nodes = std::make_shared<std::vector<cw::batch::Node>>();
            derived().poll.start([nodes, pbs, &send, &json_error_response, &json_response](const boost::system::error_code& ec){
                (void)ec;
                try {
                    std::cout << "7" << std::endl;

                    bool done = pbs->getNodesAsync({}, [nodes](cw::batch::Node n){
                        nodes->push_back(n);
                        return true;
                    });
                    if (done) {
                        rapidjson::Document document;
                        rapidjson::Document::AllocatorType& allocator = document.GetAllocator();
                        document.SetObject();

                        rapidjson::Value nodesArr;
                        nodesArr.SetArray();
                        for (const auto& node : *nodes) {
                                rapidjson::Document subdocument(&document.GetAllocator());
                                cw::batch::json::serialize(node, subdocument);
                                nodesArr.PushBack(subdocument, allocator);
                        }
                        document.AddMember("nodes", nodesArr, allocator);
                        send(json_response(document));
                        return false;
                    }
                } catch (const boost::process::process_error& e) {
                    send(json_error_response("Running command failed", e.what(), http::status::internal_server_error));
                    return false;
                }

                return true;

            });
            return;
        }
        return send(bad_request());
    }

    void
    do_read()
    {
        // Construct a new parser for each message
        parser_.emplace();

        // Apply a reasonable limit to the allowed size
        // of the body in bytes to prevent abuse.
        parser_->body_limit(10000);

        // Set the timeout.
        beast::get_lowest_layer(
            derived().stream()).expires_after(std::chrono::seconds(30));

        // Read a request using the parser-oriented interface
        http::async_read(
            derived().stream(),
            buffer_,
            *parser_,
            beast::bind_front_handler(
                &http_session::on_read,
                derived().shared_from_this()));
    }

    void
    on_read(beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        // This means they closed the connection
        if(ec == http::error::end_of_stream)
            return derived().do_eof();

        if(ec)
            return fail(ec, "read");

        // See if it is a WebSocket Upgrade
        if(websocket::is_upgrade(parser_->get()))
        {
            // Disable the timeout.
            // The websocket::stream uses its own timeout settings.
            beast::get_lowest_layer(derived().stream()).expires_never();

            // Create a websocket session, transferring ownership
            // of both the socket and the HTTP request.
            return make_websocket_session(
                derived().release_stream(),
                parser_->release());
        }

        // Send the response
        handle_request(parser_->release(), queue_);

        // If we aren't at the queue limit, try to pipeline another request
        if(! queue_.is_full())
            do_read();
    }

    void
    on_write(bool close, beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if(ec)
            return fail(ec, "write");

        if(close)
        {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            return derived().do_eof();
        }

        // Inform the queue that a write completed
        if(queue_.on_write())
        {
            // Read another request
            do_read();
        }
    }
};

//------------------------------------------------------------------------------

// Handles a plain HTTP connection
class plain_http_session
    : public http_session<plain_http_session>
    , public std::enable_shared_from_this<plain_http_session>
{
    beast::tcp_stream stream_;

public:
    std::string buf;
    net::io_context& ioc_;
    std::map<cw::batch::CmdOptions, boost::optional<CmdProcess>> process_cache_;
    boost::asio::deadline_timer timer;
    PollTimer poll;

    // Create the session
    plain_http_session(
        beast::tcp_stream&& stream,
        beast::flat_buffer&& buffer,
        net::io_context& ioc)
        : http_session<plain_http_session>(
            std::move(buffer))
        , stream_(std::move(stream))
        , ioc_(ioc)
        , timer(ioc, boost::posix_time::seconds(1))
        , poll(ioc)
    {
    }

    // Start the session
    void
    run()
    {
        this->do_read();
    }

    // Called by the base class
    beast::tcp_stream&
    stream()
    {
        return stream_;
    }

    // Called by the base class
    beast::tcp_stream
    release_stream()
    {
        return std::move(stream_);
    }

    // Called by the base class
    void
    do_eof()
    {
        // Send a TCP shutdown
        beast::error_code ec;
        stream_.socket().shutdown(tcp::socket::shutdown_send, ec);

        // At this point the connection is closed gracefully
    }
};

//------------------------------------------------------------------------------

// Handles an SSL HTTP connection
class ssl_http_session
    : public http_session<ssl_http_session>
    , public std::enable_shared_from_this<ssl_http_session>
{
    beast::ssl_stream<beast::tcp_stream> stream_;

public:
    std::string buf;
    net::io_context& ioc_;
    std::map<cw::batch::CmdOptions, boost::optional<CmdProcess>> process_cache_;
    boost::asio::deadline_timer timer;
    PollTimer poll;

    // Create the http_session
    ssl_http_session(
        beast::tcp_stream&& stream,
        ssl::context& ctx,
        beast::flat_buffer&& buffer,
        net::io_context& ioc)
        : http_session<ssl_http_session>(
            std::move(buffer))
        , stream_(std::move(stream), ctx)
        , ioc_(ioc)
        , timer(ioc, boost::posix_time::seconds(1))
        , poll(ioc)
    {
    }

    // Start the session
    void
    run()
    {
        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Perform the SSL handshake
        // Note, this is the buffered version of the handshake.
        stream_.async_handshake(
            ssl::stream_base::server,
            buffer_.data(),
            beast::bind_front_handler(
                &ssl_http_session::on_handshake,
                shared_from_this()));
    }

    // Called by the base class
    beast::ssl_stream<beast::tcp_stream>&
    stream()
    {
        return stream_;
    }

    // Called by the base class
    beast::ssl_stream<beast::tcp_stream>
    release_stream()
    {
        return std::move(stream_);
    }

    // Called by the base class
    void
    do_eof()
    {
        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Perform the SSL shutdown
        stream_.async_shutdown(
            beast::bind_front_handler(
                &ssl_http_session::on_shutdown,
                shared_from_this()));
    }

private:
    void
    on_handshake(
        beast::error_code ec,
        std::size_t bytes_used)
    {
        if(ec)
            return fail(ec, "handshake");

        // Consume the portion of the buffer used by the handshake
        buffer_.consume(bytes_used);

        do_read();
    }

    void
    on_shutdown(beast::error_code ec)
    {
        if(ec)
            return fail(ec, "shutdown");

        // At this point the connection is closed gracefully
    }
};

//------------------------------------------------------------------------------

// Detects SSL handshakes
class detect_session : public std::enable_shared_from_this<detect_session>
{
    beast::tcp_stream stream_;
    ssl::context& ctx_;
    beast::flat_buffer buffer_;
    net::io_context& ioc_;

public:
    explicit
    detect_session(
        tcp::socket&& socket,
        ssl::context& ctx,
        net::io_context& ioc)
        : stream_(std::move(socket))
        , ctx_(ctx)
        , ioc_(ioc)
    {
    }

    // Launch the detector
    void
    run()
    {
        // Set the timeout.
        stream_.expires_after(std::chrono::seconds(30));

        beast::async_detect_ssl(
            stream_,
            buffer_,
            beast::bind_front_handler(
                &detect_session::on_detect,
                this->shared_from_this()));
    }

    void
    on_detect(beast::error_code ec, boost::tribool result)
    {
        if(ec)
            return fail(ec, "detect");

        if(result)
        {
            // Launch SSL session
            std::make_shared<ssl_http_session>(
                std::move(stream_),
                ctx_,
                std::move(buffer_),
                ioc_)->run();
            return;
        }

        // Launch plain session
        std::make_shared<plain_http_session>(
            std::move(stream_),
            std::move(buffer_),
            ioc_)->run();
    }
};

// Accepts incoming connections and launches the sessions
class listener : public std::enable_shared_from_this<listener>
{
    net::io_context& ioc_;
    ssl::context& ctx_;
    tcp::acceptor acceptor_;

public:
    listener(
        net::io_context& ioc,
        ssl::context& ctx,
        tcp::endpoint endpoint)
        : ioc_(ioc)
        , ctx_(ctx)
        , acceptor_(net::make_strand(ioc))
    {
        beast::error_code ec;

        // Open the acceptor
        acceptor_.open(endpoint.protocol(), ec);
        if(ec)
        {
            fail(ec, "open");
            return;
        }

        // Allow address reuse
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if(ec)
        {
            fail(ec, "set_option");
            return;
        }

        // Bind to the server address
        acceptor_.bind(endpoint, ec);
        if(ec)
        {
            fail(ec, "bind");
            return;
        }

        // Start listening for connections
        acceptor_.listen(
            net::socket_base::max_listen_connections, ec);
        if(ec)
        {
            fail(ec, "listen");
            return;
        }
    }

    // Start accepting incoming connections
    void
    run()
    {
        do_accept();
    }

private:
    void
    do_accept()
    {
        // The new connection gets its own strand
        acceptor_.async_accept(
            net::make_strand(ioc_),
            beast::bind_front_handler(
                &listener::on_accept,
                shared_from_this()));
    }

    void
    on_accept(beast::error_code ec, tcp::socket socket)
    {
        if(ec)
        {
            fail(ec, "accept");
        }
        else
        {
            // Create the detector http_session and run it
            std::make_shared<detect_session>(
                std::move(socket),
                ctx_,
                ioc_)->run();
        }

        // Accept another connection
        do_accept();
    }
};



int main(int argc, char **argv) {
    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = sigHandler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL); /* for CTRL+C */

    enum class mode { run, user_set, help
    };
    mode selected;

    std::string cert;
    std::string cred;
    std::string dh;
    std::string priv;
    std::string host = "0.0.0.0";
    int portInput = -1;
    std::string username;
    unsigned int threads = 10;
    std::vector<std::string> scopes;

    auto cli = (
        (clipp::command("help").set(selected,mode::help) % "Show help message")
        | (((clipp::required("--cred") & clipp::value("CRED", cred)) % "Credentials file"),
            (clipp::command("run").set(selected, mode::run) % "Run server",
                (clipp::required("--cert") & clipp::value("CERT", cert)) % "SSL certificate file",
                (clipp::required("--priv") & clipp::value("KEY", priv)) % "SSL private key file",
                (clipp::required("--dh") & clipp::value("DH", dh)) % "SSL dh file",
                (clipp::option("--port") & clipp::value("PORT", portInput)) % "Port to run server on (1-65535), default 80",
                (clipp::option("--host") & clipp::value("HOST", host)) % "Host to run server on, default 0.0.0.0",
                (clipp::option("--threads") & clipp::value("NTHREADS", threads)) % "Number of threads to use"
            )
            | (clipp::command("user"), (clipp::command("set").set(selected, mode::user_set) % "Set / add user credentials",
                (clipp::value("name").set(username)) % "Username",
                (clipp::option("--scopes") & clipp::values("SCOPE", scopes)) % "Permission scopes to set for user"
            )))
    );

    if (!clipp::parse(argc, argv, cli)) selected = mode::help;

    switch (selected) {
        default: {
            assert(false && "invalid cmd");
            return 1;
        }
        case mode::help: {
            // std::cout << make_man_page(cli, argv[0]) << std::endl;
            std::cout << "USAGE:\n"
                    << clipp::usage_lines(cli, argv[0]) << "\n\n\n"
                    << "PARAMETERS:\n\n"
                    << clipp::documentation(cli) << std::endl;
            return 1;
        }

        case mode::user_set: {
            cw::credentials::dict creds;
            {
                std::ifstream creds_fs(cred);
                cw::credentials::read(creds, creds_fs);
            }
            
            std::cout << "password> ";
            std::cout.flush();
            std::string password;
            std::getline(std::cin, password);
            std::set<std::string> scopes_set(scopes.begin(), scopes.end());
            cw::credentials::set_user(creds, username, scopes_set, password);

            {
                std::ofstream creds_fso(cred);
                cw::credentials::write(creds, creds_fso);
            }
            break;
        }
        case mode::run: {
            if (threads < 1) {
                std::cout << "Minimum 1 thread" << std::endl;
                return 1;
            }

            unsigned short port = 80;

            if (portInput==-1) {
                port = 80;
            } else if (portInput < 1 || portInput > 65535) {
                std::cout << "Invalid PORT (1-65535) " << portInput << std::endl;
                return 1;
            } else {
                port = static_cast<unsigned short>(portInput);
            }


            // The io_context is required for all I/O
            net::io_context ioc{static_cast<int>(threads)};

            // Capture SIGINT and SIGTERM to perform a clean shutdown
            net::signal_set signals(ioc, SIGINT, SIGTERM);
            signals.async_wait(
            [&](beast::error_code const&, int)
            {
                // Stop the `io_context`. This will cause `run()`
                // to return immediately, eventually destroying the
                // `io_context` and all of the sockets in it.
                ioc.stop();
            });


            auto const address = net::ip::make_address(host);

            auto ctx = create_ssl_context(cert, priv, dh);

            {
                std::ifstream creds_fs(cred);
                cw::credentials::read(creds, creds_fs);
            }

            // Create and launch a listening port
            std::make_shared<listener>(
                ioc,
                ctx,
                tcp::endpoint{address, port})->run();

            std::cout << "Server running" << std::endl;

            // Run the I/O service on the requested number of threads
            std::vector<std::thread> v;
            v.reserve(threads - 1);
            for(auto i = threads - 1; i > 0; --i)
                v.emplace_back(
                [&ioc]
                {
                    ioc.run();
                });
            ioc.run();

            // (If we get here, it means we got a SIGINT or SIGTERM)

            // Block until all the threads exit
            for(auto& t : v)
                t.join();


            break;
        }
    }


    return 0;
}
