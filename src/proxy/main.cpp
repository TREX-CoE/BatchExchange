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
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
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


namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
using boost::asio::ip::tcp;

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

// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template<
    class Body, class Allocator,
    class Send>
void
handle_request(
    const cw::credentials::dict& creds,
    http::request<Body, http::basic_fields<Allocator>>&& req,
    Send&& send)
{
    auto const json_response =
    [&](const rapidjson::Document& document, http::status status = http::status::ok)
    {
        http::response<http::string_body> res{status, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(req.keep_alive());
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
        const auto it = cw::credentials::check_header(creds, req["Authorization"]);
        if (it == creds.end()) {
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

        rapidjson::Document document;
        rapidjson::Document::AllocatorType& allocator = document.GetAllocator();
        document.SetObject();
        document.AddMember("id", "a", allocator);
        return send(json_response(document));
    }
    return send(bad_request());
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

// Handles an HTTP server connection.
// This uses the Curiously Recurring Template Pattern so that
// the same code works with both SSL streams and regular sockets.
template<class Derived>
class session
{
    // Access the derived class, this is part of
    // the Curiously Recurring Template Pattern idiom.
    Derived&
    derived()
    {
        return static_cast<Derived&>(*this);
    }

    // This is the C++11 equivalent of a generic lambda.
    // The function object is used to send an HTTP message.
    struct send_lambda
    {
        session& self_;

        explicit
        send_lambda(session& self)
            : self_(self)
        {
        }

        template<bool isRequest, class Body, class Fields>
        void
        operator()(http::message<isRequest, Body, Fields>&& msg) const
        {
            // The lifetime of the message has to extend
            // for the duration of the async operation so
            // we use a shared_ptr to manage it.
            auto sp = std::make_shared<
                http::message<isRequest, Body, Fields>>(std::move(msg));

            // Store a type-erased version of the shared
            // pointer in the class to keep it alive.
            self_.res_ = sp;

            // Write the response
            http::async_write(
                self_.derived().stream(),
                *sp,
                beast::bind_front_handler(
                    &session::on_write,
                    self_.derived().shared_from_this(),
                    sp->need_eof()));
        }
    };

    std::shared_ptr<cw::credentials::dict const> creds_;
    http::request<http::string_body> req_;
    std::shared_ptr<void> res_;
    send_lambda lambda_;

protected:
    beast::flat_buffer buffer_;

public:
    // Take ownership of the buffer
    session(
        beast::flat_buffer buffer,
        std::shared_ptr<cw::credentials::dict const> const& creds)
        : creds_(creds)
        , lambda_(*this)
        , buffer_(std::move(buffer))
    {
    }

    void
    do_read()
    {
        // Set the timeout.
        beast::get_lowest_layer(
            derived().stream()).expires_after(std::chrono::seconds(30));

        // Read a request
        http::async_read(
            derived().stream(),
            buffer_,
            req_,
            beast::bind_front_handler(
                &session::on_read,
                derived().shared_from_this()));
    }

    void
    on_read(
        beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        // This means they closed the connection
        if(ec == http::error::end_of_stream)
            return derived().do_eof();

        if(ec)
            return fail(ec, "read");

        // Send the response
        handle_request(*creds_, std::move(req_), lambda_);
    }

    void
    on_write(
        bool close,
        beast::error_code ec,
        std::size_t bytes_transferred)
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

        // We're done with the response so delete it
        res_ = nullptr;

        // Read another request
        do_read();
    }
};

// Handles a plain HTTP connection
class plain_session
    : public session<plain_session>
    , public std::enable_shared_from_this<plain_session>
{
    beast::tcp_stream stream_;

public:
    // Create the session
    plain_session(
        tcp::socket&& socket,
        beast::flat_buffer buffer,
        std::shared_ptr<cw::credentials::dict const> const& creds)
        : session<plain_session>(
            std::move(buffer),
            creds)
        , stream_(std::move(socket))
    {
    }

    // Called by the base class
    beast::tcp_stream&
    stream()
    {
        return stream_;
    }

    // Start the asynchronous operation
    void
    run()
    {
        do_read();
    }

    void
    do_eof()
    {
        // Send a TCP shutdown
        beast::error_code ec;
        stream_.socket().shutdown(tcp::socket::shutdown_send, ec);

        // At this point the connection is closed gracefully
    }
};

// Handles an SSL HTTP connection
class ssl_session
    : public session<ssl_session>
    , public std::enable_shared_from_this<ssl_session>
{
    beast::ssl_stream<beast::tcp_stream> stream_;

public:
    // Create the session
    ssl_session(
        tcp::socket&& socket,
        ssl::context& ctx,
        beast::flat_buffer buffer,
        std::shared_ptr<cw::credentials::dict const> const& creds)
        : session<ssl_session>(
            std::move(buffer),
            creds)
        , stream_(std::move(socket), ctx)
    {
    }

    // Called by the base class
    beast::ssl_stream<beast::tcp_stream>&
    stream()
    {
        return stream_;
    }

    // Start the asynchronous operation
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
                &ssl_session::on_handshake,
                shared_from_this()));
    }

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
    do_eof()
    {
        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Perform the SSL shutdown
        stream_.async_shutdown(
            beast::bind_front_handler(
                &ssl_session::on_shutdown,
                shared_from_this()));
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
    std::shared_ptr<cw::credentials::dict const> creds_;
    beast::flat_buffer buffer_;

public:
    detect_session(
        tcp::socket&& socket,
        ssl::context& ctx,
        std::shared_ptr<cw::credentials::dict const> const& creds)
        : stream_(std::move(socket))
        , ctx_(ctx)
        , creds_(creds)
    {
    }

    // Launch the detector
    void
    run()
    {
        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Detect a TLS handshake
        async_detect_ssl(
            stream_,
            buffer_,
            beast::bind_front_handler(
                &detect_session::on_detect,
                shared_from_this()));
    }

    void
    on_detect(beast::error_code ec, boost::tribool result)
    {
        if(ec)
            return fail(ec, "detect");

        if(result)
        {
            // Launch SSL session
            std::make_shared<ssl_session>(
                stream_.release_socket(),
                ctx_,
                std::move(buffer_),
                creds_)->run();
            return;
        }

        // Launch plain session
        std::make_shared<plain_session>(
            stream_.release_socket(),
            std::move(buffer_),
            creds_)->run();
    }
};

// Accepts incoming connections and launches the sessions
class listener : public std::enable_shared_from_this<listener>
{
    net::io_context& ioc_;
    ssl::context& ctx_;
    tcp::acceptor acceptor_;
    std::shared_ptr<cw::credentials::dict const> creds_;

public:
    listener(
        net::io_context& ioc,
        ssl::context& ctx,
        tcp::endpoint endpoint,
        std::shared_ptr<cw::credentials::dict const> const& creds)
        : ioc_(ioc)
        , ctx_(ctx)
        , acceptor_(net::make_strand(ioc))
        , creds_(creds)
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
            // Create the detector session and run it
            std::make_shared<detect_session>(
                std::move(socket),
                ctx_,
                creds_)->run();
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

            auto const address = net::ip::make_address(host);

            auto ctx = create_ssl_context(cert, priv, dh);

            auto creds = std::make_shared<cw::credentials::dict>();

            {
                std::ifstream creds_fs(cred);
                cw::credentials::read(*creds, creds_fs);
            }

            // Create and launch a listening port
            std::make_shared<listener>(
                ioc,
                ctx,
                tcp::endpoint{address, port},
                creds)->run();

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

            break;
        }
    }


    return 0;
}
